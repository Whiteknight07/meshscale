// Feasibility spike only: undocumented Cloudflare device enrollment API.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Registration struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Key    string `json:"key"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4    string `json:"v4"`
				V6    string `json:"v6"`
				Host  string `json:"host"`
				Ports []int  `json:"ports"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
	Policy struct {
		TunnelProtocol string          `json:"tunnel_protocol"`
		ProfileID      string          `json:"policy_id"`
		DNS            json.RawMessage `json:"dns"`
	} `json:"policy"`
}
type State struct {
	NodeID       string       `json:"node_id"`
	PrivateKey   string       `json:"private_key"`
	Registration Registration `json:"registration"`
}

var httpClient = &http.Client{Timeout: 30 * time.Second}
var account string

func request(method, url, bearer string, body any, out any) (int, error) {
	var b io.Reader
	if body != nil {
		raw, e := json.Marshal(body)
		if e != nil {
			return 0, e
		}
		b = bytes.NewReader(raw)
	}
	req, e := http.NewRequest(method, url, b)
	if e != nil {
		return 0, e
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, e := httpClient.Do(req)
	if e != nil {
		return 0, e
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if e != nil {
		return res.StatusCode, e
	}
	// Never include raw bodies: successful responses contain credentials and errors may echo requests.
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return res.StatusCode, fmt.Errorf("%s %s: HTTP %d (body withheld)", method, req.URL.Path, res.StatusCode)
	}
	if out != nil && len(raw) > 0 {
		var env struct {
			Success bool            `json:"success"`
			Result  json.RawMessage `json:"result"`
		}
		if e = json.Unmarshal(raw, &env); e != nil {
			return res.StatusCode, e
		}
		if !env.Success {
			return res.StatusCode, fmt.Errorf("%s %s: success=false", method, req.URL.Path)
		}
		if e = json.Unmarshal(env.Result, out); e != nil {
			return res.StatusCode, e
		}
	}
	return res.StatusCode, nil
}
func admin(method, path string, body, out any) error {
	_, e := request(method, "https://api.cloudflare.com/client/v4/accounts/"+account+path, os.Getenv("CLOUDFLARE_API_TOKEN"), body, out)
	return e
}
func regURL(id string) string {
	return "https://api.devices.cloudflare.com/v1/accounts/" + account + "/reg/" + id
}
func save(path string, s *State) error {
	b, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, b, 0600)
}
func enroll(path string) (*State, error) {
	var s State
	if b, e := os.ReadFile(path); e == nil {
		if e = json.Unmarshal(b, &s); e != nil {
			return nil, e
		}
		if s.Registration.ID != "" {
			return &s, nil
		}
	}
	var nodes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if e := admin("GET", "/warp_connector", nil, &nodes); e != nil {
		return nil, e
	}
	for _, n := range nodes {
		if n.Name == "meshscale-native-test" {
			s.NodeID = n.ID
		}
	}
	if s.NodeID == "" {
		var n struct {
			ID string `json:"id"`
		}
		if e := admin("POST", "/warp_connector", map[string]any{"name": "meshscale-native-test", "ha": false}, &n); e != nil {
			return nil, e
		}
		s.NodeID = n.ID
		fmt.Println("Created node:", s.NodeID)
	} else {
		fmt.Println("Reusing test node:", s.NodeID)
	}
	if e := save(path, &s); e != nil {
		return nil, e
	}
	var token string
	if e := admin("GET", "/warp_connector/"+s.NodeID+"/token", nil, &token); e != nil {
		return nil, e
	}
	var fields struct {
		A string `json:"a"`
		T string `json:"t"`
	}
	raw, e := base64.StdEncoding.DecodeString(token)
	if e != nil {
		return nil, fmt.Errorf("invalid token encoding")
	}
	if json.Unmarshal(raw, &fields) != nil || fields.A != account || fields.T != s.NodeID {
		return nil, fmt.Errorf("token account/node mismatch")
	}
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	s.PrivateKey = base64.StdEncoding.EncodeToString(key.Bytes())
	body := map[string]any{"type": "linux", "name": "meshscale-native-test", "key": base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), "warp_connector_token": token}
	status, e := request("POST", "https://api.devices.cloudflare.com/v1/accounts/"+account+"/warp_connector", "", body, &s.Registration)
	if e != nil {
		return nil, e
	}
	if s.Registration.Key != body["key"] {
		return nil, fmt.Errorf("server public key mismatch")
	}
	if e = save(path, &s); e != nil {
		return nil, e
	}
	fmt.Printf("Registered directly: HTTP %d, id=%s, policy_protocol=%q profile=%s\n", status, s.Registration.ID, s.Registration.Policy.TunnelProtocol, s.Registration.Policy.ProfileID)
	return &s, nil
}
func must(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
func main() {
	statePath := flag.String("state", "/state/registration.secret.json", "credential state, mode 0600")
	mtu := flag.Int("mtu", 1280, "netstack inner IP MTU")
	endpoint := flag.String("endpoint", "", "override returned endpoint")
	target := flag.String("target", "100.96.0.2:8080", "probe target")
	udpTarget := flag.String("udp-target", "", "optional peer UDP echo for MTU sweep")
	count := flag.Int("count", 20, "TCP connect and reply samples")
	once := flag.Bool("once", false, "exit after probes")
	remove := flag.Bool("delete-registration", false, "delete only this spike registration")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	account = os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	if account == "" {
		log.Fatal("missing CLOUDFLARE_ACCOUNT_ID")
	}
	s, e := enroll(*statePath)
	must(e)
	if *remove {
		status, e := request("DELETE", regURL(s.Registration.ID), s.Registration.Token, nil, nil)
		must(e)
		fmt.Println("Deleted registration HTTP", status)
		return
	}
	var fresh Registration
	status, e := request("GET", regURL(s.Registration.ID), s.Registration.Token, nil, &fresh)
	must(e)
	// GET does not return the bearer credential. Preserve it locally.
	fresh.Token = s.Registration.Token
	s.Registration = fresh
	must(save(*statePath, s))
	fmt.Printf("Refresh config: HTTP %d; Mesh IPv4=%s IPv6=%s; profile_protocol=%q\n", status, fresh.Config.Interface.Addresses.V4, fresh.Config.Interface.Addresses.V6, fresh.Policy.TunnelProtocol)
	if len(fresh.Config.Peers) == 0 {
		log.Fatal("no peers")
	}
	peer := fresh.Config.Peers[0]
	ep := peer.Endpoint.V4
	host, port, e := net.SplitHostPort(ep)
	must(e)
	if port == "0" {
		if len(peer.Endpoint.Ports) == 0 {
			log.Fatal("no ports")
		}
		ep = net.JoinHostPort(host, strconv.Itoa(peer.Endpoint.Ports[0]))
	}
	if *endpoint != "" {
		ep = *endpoint
	}
	ips := []netip.Addr{netip.MustParseAddr(fresh.Config.Interface.Addresses.V4), netip.MustParseAddr(fresh.Config.Interface.Addresses.V6)}
	tun, stack, e := netstack.CreateNetTUN(ips, []netip.Addr{netip.MustParseAddr("172.64.36.1")}, *mtu)
	must(e)
	wg := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard: "))
	defer wg.Close()
	private, e := base64.StdEncoding.DecodeString(s.PrivateKey)
	must(e)
	pub, e := base64.StdEncoding.DecodeString(peer.PublicKey)
	must(e)
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=25\n", hex.EncodeToString(private), hex.EncodeToString(pub), ep)
	must(wg.IpcSet(cfg))
	must(wg.Up())
	fmt.Printf("Userspace WireGuard up endpoint=%s MTU=%d uid=%d; no OS TUN or routes\n", ep, *mtu, os.Getuid())
	ln, e := stack.ListenTCPAddrPort(netip.AddrPortFrom(ips[0], 8080))
	must(e)
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprintf(c, "hello from native wireguard %s, you are %s\n", c.LocalAddr(), c.RemoteAddr())
				log.Printf("Inbound peer %s -> %s", c.RemoteAddr(), c.LocalAddr())
			}()
		}
	}()
	fmt.Printf("Listening on %s:8080\n", ips[0])
	udp, e := stack.ListenUDPAddrPort(netip.AddrPortFrom(ips[0], 8082))
	must(e)
	defer udp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			if _, e = udp.WriteTo(b[:n], a); e != nil {
				log.Printf("UDP echo bytes=%d error=%v", n, e)
			}
		}
	}()

	// Echo permits an application-level size sweep through both directions.
	echo, e := stack.ListenTCPAddrPort(netip.AddrPortFrom(ips[0], 8081))
	must(e)
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(30 * time.Second)); io.Copy(c, c) }()
		}
	}()
	var samples []float64
	for i := 0; i < *count; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := time.Now()
		c, e := stack.DialContext(ctx, "tcp", *target)
		if e == nil {
			c.SetDeadline(time.Now().Add(10 * time.Second))
			reply, er := bufio.NewReader(c).ReadString('\n')
			c.Close()
			e = er
			if er == nil {
				ms := float64(time.Since(start).Microseconds()) / 1000
				samples = append(samples, ms)
				fmt.Printf("TCP probe %02d %.3fms: %s", i+1, ms, reply)
			}
		}
		cancel()
		if e != nil {
			fmt.Printf("TCP probe %02d error: %v\n", i+1, e)
		}
	}
	if len(samples) > 0 {
		sort.Float64s(samples)
		sum := 0.0
		for _, v := range samples {
			sum += v
		}
		fmt.Printf("TCP timings n=%d min=%.3f median=%.3f p95=%.3f max=%.3f mean=%.3f ms\n", len(samples), samples[0], (samples[(len(samples)-1)/2]+samples[len(samples)/2])/2, samples[(len(samples)-1)*95/100], samples[len(samples)-1], sum/float64(len(samples)))
	}

	if *udpTarget != "" {
		for _, size := range []int{1200, 1232, 1252, 1253, 1272, 1280, 1392, 1393, 1420, 1472} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			c, e := stack.DialContext(ctx, "udp", *udpTarget)
			cancel()
			if e != nil {
				fmt.Printf("UDP payload=%d dial error=%v\n", size, e)
				continue
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			payload := bytes.Repeat([]byte{42}, size)
			n, e := c.Write(payload)
			if e == nil {
				b := make([]byte, 65535)
				n, e = c.Read(b)
				if e == nil && !bytes.Equal(payload, b[:n]) {
					e = fmt.Errorf("payload mismatch")
				}
			}
			fmt.Printf("UDP MTU=%d payload=%d innerIPv4=%d transferred=%d error=%v\n", *mtu, size, size+28, n, e)
			c.Close()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	c, e := stack.DialContext(ctx, "tcp", "100.96.0.2:22")
	cancel()
	if e == nil {
		c.SetDeadline(time.Now().Add(15 * time.Second))
		sc, ch, rq, er := ssh.NewClientConn(c, "100.96.0.2:22", &ssh.ClientConfig{User: "testuser", HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			fmt.Println("SSH spike accepts host fingerprint:", ssh.FingerprintSHA256(k))
			return nil
		}, Timeout: 10 * time.Second})
		if er == nil {
			client := ssh.NewClient(sc, ch, rq)
			session, er := client.NewSession()
			if er == nil {
				b, er := session.CombinedOutput("id; printf 'native-wireguard-ssh-ok\\n'")
				fmt.Printf("SSH keyless result: %s error=%v\n", b, er)
				session.Close()
			} else {
				fmt.Println("SSH session:", er)
			}
			client.Close()
		} else {
			fmt.Println("SSH handshake:", er)
			c.Close()
		}
	} else {
		fmt.Println("SSH dial:", e)
	}
	for _, server := range []string{"172.64.36.1:53", "1.1.1.1:53"} {
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return stack.DialContext(ctx, "udp", server)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ans, er := resolver.LookupHost(ctx, "meshscale-docker-test.mesh")
		cancel()
		fmt.Printf("DNS through tunnel via %s: answers=%v error=%v\n", server, ans, er)
	}
	dump, e := wg.IpcGet()
	if e == nil {
		for _, line := range strings.Split(dump, "\n") {
			if strings.HasPrefix(line, "last_handshake_") || strings.HasPrefix(line, "rx_bytes=") || strings.HasPrefix(line, "tx_bytes=") {
				fmt.Println("WG", line)
			}
		}
	}
	if *once {
		return
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
