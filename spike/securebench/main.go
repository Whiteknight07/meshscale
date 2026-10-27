// securebench measures TCP-connect latency or bridges iperf3 into the private
// secure netstack. Bridges add copying/socket overhead: report it with results.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/native"
)

type dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func main() {
	dir := flag.String("dir", "", "secure state directory (defaults to current user's config)")
	mode := flag.String("mode", "latency", "latency, proxy (local OS listener), or server (secure listener)")
	plain := flag.Bool("plain", false, "dial ordinary OS TCP for baseline")
	target := flag.String("target", "", "TCP destination; server mode: secure listen address")
	listen := flag.String("listen", "127.0.0.1:15202", "proxy OS listener")
	forward := flag.String("forward", "127.0.0.1:5202", "server forwarding destination")
	samples := flag.Int("samples", 100, "TCP-connect samples")
	flag.Parse()
	if *dir == "" {
		d, err := config.Dir()
		if err != nil {
			log.Fatal(err)
		}
		*dir = d + "/secure"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var dial dialer = &native.Client{Dir: *dir}
	if *plain {
		dial = &net.Dialer{}
	}
	if *target == "" {
		log.Fatal("-target is required")
	}
	if *mode == "latency" {
		if *samples < 1 {
			log.Fatal("positive sample count required")
		}
		times := make([]float64, 0, *samples)
		for range *samples {
			call, cancel := context.WithTimeout(ctx, 5*time.Second)
			start := time.Now()
			c, err := dial.DialContext(call, "tcp", *target)
			elapsed := float64(time.Since(start)) / 1e6
			cancel()
			if err != nil {
				log.Fatal(err)
			}
			c.Close()
			times = append(times, elapsed)
			select {
			case <-ctx.Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
		sort.Float64s(times)
		sum := 0.
		for _, n := range times {
			sum += n
		}
		fmt.Printf("TCP connect n=%d mean=%.3f p50=%.3f p95=%.3f ms\n", len(times), sum/float64(len(times)), times[len(times)/2], times[min(len(times)-1, len(times)*95/100)])
		return
	}
	var l net.Listener
	var err error
	switch *mode {
	case "proxy":
		l, err = net.Listen("tcp", *listen)
	case "server":
		addr, parseErr := netip.ParseAddrPort(*target)
		if parseErr != nil {
			log.Fatal(parseErr)
		}
		l, err = (&native.Client{Dir: *dir}).ListenTCP(ctx, addr)
		dial = &net.Dialer{}
		*target = *forward
	default:
		log.Fatal("invalid -mode")
	}
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	context.AfterFunc(ctx, func() { l.Close() })
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Fatal(err)
		}
		go bridge(ctx, c, dial, *target)
	}
}
func bridge(ctx context.Context, c net.Conn, dial dialer, target string) {
	defer c.Close()
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	remote, err := dial.DialContext(call, "tcp", target)
	if err != nil {
		log.Print(err)
		return
	}
	defer remote.Close()
	stop := context.AfterFunc(ctx, func() { c.Close(); remote.Close() })
	defer stop()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(remote, c)
		if half, ok := remote.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		}
	}()
	io.Copy(c, remote)
	c.Close()
	remote.Close()
	wg.Wait()
}
