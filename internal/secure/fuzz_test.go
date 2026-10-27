package secure

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

// FuzzDirectoryRecords feeds editable Gateway list data through discovery.
// Whatever the directory says, a peer's AllowedIPs stay its key-derived
// overlay /128 (plus its key-derived v2 /32 for exits), and defaults appear
// only for the locally selected key.
func FuzzDirectoryRecords(f *testing.F) {
	key, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	public, _ := key.Public()
	v4, _ := IPv4Address("account", public)
	valid, _ := json.Marshal(Record{RegistrationID: "a", PublicKey: public, Enabled: true, ExitVersion: 2, IPv4: v4, OffersExit: true})
	f.Add(listPrefix+"a", "IP", recordPrefix+string(valid), "100.96.0.1", "laptop")
	f.Add(listPrefix+"a", "IP", recordPrefix+`{"registration_id":"a","public_key":"`+public+`","enabled":true,"ipv4":"0.0.0.0","exit_version":2}`, "100.96.0.1", "x")
	f.Add(listPrefix+"a", "IP", recordPrefix+`{"registration_id":"a","public_key":"`+public+`","enabled":true,"allowed_ips":["0.0.0.0/0"]}`, "100.96.0.1", "\x1b[2J")
	f.Add(listPrefix+"a", "IP", recordPrefix+"null", "", "")
	f.Fuzz(func(t *testing.T, name, kind, description, meshIP, deviceName string) {
		lists := []cfapi.GatewayList{{ID: "l1", Name: name, Type: kind, Description: description, Items: []cfapi.GatewayListItem{{Value: "0.0.0.0/0"}}}}
		records, _, err := Records(context.Background(), &memoryDirectory{lists: lists}, "account")
		if err != nil {
			t.Fatal(err)
		}
		regs := []cfapi.Registration{{ID: "a", Device: cfapi.RegistrationDevice{ID: "dev-a", Name: deviceName}, User: cfapi.User{Email: "alice@example.com"}, VirtualIPv4: meshIP}}
		peers, _, err := BuildPeers("account", records, regs)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range peers {
			overlay, err := Address("account", p.PublicKey)
			if err != nil || p.IP != overlay || !IsIP(p.IP) {
				t.Fatalf("overlay address not derived from key: %+v", p)
			}
			if !reflect.DeepEqual(p.AllowedIPs, []netip.Prefix{netip.PrefixFrom(overlay, 128)}) {
				t.Fatalf("directory widened AllowedIPs: %v", p.AllowedIPs)
			}
			if p.IPv4.IsValid() {
				if want, _ := IPv4Address("account", p.PublicKey); p.IPv4 != want || !netip.MustParsePrefix("10.192.0.0/10").Contains(p.IPv4) {
					t.Fatalf("exit binding %s not derived from key", p.IPv4)
				}
			}
			for _, selected := range []string{"", "other-key"} {
				for _, prefix := range ExitAllowedIPs(p, selected) {
					if prefix.Bits() < 32 {
						t.Fatalf("unselected peer granted %s", prefix)
					}
				}
			}
			if want, _ := netip.ParseAddr(meshIP); p.Endpoint != netip.AddrPortFrom(want, Port) || p.MeshIP != want {
				t.Fatalf("endpoint not taken from the registration: %+v", p)
			}
			if p.Name != deviceName || p.Owner != "alice@example.com" || p.DeviceID != "dev-a" {
				t.Fatalf("directory overrode registration identity: %+v", p)
			}
		}
	})
}

func FuzzLoadConfig(f *testing.F) {
	f.Add([]byte(`{"enabled":true,"exit_node_id":"a","exit_node_key":"k","exit_node_allow_lan_access":true}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"enabled":"yes"}`))
	f.Add([]byte("\xef\xbb\xbf{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConfig(dir)
		if err != nil {
			return
		}
		if err := c.Save(dir); err != nil {
			t.Fatal(err)
		}
		again, err := LoadConfig(dir)
		if err != nil || again != c {
			t.Fatalf("saved config reloads differently: %+v vs %+v (%v)", again, c, err)
		}
	})
}

// An exit must be owned by the same identity; Unicode case folding would let
// a lookalike owner ("ſ" for "s") qualify as this account owner's exit.
func TestSelectExitRejectsLookalikeOwner(t *testing.T) {
	self := Peer{PublicKey: "self", Owner: "sam@example.com"}
	exit := Peer{Name: "exit", PublicKey: "exit", OffersExit: true, ExitVersion: 2, Owner: "ſam@example.com"}
	if _, err := SelectExit([]Peer{exit}, self, "exit"); err == nil {
		t.Fatal("lookalike owner accepted as exit")
	}
	exit.Owner = "SAM@example.com"
	if _, err := SelectExit([]Peer{exit}, self, "exit"); err != nil {
		t.Fatalf("ASCII case difference refused: %v", err)
	}
	if !slices.Equal([]bool{SameEmail("a@b", "A@B"), SameEmail("K@b", "k@b"), SameEmail("a", "ab")}, []bool{true, false, false}) {
		t.Fatal("SameEmail folding")
	}
}
