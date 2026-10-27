package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

var fixtureNow = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func timeAgo(age time.Duration) *time.Time {
	t := fixtureNow.Add(-age)
	return &t
}

type fakeLocalWARP struct {
	status    warpcli.ConnectionStatus
	info      warpcli.RegistrationInfo
	statusErr error
	infoErr   error
}

func (f fakeLocalWARP) Status(context.Context) (warpcli.ConnectionStatus, error) {
	return f.status, f.statusErr
}
func (f fakeLocalWARP) Registration(context.Context) (warpcli.RegistrationInfo, error) {
	return f.info, f.infoErr
}

func commandAPI(t *testing.T, handler http.HandlerFunc) *cfapi.Client {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	c := cfapi.New(cfapi.StaticToken("test-token"), "test")
	c.BaseURL, c.HTTPClient = s.URL, s.Client()
	return c
}

func fixtureDevices() ([]cfapi.Registration, []cfapi.PhysicalDevice, []cfapi.MeshNode) {
	return []cfapi.Registration{
		{ID: "reg1", Device: cfapi.RegistrationDevice{ID: "dev1", Name: "old-name"}, User: cfapi.User{Email: "alice@example.com"}, VirtualIPv4: "100.96.0.1", VirtualIPv6: "2606:4700:cf1:1000::1", LastSeenAt: timeAgo(time.Minute)},
		{ID: "reg2", Device: cfapi.RegistrationDevice{ID: "dev2", Name: "phone"}, LastSeenAt: timeAgo(3 * time.Hour), VirtualIPv4: "100.96.0.2"},
		{ID: "revoked", Device: cfapi.RegistrationDevice{ID: "dev3"}, RevokedAt: timeAgo(time.Hour)},
		{ID: "deleted", DeletedAt: timeAgo(time.Hour)},
		{ID: "extension", RegistrationType: "browser_extension"},
	}, []cfapi.PhysicalDevice{
		{ID: "dev1", Name: "laptop", DeviceType: "mac", LastSeenAt: timeAgo(time.Minute)},
		{ID: "dev2", Name: "phone", DeviceType: "ios", LastSeenUser: cfapi.User{Email: "bob@example.com"}, LastSeenAt: timeAgo(time.Minute)},
		{ID: "dev4", Name: "unenrolled", DeviceType: "linux"},
	}, []cfapi.MeshNode{
		{ID: "node1", Name: "server", Status: "healthy", ConnsActiveAt: timeAgo(48 * time.Hour)},
		{ID: "node2", Name: "server-old", Status: "down", ConnsInactiveAt: timeAgo(25 * time.Hour)},
		{ID: "node-deleted", DeletedAt: timeAgo(time.Hour)},
	}
}

func TestMergeAndStatusFormatting(t *testing.T) {
	r, p, n := fixtureDevices()
	devices := mergeMeshDevices(r, p, n, fixtureNow)
	markThisMachine(devices, warpcli.RegistrationInfo{RegistrationID: "reg1"})
	if len(devices) != 5 {
		t.Fatalf("unexpected devices: %#v", devices)
	}
	if devices[0].Name != "laptop" || devices[0].OS != "mac" || !devices[0].ThisMachine || !devices[0].Online || devices[1].User != "bob@example.com" || devices[1].Online {
		t.Fatalf("incorrect join or liveness: %#v", devices)
	}
	var out bytes.Buffer
	if err := writeStatus(&out, devices, false, fixtureNow); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"MESH IP DEVICE DNS NAME USER/OWNER OS STATUS SSH MODE SECURE EXIT NODE SECURE TCP",
		"100.96.0.1 laptop (this machine) - alice@example.com mac online - plain - -",
		"100.96.0.2 phone - bob@example.com ios last seen 3h ago - plain - -",
		"- server - Mesh node linux online - plain - -",
		"- server-old - Mesh node linux last seen 1d ago - plain - -",
		"- unenrolled - - linux offline - plain - -",
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("got:\n%s", out.String())
	}
	for i, line := range lines {
		if got := strings.Join(strings.Fields(line), " "); got != want[i] {
			t.Errorf("line %d: %q, want %q", i, got, want[i])
		}
	}
	out.Reset()
	if err := writeStatus(&out, devices, true, fixtureNow); err != nil {
		t.Fatal(err)
	}
	var decoded []meshDevice
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 5 || !decoded[0].ThisMachine || decoded[0].IPv6 != "2606:4700:cf1:1000::1" || decoded[2].Kind != "node" {
		t.Fatalf("unexpected JSON: %s", out.String())
	}
}

func TestStatusEmpty(t *testing.T) {
	var out bytes.Buffer
	if err := writeStatus(&out, nil, true, fixtureNow); err != nil {
		t.Fatal(err)
	}
	if out.String() != "[]\n" {
		t.Fatalf("got %q", out.String())
	}
	out.Reset()
	if err := writeStatus(&out, nil, false, fixtureNow); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No Mesh devices found.") {
		t.Fatal(out.String())
	}
}

func TestLoadMeshDevices(t *testing.T) {
	regs, physical, nodes := fixtureDevices()
	c := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected mutation: %s", r.Method)
		}
		var result any
		switch r.URL.Path {
		case "/accounts/acc/devices/registrations":
			result = regs
		case "/accounts/acc/devices/physical-devices":
			result = physical
		case "/accounts/acc/warp_connector":
			result = nodes
		case "/accounts/acc/warp_connector/node1/connections", "/accounts/acc/warp_connector/node2/connections":
			result = []cfapi.MeshConnector{}
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	})
	local := fakeLocalWARP{info: warpcli.RegistrationInfo{DeviceID: "dev1"}}
	devices, err := loadMeshDevices(context.Background(), c, "acc", local, fixtureNow, nil)
	if err != nil || len(devices) != 5 || !devices[0].ThisMachine {
		t.Fatalf("got %#v, %v", devices, err)
	}
	local.infoErr = fmt.Errorf("warp-cli is absent")
	devices, err = loadMeshDevices(context.Background(), c, "acc", local, fixtureNow, nil)
	if err != nil || len(devices) != 5 || devices[0].ThisMachine {
		t.Fatalf("got %#v, %v", devices, err)
	}
}

func TestLoadMeshDevicesFailure(t *testing.T) {
	c := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "physical-devices") {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"missing device permission"}]}`)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":[]}`)
	})
	_, err := loadMeshDevices(context.Background(), c, "acc", nil, fixtureNow, nil)
	if err == nil || !strings.Contains(err.Error(), "missing device permission") {
		t.Fatalf("got %v", err)
	}
}

func TestMachineIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		info warpcli.RegistrationInfo
		want []bool
	}{
		{"registration", warpcli.RegistrationInfo{RegistrationID: "r1", DeviceID: "d"}, []bool{true, false, false}},
		{"device", warpcli.RegistrationInfo{DeviceID: "d"}, []bool{true, true, false}},
		{"explicit device precedes legacy ID", warpcli.RegistrationInfo{DeviceID: "d", ID: "other"}, []bool{true, true, false}},
		{"legacy registration", warpcli.RegistrationInfo{ID: "r2"}, []bool{false, true, false}},
		{"legacy device", warpcli.RegistrationInfo{ID: "d"}, []bool{true, true, false}},
		{"node", warpcli.RegistrationInfo{ConnectorID: "n"}, []bool{false, false, true}},
		{"no hostname guessing", warpcli.RegistrationInfo{}, []bool{false, false, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			devices := []meshDevice{{ID: "r1", DeviceID: "d", Kind: "device"}, {ID: "r2", DeviceID: "d", Kind: "device"}, {ID: "n", Kind: "node"}}
			markThisMachine(devices, tc.info)
			for i, d := range devices {
				if d.ThisMachine != tc.want[i] {
					t.Errorf("device %d: got %v", i, d.ThisMachine)
				}
			}
		})
	}
}

func TestStatusAgeAndSafeFields(t *testing.T) {
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{5 * time.Minute, "online"}, {5*time.Minute + time.Second, "last seen 5m ago"}, {3 * time.Hour, "last seen 3h ago"}, {49 * time.Hour, "last seen 2d ago"},
	} {
		d := meshDevice{LastSeenAt: timeAgo(tc.age), Online: recentlySeen(timeAgo(tc.age), fixtureNow)}
		if got := deviceState(d, fixtureNow); got != tc.want {
			t.Errorf("age %v: %q", tc.age, got)
		}
	}
	if got := tableField("bad\tname\n\x1b"); got != "bad name  " {
		t.Fatalf("got %q", got)
	}
	if got := deviceState(meshDevice{Online: true, ConnectionState: "degraded"}, fixtureNow); got != "online (degraded)" {
		t.Fatal(got)
	}
	var out bytes.Buffer
	if err := writeStatus(&out, []meshDevice{{Name: "v6-only", IPv6: "2606:4700:cf1:1000::2"}}, false, fixtureNow); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2606:4700:cf1:1000::2") {
		t.Fatal(out.String())
	}
}

func TestJoinNodeRegistration(t *testing.T) {
	regs, physical, _ := fixtureDevices()
	nodes := []cfapi.MeshNode{{ID: "node", Name: "meshscale-node", Status: "healthy", Connectors: []cfapi.MeshConnector{{ID: "dev1", HAStatus: "active"}}}}
	devices := mergeMeshDevices(regs, physical, nodes, fixtureNow)
	if len(devices) != 3 {
		t.Fatalf("duplicate node: %#v", devices)
	}
	var node meshDevice
	for _, d := range devices {
		if d.Kind == "node" {
			node = d
		}
	}
	if node.ID != "node" || node.RegistrationID != "reg1" || node.IPv4 != "100.96.0.1" || !node.Online {
		t.Fatalf("incorrect join: %#v", node)
	}
	for _, info := range []warpcli.RegistrationInfo{{ID: "dev1"}, {DeviceID: "dev1"}, {RegistrationID: "reg1"}} {
		markThisMachine(devices, info)
		for _, d := range devices {
			if d.Kind == "node" && !d.ThisMachine {
				t.Fatalf("node not identified: %#v", info)
			}
		}
	}
	// Equal hostnames do not join unrelated registrations.
	nodes[0].Connectors = nil
	nodes[0].Name = "laptop"
	devices = mergeMeshDevices(regs, physical, nodes, fixtureNow)
	if len(devices) != 4 {
		t.Fatalf("joined by hostname: %#v", devices)
	}
}

func TestRememberOfflineNode(t *testing.T) {
	online := true
	state := &config.MeshState{}
	client := commandAPI(t, func(w http.ResponseWriter, r *http.Request) {
		var result any
		switch r.URL.Path {
		case "/accounts/acc/devices/registrations":
			result = []cfapi.Registration{{ID: "reg", Device: cfapi.RegistrationDevice{ID: "device"}, VirtualIPv4: "100.96.0.8"}}
		case "/accounts/acc/devices/physical-devices":
			result = []cfapi.PhysicalDevice{}
		case "/accounts/acc/warp_connector":
			status := "down"
			if online {
				status = "healthy"
			}
			result = []cfapi.MeshNode{{ID: "node", Name: "meshscale-test", Status: status}}
		case "/accounts/acc/warp_connector/node/connections":
			connectors := []cfapi.MeshConnector{}
			if online {
				connectors = append(connectors, cfapi.MeshConnector{ID: "reg"})
			}
			result = connectors
		default:
			t.Errorf("unexpected %s", r.URL)
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	})
	for _, connected := range []bool{true, false} {
		online = connected
		ds, err := loadMeshDevices(context.Background(), client, "acc", nil, fixtureNow, state)
		if err != nil {
			t.Fatal(err)
		}
		if len(ds) != 1 || ds[0].Kind != "node" || ds[0].IPv4 != "100.96.0.8" || ds[0].Online != connected {
			t.Fatalf("online %v: %#v", connected, ds)
		}
	}
}

func TestStatusNoCacheKeepsAccountIdentityInMemory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	state, err := statusMeshState(true)
	if err != nil {
		t.Fatal(err)
	}
	state.Remember("private-account-id", "node", "registration")
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	dir, err := config.Dir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "mesh-state.json")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("no-cache wrote state: %v", err)
	}
	// Normal status still persists and reloads its associations.
	persistent, err := statusMeshState(false)
	if err != nil {
		t.Fatal(err)
	}
	persistent.Remember("private-account-id", "node", "registration")
	if err := persistent.Save(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := statusMeshState(false)
	if err != nil || loaded.Node("private-account-id", "registration") != "node" {
		t.Fatalf("default cache failed: %v", err)
	}
	// No-cache must ignore existing associations and leave their file unchanged.
	fresh, err := statusMeshState(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.Registrations("private-account-id", "node")) != 0 {
		t.Fatal("no-cache read existing associations")
	}
	fresh.Remember("different-account", "other-node", "other-registration")
	if err := fresh.Save(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("no-cache modified existing cache: %v", err)
	}
}

func TestExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		device meshDevice
		want   string
	}{
		{"advertisement", meshDevice{OffersExit: true}, "offers exit node"},
		{"selected offline", meshDevice{ExitNode: "ashburn", ExitState: "blocked: selected exit unavailable"}, "ashburn (blocked: selected exit unavailable)"},
		{"ordinary", meshDevice{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitState(tc.device); got != tc.want {
				t.Fatalf("%q != %q", got, tc.want)
			}
		})
	}
}
