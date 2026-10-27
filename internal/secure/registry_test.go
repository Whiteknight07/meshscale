package secure

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func testRecord(t *testing.T, id string) Record {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	public, _ := key.Public()
	return Record{RegistrationID: id, PublicKey: public, Enabled: true}
}
func registration(id, ip string) cfapi.Registration {
	return cfapi.Registration{ID: id, Device: cfapi.RegistrationDevice{ID: "dev-" + id, Name: "laptop"}, User: cfapi.User{Email: "alice@example.com"}, VirtualIPv4: ip}
}

func TestBuildPeers(t *testing.T) {
	a, b := testRecord(t, "a"), testRecord(t, "b")
	regs := []cfapi.Registration{registration("a", "100.96.0.1"), registration("b", "100.96.0.2")}
	for _, tc := range []struct {
		name    string
		records []Record
		regs    []cfapi.Registration
		want    int
		warns   bool
	}{
		{"normal", []Record{a, b}, regs, 2, false},
		{"unknown registration", []Record{testRecord(t, "missing")}, regs, 0, false},
		{"duplicate key", []Record{a, {RegistrationID: "b", PublicKey: a.PublicKey, Enabled: true}}, regs, 0, true},
		{"duplicate registration", []Record{a, a}, regs, 0, true},
		{"duplicate Mesh IP", []Record{a, b}, []cfapi.Registration{regs[0], registration("b", "100.96.0.1")}, 0, true},
		{"public endpoint", []Record{a}, []cfapi.Registration{registration("a", "1.1.1.1")}, 0, true},
		{"incomplete", []Record{a}, []cfapi.Registration{{ID: "a", VirtualIPv4: "100.96.0.1"}}, 0, true},
		{"disabled", []Record{{RegistrationID: a.RegistrationID, PublicKey: a.PublicKey}}, regs, 0, false},
		{"bad record spares others", []Record{a, b, {RegistrationID: "c", PublicKey: a.PublicKey, Enabled: true}}, append(regs, registration("c", "100.96.0.3")), 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peers, warnings, err := BuildPeers("account", tc.records, tc.regs)
			if err != nil || (len(warnings) > 0) != tc.warns || len(peers) != tc.want {
				t.Fatalf("peers=%+v warnings=%q err=%v", peers, warnings, err)
			}
			for _, p := range peers {
				ip, _ := Address("account", p.PublicKey)
				if p.IP != ip || len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != netip.PrefixFrom(ip, 128) || p.Endpoint.Port() != Port || p.Owner != "alice@example.com" {
					t.Fatalf("incorrect peer: %+v", p)
				}
			}
		})
	}
	forward, _, _ := BuildPeers("account", []Record{a, b}, regs)
	reverse, _, _ := BuildPeers("account", []Record{b, a}, []cfapi.Registration{regs[1], regs[0]})
	if !reflect.DeepEqual(forward, reverse) || forward[0].DNSName == forward[1].DNSName {
		t.Fatal("names/order not deterministic")
	}
	for _, field := range []string{"revoke", "delete"} {
		t.Run(field, func(t *testing.T) {
			reg := regs[0]
			now := time.Now()
			if field == "revoke" {
				reg.RevokedAt = &now
			} else {
				reg.DeletedAt = &now
			}
			peers, _, err := BuildPeers("account", []Record{a}, []cfapi.Registration{reg})
			if err != nil || len(peers) != 0 {
				t.Fatalf("revoked peer: %v %v", peers, err)
			}
		})
	}
}

type memoryDirectory struct {
	lists  []cfapi.GatewayList
	writes int
}

func (d *memoryDirectory) ListGatewayLists(context.Context, string) ([]cfapi.GatewayList, error) {
	return d.lists, nil
}
func (d *memoryDirectory) CreateGatewayList(_ context.Context, _ string, l cfapi.GatewayList) (cfapi.GatewayList, error) {
	l.ID = "list"
	d.lists = append(d.lists, l)
	d.writes++
	return l, nil
}
func (d *memoryDirectory) UpdateGatewayList(_ context.Context, _ string, id string, l cfapi.GatewayList) (cfapi.GatewayList, error) {
	for i := range d.lists {
		if d.lists[i].ID == id {
			l.ID = id
			d.lists[i] = l
		}
	}
	d.writes++
	return l, nil
}
func TestPublish(t *testing.T) {
	d := &memoryDirectory{lists: []cfapi.GatewayList{{ID: "customer", Name: "my-list", Type: "IP", Description: "owned by customer"}}}
	r := testRecord(t, "a")
	ip := netip.MustParseAddr("100.96.0.1")
	for i := 0; i < 2; i++ {
		if err := Publish(t.Context(), d, "account", r, ip); err != nil {
			t.Fatal(err)
		}
	}
	if d.writes != 1 || d.lists[0].Description != "owned by customer" {
		t.Fatalf("non-idempotent writes: %d", d.writes)
	}
	got, warnings, err := Records(t.Context(), d, "account")
	if err != nil || len(warnings) != 0 || !reflect.DeepEqual(got, []Record{r}) {
		t.Fatalf("records=%v error=%v", got, err)
	}
	r.Enabled = false
	if err := Publish(t.Context(), d, "account", r, ip); err != nil {
		t.Fatal(err)
	}
	got, warnings, err = Records(t.Context(), d, "account")
	if err != nil || len(warnings) != 0 || len(got) != 0 || d.writes != 2 {
		t.Fatalf("withdraw=%v %v writes=%d", got, err, d.writes)
	}
	// A similarly named unowned list is never adopted.
	d.lists[1].Description = "customer list"
	if err := Publish(t.Context(), d, "account", r, ip); err == nil {
		t.Fatal("adopted unowned list")
	}
	if _, warnings, err := Records(t.Context(), d, "account"); err != nil || len(warnings) == 0 {
		t.Fatal("accepted invalid record")
	}
}
func TestRecordsRejectDuplicateAndMalformed(t *testing.T) {
	r := testRecord(t, "a")
	data, _ := json.Marshal(r)
	l := cfapi.GatewayList{ID: "one", Name: listPrefix + "a", Type: "IP", Description: recordPrefix + string(data)}
	for _, tc := range []struct {
		name  string
		lists []cfapi.GatewayList
	}{
		{"duplicate", []cfapi.GatewayList{l, l}},
		{"malformed", []cfapi.GatewayList{{ID: "bad", Name: l.Name, Type: "IP", Description: recordPrefix + "{"}}},
		{"mismatch", []cfapi.GatewayList{{ID: "bad", Name: listPrefix + "b", Type: "IP", Description: l.Description}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, warnings, err := Records(t.Context(), &memoryDirectory{lists: tc.lists}, "account"); err != nil || len(got) != 0 || len(warnings) == 0 {
				t.Fatal("accepted invalid directory")
			}
		})
	}
}

func TestRecordsIsolateInvalid(t *testing.T) {
	good, bad := testRecord(t, "good"), testRecord(t, "bad")
	list := func(r Record) cfapi.GatewayList {
		data, _ := json.Marshal(r)
		return cfapi.GatewayList{ID: r.RegistrationID, Name: listPrefix + r.RegistrationID, Type: "IP", Description: recordPrefix + string(data)}
	}
	valid := list(good)
	for _, tc := range []struct {
		name     string
		entries  []cfapi.GatewayList
		warnings int
	}{
		{"malformed", []cfapi.GatewayList{{ID: "bad", Name: listPrefix + "bad", Type: "IP", Description: recordPrefix + "{"}}, 1},
		{"duplicate", []cfapi.GatewayList{list(bad), list(bad)}, 2},
		{"invalid key", []cfapi.GatewayList{list(Record{RegistrationID: "bad", PublicKey: "invalid", Enabled: true})}, 1},
		{"unowned", []cfapi.GatewayList{{ID: "bad", Name: listPrefix + "bad", Type: "IP", Description: "customer"}}, 1},
		{"disabled", []cfapi.GatewayList{list(Record{RegistrationID: bad.RegistrationID, PublicKey: bad.PublicKey})}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries := append([]cfapi.GatewayList{valid}, tc.entries...)
			records, warnings, err := Records(t.Context(), &memoryDirectory{lists: entries}, "account")
			if err != nil || !reflect.DeepEqual(records, []Record{good}) || len(warnings) != tc.warnings {
				t.Fatalf("records=%v warnings=%v err=%v", records, warnings, err)
			}
		})
	}
}

type localRegistration struct {
	backend.Backend
	info backend.Registration
}

func (l localRegistration) Registration(context.Context) (backend.Registration, error) {
	return l.info, nil
}

type registrationSource struct {
	Registrations
	regs []cfapi.Registration
}

func (s registrationSource) ListRegistrations(context.Context, string) ([]cfapi.Registration, error) {
	return s.regs, nil
}
func TestPublishLocalSelection(t *testing.T) {
	key, _ := GenerateKey()
	a, b := registration("a", "100.96.0.1"), registration("b", "100.96.0.2")
	a.Device.ID = "physical"
	b.Device.ID = "physical"
	for _, tc := range []struct {
		name string
		info backend.Registration
		regs []cfapi.Registration
		id   string
		bad  bool
	}{
		{"explicit", backend.Registration{RegistrationID: "a", DeviceID: "physical"}, []cfapi.Registration{a, b}, "a", false},
		{"ambiguous physical", backend.Registration{DeviceID: "physical"}, []cfapi.Registration{a, b}, "", true},
		{"client enrollment labeled device", backend.Registration{DeviceID: "b"}, []cfapi.Registration{a, b}, "b", false},
		{"missing", backend.Registration{RegistrationID: "missing"}, []cfapi.Registration{a, b}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := &memoryDirectory{}
			self, err := PublishLocal(t.Context(), directory, registrationSource{regs: tc.regs}, "account", localRegistration{info: tc.info}, key, Advertisement{Enabled: true})
			if (err != nil) != tc.bad || self.RegistrationID != tc.id {
				t.Fatalf("self=%+v err=%v", self, err)
			}
			if tc.bad && directory.writes != 0 {
				t.Fatal("published an ambiguous identity")
			}
		})
	}
}
