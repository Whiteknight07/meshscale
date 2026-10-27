package devicesync

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRegistryOrderAndFailures(t *testing.T) {
	var r Registry
	var calls []string
	r.Register("rules", func(context.Context, Snapshot) error { calls = append(calls, "rules"); return nil })
	r.Register("dns", func(context.Context, Snapshot) error { calls = append(calls, "dns"); return errors.New("offline") })
	if err := r.Run(context.Background(), Snapshot{}); err == nil {
		t.Fatal("lost hook error")
	}
	if !reflect.DeepEqual(calls, []string{"dns", "rules"}) {
		t.Fatal(calls)
	}
}
func TestFingerprintOrderAndIdentity(t *testing.T) {
	a := Snapshot{Account: "a", Devices: []Device{{ID: "b", Name: "laptop"}, {ID: "a", IPv4: "100.96.0.2"}}}
	b := Snapshot{Account: "a", Devices: []Device{a.Devices[1], a.Devices[0]}}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("API order changed fingerprint")
	}
	b.Devices[0].IPv4 = "100.96.0.3"
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("IP change not detected")
	}
	b = a
	b.Account = "b"
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("account isolation")
	}
}
