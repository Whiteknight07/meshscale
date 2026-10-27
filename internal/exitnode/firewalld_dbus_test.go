package exitnode

import (
	"errors"
	"os"
	"testing"
)

func TestFirewalldWithoutSystemBusInContainer(t *testing.T) {
	if os.Getenv("MESHSCALE_E2E_NO_DBUS") != "1" {
		t.Skip("opt-in headless container check")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("run only in a disposable container")
	}
	for _, path := range []string{"/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("test requires an absent system bus")
		}
	}
	_, err := (FirewalldDBus{}).Zone(t.Context(), "meshsecure0")
	if !errors.Is(err, ErrFirewalldUnavailable) {
		t.Fatalf("headless Linux wrongly requires firewalld: %v", err)
	}
}
