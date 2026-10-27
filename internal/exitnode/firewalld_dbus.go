package exitnode

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"github.com/godbus/dbus/v5"
)

const firewalldService = "org.fedoraproject.FirewallD1"
const firewalldPath dbus.ObjectPath = "/org/fedoraproject/FirewallD1"
const firewalldInterface = "org.fedoraproject.FirewallD1"
const firewalldZoneInterface = firewalldInterface + ".zone"

type FirewalldClient interface {
	Zone(context.Context, string) (string, error)
	QueryForward(context.Context, string) (bool, error)
	Watch(context.Context) (<-chan struct{}, error)
}

// FirewalldDBus reads firewalld's runtime state over the shared system bus.
type FirewalldDBus struct{}

// Zone returns dev's zone, or the default zone that firewalld applies to
// interfaces without one.
func (FirewalldDBus) Zone(ctx context.Context, dev string) (string, error) {
	var zone string
	if err := firewalldCall(ctx, firewalldZoneInterface+".getZoneOfInterface", &zone, dev); err != nil {
		return "", err
	}
	if zone == "" {
		if err := firewalldCall(ctx, firewalldInterface+".getDefaultZone", &zone); err != nil {
			return "", err
		}
	}
	return zone, nil
}

// QueryForward reports the zone's runtime intra-zone forwarding (firewalld
// 1.0+), as `firewall-cmd --zone=Z --query-forward` does.
func (FirewalldDBus) QueryForward(ctx context.Context, zone string) (bool, error) {
	var settings map[string]dbus.Variant
	if err := firewalldCall(ctx, firewalldZoneInterface+".getZoneSettings2", &settings, zone); err != nil {
		return false, err
	}
	forward, ok := settings["forward"].Value().(bool)
	if !ok {
		return false, fmt.Errorf("firewalld zone %s reports no forward setting; firewalld 1.0 or newer is required", zone)
	}
	return forward, nil
}

func firewalldCall(ctx context.Context, method string, result any, args ...any) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		// godbus returns this untyped error when neither default socket exists,
		// before attempting a dial that could produce ENOENT.
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) || err.Error() == "system bus not found" {
			return ErrFirewalldUnavailable // no system bus, so no firewalld
		}
		return fmt.Errorf("connect to system D-Bus: %w", err)
	}
	call := conn.Object(firewalldService, firewalldPath).CallWithContext(ctx, method, 0, args...)
	if call.Err != nil {
		var busErr dbus.Error
		if errors.As(call.Err, &busErr) && (busErr.Name == "org.freedesktop.DBus.Error.ServiceUnknown" || busErr.Name == "org.freedesktop.DBus.Error.NameHasNoOwner") {
			return ErrFirewalldUnavailable
		}
		return fmt.Errorf("firewalld %s: %w", method, call.Err)
	}
	return call.Store(result)
}

func (FirewalldDBus) Watch(ctx context.Context) (<-chan struct{}, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("connect firewalld signal monitor: %w", err)
	}
	// Any firewalld signal may change a zone or its forwarding (reloads, runtime
	// --change-interface, --add-forward), so all of them invalidate the cache.
	if err := conn.AddMatchSignal(dbus.WithMatchSender(firewalldService)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath("/org/freedesktop/DBus"),
		dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"),
		dbus.WithMatchArg(0, firewalldService),
	); err != nil {
		conn.Close()
		return nil, err
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		defer conn.Close()
		defer conn.RemoveSignal(signals)
		for {
			select {
			case <-ctx.Done():
				return
			case signal := <-signals:
				if signal == nil {
					return // the bus connection closed
				}
				queueEvent(out)
			}
		}
	}()
	return out, nil
}
