package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/service"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

func init() {
	register(&command{name: "service", short: "install, uninstall or inspect the explicit background service", run: runService})
}
func runService(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshscale service install [--print] [--ssh] | uninstall | status")
	}
	fs := flag.NewFlagSet("service "+args[0], flag.ContinueOnError)
	printOnly := fs.Bool("print", false, "print systemd unit or macOS launchd plist without installing")
	initPolicy := fs.Bool("init-policy", false, "initialize missing owner-only SSH policy when installing with --ssh")
	ssh := fs.Bool("ssh", false, "enable keyless SSH in the installed daemon")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected service arguments")
	}
	if args[0] != "install" && args[0] != "uninstall" && args[0] != "status" {
		return fmt.Errorf("unknown service operation %q", args[0])
	}
	if *initPolicy && (args[0] != "install" || !*ssh || *printOnly) {
		return fmt.Errorf("--init-policy requires service install --ssh")
	}
	if args[0] != "install" && (*printOnly || *ssh) {
		return fmt.Errorf("--print and --ssh require service install")
	}
	if *printOnly && *ssh {
		return fmt.Errorf("--ssh is saved in the service config by service install; --print only shows the unit")
	}
	if args[0] == "status" {
		dir, err := config.ServiceDir()
		if err != nil {
			return err
		}
		var status service.Status
		err = service.Request(ctx, dir, "GET", "/status", nil, &status)
		if err == nil {
			return json.NewEncoder(os.Stdout).Encode(status)
		}
		if !noServiceSocket(err) {
			return err
		}
		fmt.Println("No meshscale daemon is running for this user/configuration.")
		if runtime.GOOS == "linux" {
			out, err := service.Exec(ctx, "systemctl", "show", "meshscale.service", "--property=LoadState,ActiveState,UnitFileState")
			fmt.Print(string(out))
			return err
		}
		return nil
	}
	if args[0] == "install" {
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		binary, err = filepath.EvalSymlinks(binary)
		if err != nil {
			return err
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		configHome, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		install := service.Installation{Binary: binary, Home: home, ConfigHome: configHome}
		var unit string
		if runtime.GOOS == "darwin" {
			unit, err = install.Plist()
		} else {
			unit, err = install.Unit()
		}
		if err != nil {
			return err
		}
		if *printOnly {
			fmt.Print(unit)
			return nil
		}
		if runtime.GOOS != "linux" {
			return fmt.Errorf("automatic installation supports Linux systemd only; use service install --print for a launchd plist")
		}
		if os.Geteuid() != 0 {
			return fmt.Errorf("systemd installation requires root; run with the same root configuration used for meshscale up")
		}
		if err := service.ValidateSystemBinary(binary); err != nil {
			return err
		}
		options, err := config.LoadService()
		if err != nil {
			return err
		}
		sshChanged := options.SSH != *ssh
		sshExplicit := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "ssh" {
				sshExplicit = true
				options.SSH = *ssh
			}
		})
		if options.SSH {
			if err := ensureOwnSSHPolicy(ctx, options.SSHPolicy, *initPolicy); err != nil {
				return err
			}
		}
		if err := options.Save(); err != nil {
			return err
		}
		if err := (service.Installer{Path: service.UnitPath, Run: service.Exec}).Install(ctx, unit); err != nil {
			return err
		}
		if sshExplicit && sshChanged {
			if _, err := service.Exec(ctx, "systemctl", "restart", "meshscale.service"); err != nil {
				return err
			}
		}
		fmt.Println("Installed, enabled and started meshscale.service.")
		return nil
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("automatic uninstall supports Linux systemd only")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("systemd uninstall requires root")
	}
	if err := (service.Installer{Path: service.UnitPath, Run: service.Exec}).Uninstall(ctx); err != nil {
		return err
	}
	if err := cleanupHosts(ctx); err != nil {
		return fmt.Errorf("remove hosts DNS: %w", err)
	}
	if err := warpcli.New("").CleanupNetwork(ctx); err != nil {
		return fmt.Errorf("clean up service networking: %w", err)
	}
	fmt.Println("meshscale.service uninstalled; enrollment and configuration preserved.")
	return nil
}
