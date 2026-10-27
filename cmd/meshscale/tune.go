package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/warptune"
)

func init() {
	register(&command{name: "tune", short: "explicit WARP receive buffer tuning: --warp-buffers [--undo]", run: runTune})
}

func runTune(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("tune", flag.ContinueOnError)
	buffers := fs.Bool("warp-buffers", false, "resize existing WARP UDP/443 receive sockets to 8 MiB; no sysctls")
	undo := fs.Bool("undo", false, "restore recorded WARP socket buffers")
	pid := fs.Int("warp-pid", 0, "explicit warp-svc PID (default: discover in this network namespace)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if !*buffers || fs.NArg() != 0 || *pid < 0 || *undo && *pid != 0 {
		return fmt.Errorf("usage: meshscale tune --warp-buffers [--warp-pid PID | --undo]")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("WARP buffer tuning requires Linux root with CAP_SYS_PTRACE and CAP_NET_ADMIN")
	}
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	tuner := warptune.Tuner{Dir: filepath.Join(dir, "tuning"), Backend: warptune.System{}}
	if *undo {
		if err := tuner.Undo(ctx); err != nil {
			return err
		}
		fmt.Println("WARP receive buffers restored; closed/replaced sockets left unchanged.")
		return nil
	}
	if err := tuner.Apply(ctx, *pid); err != nil {
		return err
	}
	fmt.Println("Existing WARP UDP/443 receive buffers: 8 MiB. Undo: meshscale tune --warp-buffers --undo. WARP reconnects discard this tuning.")
	return nil
}
