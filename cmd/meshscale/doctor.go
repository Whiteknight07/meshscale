package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

const doctorCheckTimeout = 2500 * time.Millisecond

type doctorCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Measurement string `json:"measurement"`
	Detail      string `json:"detail"`
	Hint        string `json:"hint"`
}
type doctorReport struct {
	Version string        `json:"version"`
	Checks  []doctorCheck `json:"checks"`
}
type doctorTask struct {
	name, measurement, hint string
	run                     func(context.Context) doctorCheck
}

func registerDoctorCommands() {
	register(&command{name: "doctor", short: "read-only Mesh health checklist (--json)", run: runDoctor})
	register(&command{name: "bugreport", short: "write a redacted local diagnostic archive (--out PATH)", run: runBugreport})
}

func runDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the checklist as JSON")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: meshscale doctor [--json]")
	}
	report := collectDoctor(ctx)
	if err := writeDoctor(os.Stdout, report, *asJSON); err != nil {
		return err
	}
	if report.failed() {
		return errors.New("checks failed; follow the checklist hints")
	}
	return nil
}

func collectDoctor(ctx context.Context) doctorReport {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dir, _ := doctorConfigDir()
	scrubCtx, scrubCancel := context.WithTimeout(ctx, doctorCheckTimeout)
	defer scrubCancel()
	secretRead := startDoctorRead(scrubCtx, func(context.Context) ([]string, error) { return bugreportKnownSecrets(dir), nil })
	report := runDoctorTasks(ctx, newDoctorTasks(ctx), doctorCheckTimeout)
	secrets, scrubErr := secretRead.get(scrubCtx)
	for i := range report.Checks {
		if scrubErr != nil {
			report.Checks[i].Detail = "detail withheld: credential scrub deadline exceeded"
		} else {
			report.Checks[i].Detail = tableField(scrubDoctorDetail(report.Checks[i].Detail, secrets))
		}
	}
	return report
}

// Every check has an independent deadline, including waiting for shared inputs.
// Buffered channels also bound the command when a kernel reader ignores context.
func runDoctorTasks(ctx context.Context, tasks []doctorTask, timeout time.Duration) doctorReport {
	type result struct {
		index int
		check doctorCheck
	}
	results := make(chan result, len(tasks))
	for i, task := range tasks {
		go func() {
			checkCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			done := make(chan doctorCheck, 1)
			go func() { done <- task.run(checkCtx) }()
			var check doctorCheck
			select {
			case check = <-done:
			case <-checkCtx.Done():
				check = doctorResult("fail", "check timed out or was canceled", task.hint)
			}
			check.Name, check.Measurement = task.name, task.measurement
			check.Detail = tableField(scrubDoctorDetail(check.Detail, nil))
			results <- result{i, check}
		}()
	}
	report := doctorReport{Version: version, Checks: make([]doctorCheck, len(tasks))}
	for range tasks {
		r := <-results
		report.Checks[r.index] = r.check
	}
	return report
}
func doctorResult(status, detail, hint string) doctorCheck {
	return doctorCheck{Status: status, Detail: detail, Hint: hint}
}
func (r doctorReport) failed() bool {
	for _, c := range r.Checks {
		if c.Status == "fail" {
			return true
		}
	}
	return false
}
func writeDoctor(out io.Writer, report doctorReport, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	for _, c := range report.Checks {
		if _, err := fmt.Fprintf(out, "%s %s [%s]: %s; %s\n", c.Status, c.Name, c.Measurement, c.Detail, c.Hint); err != nil {
			return err
		}
	}
	return nil
}

type doctorValue[T any] struct {
	value T
	err   error
}
type doctorFuture[T any] struct {
	done   chan struct{}
	result doctorValue[T]
}

func startDoctorRead[T any](ctx context.Context, read func(context.Context) (T, error)) *doctorFuture[T] {
	f := &doctorFuture[T]{done: make(chan struct{})}
	go func() {
		readCtx, cancel := context.WithTimeout(ctx, doctorCheckTimeout)
		defer cancel()
		f.result.value, f.result.err = read(readCtx)
		close(f.done)
	}()
	return f
}
func (f *doctorFuture[T]) get(ctx context.Context) (T, error) {
	// Prefer an already completed read even if the caller's deadline just fired.
	select {
	case <-f.done:
		return f.result.value, f.result.err
	default:
	}
	select {
	case <-f.done:
		return f.result.value, f.result.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}
