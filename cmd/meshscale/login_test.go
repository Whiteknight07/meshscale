package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/auth"
)

func TestChooseAccount(t *testing.T) {
	accounts := []auth.Account{{ID: "a", Name: "First"}, {ID: "b", Name: "Second"}}
	for _, test := range []struct {
		name    string
		items   []auth.Account
		id      string
		input   string
		want    string
		wantErr bool
	}{
		{name: "only account", items: accounts[:1], want: "a"},
		{name: "explicit account", items: accounts, id: "b", want: "b"},
		{name: "prompt number", items: accounts, input: "2\n", want: "b"},
		{name: "prompt id", items: accounts, input: "a\n", want: "a"},
		{name: "unknown id", items: accounts, id: "missing", wantErr: true},
		{name: "no accounts", wantErr: true},
		{name: "noninteractive", items: accounts, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := &loginInput{reader: bufio.NewReader(strings.NewReader(test.input))}
			account, err := chooseAccount(context.Background(), test.items, test.id, input.readLine, io.Discard)
			if (err != nil) != test.wantErr || (!test.wantErr && account.ID != test.want) {
				t.Fatalf("account=%q error=%v", account.ID, err)
			}
		})
	}
}

func TestLoginInputPreservesPendingRead(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	input := &loginInput{reader: bufio.NewReader(reader)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := input.readLine(ctx); err != context.Canceled {
		t.Fatalf("canceled read: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(writer, "2\n")
		done <- err
	}()
	accounts := []auth.Account{{ID: "a", Name: "First"}, {ID: "b", Name: "Second"}}
	account, err := chooseAccount(context.Background(), accounts, "", input.readLine, io.Discard)
	if err != nil || account.ID != "b" {
		t.Fatalf("pending stdin read stole account selection: account=%q, error=%v", account.ID, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLoginInputKeepsBufferedAccountSelection(t *testing.T) {
	input := &loginInput{reader: bufio.NewReader(strings.NewReader("pasted-code\n2\n"))}
	line, err := input.readLine(context.Background())
	if err != nil || line != "pasted-code\n" {
		t.Fatalf("first line = %q, error=%v", line, err)
	}
	accounts := []auth.Account{{ID: "a", Name: "First"}, {ID: "b", Name: "Second"}}
	account, err := chooseAccount(context.Background(), accounts, "", input.readLine, io.Discard)
	if err != nil || account.ID != "b" {
		t.Fatalf("buffered account selection: account=%q, error=%v", account.ID, err)
	}
}

func TestAccountPickerDoesNotEmitTerminalControls(t *testing.T) {
	accounts := []auth.Account{{ID: "first", Name: "account\x1b]52;c;payload\a\rspoof"}, {ID: "second", Name: "Other"}}
	var out bytes.Buffer
	selected, err := chooseAccount(t.Context(), accounts, "", func(context.Context) (string, error) { return "1", nil }, &out)
	if err != nil || selected.ID != "first" {
		t.Fatalf("selection: %v", err)
	}
	if strings.ContainsAny(out.String(), "\x1b\a\r") {
		t.Fatal("account response injected terminal controls")
	}
}
