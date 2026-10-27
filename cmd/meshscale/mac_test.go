package main

import (
	"github.com/Whiteknight07/meshscale/internal/warpcli"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMacRegistrationIdentifiesActiveAPISession(t *testing.T) {
	data, err := os.ReadFile("../../internal/warpcli/testdata/mac-registration.txt")
	if err != nil {
		t.Fatal(err)
	}
	info, err := warpcli.ParseRegistration(string(data))
	if err != nil {
		t.Fatal(err)
	}
	devices := []meshDevice{{ID: info.DeviceID, DeviceID: "physical-mac", Kind: "device"}, {ID: "old-session", DeviceID: "physical-mac", Kind: "device"}}
	markThisMachine(devices, info)
	if !devices[0].ThisMachine || devices[1].ThisMachine {
		t.Fatal(devices)
	}
}

func TestMDMPolicyPublicationNeverOverwritesUnownedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "com.cloudflare.warp.plist")
	initial, err := writeMacMDM(path, "postureonly", nil)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Mode().Perm() != 0600 {
		t.Fatal(initial.Mode())
	}
	if _, err := writeMacMDM(path, "unsafe replacement", nil); err == nil {
		t.Fatal("overwrote existing file")
	}
	updated, err := writeMacMDM(path, "warp after guard", initial)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(initial, updated) {
		t.Fatal("replacement was not atomic")
	}
	if _, err := writeMacMDM(path, "stale writer", initial); err == nil {
		t.Fatal("accepted stale file identity")
	}
	contents, _ := os.ReadFile(path)
	if string(contents) != "warp after guard" {
		t.Fatal(string(contents))
	}
}

func TestMDMStagingEscapesSecretsAndRetainsDisconnect(t *testing.T) {
	credentials := macMDMCredentials{Team: "team", ClientID: "client&<", ClientSecret: "secret<&\""}
	plist := mdmPlist(credentials, "postureonly")
	if !strings.Contains(plist, "<string>postureonly</string>") || !strings.Contains(plist, "secret&lt;&amp;&#34;") || !strings.Contains(plist, "<key>switch_locked</key><false/>") || !strings.Contains(plist, "<key>auto_connect</key><integer>0</integer>") {
		t.Fatal("unsafe MDM staging")
	}
	if strings.Contains(plist, "<key>enabled</key>") {
		t.Fatal("deprecated enabled conflicts with switch_locked")
	}
	if got := shellQuoteMac("a'b$(x)"); got != "'a'\\''b$(x)'" {
		t.Fatal(got)
	}
}
