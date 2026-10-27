package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/exitnode"
)

func TestBugreportRedaction(t *testing.T) {
	input := []byte(`{"enabled":true,"ssh":true,"backend":"warp","engine":"plant-engine","newSecretField":"unknown-plant","checks":[{"name":"connection","status":"warn","detail":"private-plant","extra":"more-plant"}]}`)
	out := redactBugreport(input, nil)
	if !json.Valid(out) || !bytes.Contains(out, []byte(`"enabled": true`)) || !bytes.Contains(out, []byte(`"status": "warn"`)) {
		t.Fatalf("lost diagnostic structure: %s", out)
	}
	for _, value := range []string{"plant", "newSecretField", "extra"} {
		if bytes.Contains(out, []byte(value)) {
			t.Fatalf("leaked %q: %s", value, out)
		}
	}
	for _, input := range []string{
		`2026-10-26T12:00:00+0000 host meshscale[1]: {"email":"alice\u0040example.org"}`,
		`{"time":"2026-10-26T12:00:00Z","level":"INFO","message":"private"}` + "\n" + `unrecognized private`,
	} {
		out := redactBugreport([]byte(input), nil)
		if bytes.Contains(out, []byte("private")) || bytes.Contains(out, []byte("alice")) {
			t.Fatalf("leaked free text: %s", out)
		}
		if !bytes.Contains(out, []byte("2026-10-26T12:00:00Z")) {
			t.Fatalf("lost parsed timestamp: %s", out)
		}
	}
}

func readBugreportArchive(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Mode != 0600 || header.Typeflag != tar.TypeReg {
			t.Fatalf("unsafe member header: %+v", header)
		}
		files[header.Name], err = io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

// Every diagnostic input carries all planted secret classes, including bare
// copies. Exercise collection AND the only archive writer, then inspect every
// decompressed member rather than just scanning the compressed bytes.
func TestBugreportArchiveNeverContainsPlantedSecrets(t *testing.T) {
	secrets := []string{"plant-api-value", "plant-access-value", "plant-refresh-value", "plant-wg-value", "plant-enrollment-value", "owner+plant@example.org"}
	names := []string{"doctor.json", "versions.txt", "service-config.json", "secure-config.json", "journal.txt", "ip-rule.txt", "mesh-routes.json"}
	var sources []bugreportSource
	for _, name := range names {
		sources = append(sources, bugreportSource{name: name, read: func(context.Context) ([]byte, error) {
			return json.Marshal(map[string]any{"api_key": secrets[0], "access_token": secrets[1], "refresh_token": secrets[2], "private_key": secrets[3], "enrollment_token": secrets[4], "email": secrets[5], "unlabelled_copies": strings.Join(secrets, " | "), "enabled": true})
		}})
	}
	files := collectBugreportSources(t.Context(), sources)
	var archive bytes.Buffer
	// No pre-supplied list: discover the planted secret fields across the inputs.
	if err := writeBugreport(&archive, files, nil); err != nil {
		t.Fatal(err)
	}
	exported := readBugreportArchive(t, archive.Bytes())
	if len(exported) != len(names) {
		t.Fatalf("archive members=%d, want %d", len(exported), len(names))
	}
	for name, data := range exported {
		for _, secret := range secrets {
			if bytes.Contains(data, []byte(secret)) {
				t.Errorf("%s leaked a planted secret", name)
			}
		}
		if !bytes.Contains(data, []byte(`"enabled": true`)) {
			t.Errorf("%s lost allowed diagnostic field", name)
		}
	}
}
func TestBugreportRedactsSecretsRepeatedInEarlierMember(t *testing.T) {
	files := map[string][]byte{"a-journal.txt": []byte("unlabelled short-repeated"), "z-config.json": []byte(`{"refresh_token":"short-repeated"}`)}
	var archive bytes.Buffer
	if err := writeBugreport(&archive, files, nil); err != nil {
		t.Fatal(err)
	}
	for name, data := range readBugreportArchive(t, archive.Bytes()) {
		if bytes.Contains(data, []byte("short-repeated")) {
			t.Fatalf("%s leaked later config's token", name)
		}
	}
}
func TestBugreportKnownSecrets(t *testing.T) {
	dir := t.TempDir()
	writeDoctorFixture(t, dir, "oauth.json", `{"access_token":"saved-access-plant","refresh_token":"saved-refresh-plant"}`)
	writeDoctorFixture(t, dir, "secure/wireguard.json", `{"private_key":"wg-plant"}`)
	writeDoctorFixture(t, dir, "backend.json", `{"backend":"native","native_state_dir":"`+filepath.Join(dir, "native")+`"}`)
	writeDoctorFixture(t, dir, "native/registration.json", `{"private_key":"native-plant","registration":{"token":"native-token-plant"}}`)
	writeDoctorFixture(t, dir, "dev.env", "CLOUDFLARE_API_TOKEN='dev-token-plant'\n")
	t.Setenv("PLANTED_ACCESS_TOKEN", "env-token-plant")
	var checkBackend struct {
		Backend string `json:"backend"`
	}
	if err := doctorReadJSON(filepath.Join(dir, "backend.json"), &checkBackend); err != nil {
		t.Fatal("read planted backend", err)
	}
	known := bugreportKnownSecrets(dir)
	for i, value := range []string{"saved-access-plant", "saved-refresh-plant", "wg-plant", "native-plant", "native-token-plant", "dev-token-plant", "env-token-plant"} {
		found := false
		for _, candidate := range known {
			if candidate == value {
				found = true
			}
		}
		if !found {
			t.Errorf("known local secret class %d was not discovered", i)
		}
		if got := scrubDoctorDetail("bare "+value, known); strings.Contains(got, value) {
			t.Errorf("known local secret class %d was not scrubbed", i)
		}
	}
}
func TestBugreportConsentAndDestination(t *testing.T) {
	for _, answer := range []string{"", "n\n", "no\n", "unexpected\n"} {
		if err := confirmBugreport(strings.NewReader(answer), io.Discard, "report.tar.gz"); err == nil {
			t.Fatalf("accepted %q", answer)
		}
	}
	for _, answer := range []string{"y\n", "yes\n", "YES\n"} {
		if err := confirmBugreport(strings.NewReader(answer), io.Discard, "report.tar.gz"); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "existing.tar.gz")
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runBugreport(t.Context(), []string{"--out", path}); err == nil {
		t.Fatal("overwrote existing destination")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "preserve" {
		t.Fatal("modified existing destination")
	}
	for _, args := range [][]string{{"--out", ""}, {"extra"}, {"--unknown"}} {
		if err := runBugreport(t.Context(), args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
func TestBugreportSourceDeadlineAndErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	gate := make(chan struct{})
	defer close(gate)
	sources := []bugreportSource{
		{"stuck.txt", func(context.Context) ([]byte, error) { <-gate; return nil, nil }},
		{"missing.json", func(context.Context) ([]byte, error) {
			return []byte("private-content-plant"), errors.New("secret-error-plant")
		}},
	}
	started := time.Now()
	files := collectBugreportSources(ctx, sources)
	if time.Since(started) > time.Second {
		t.Fatal("source ignored deadline")
	}
	if !json.Valid(files["missing.json"]) {
		t.Fatal("missing JSON source marker is not valid JSON")
	}
	for _, data := range files {
		if bytes.Contains(data, []byte("plant")) {
			t.Fatal("error included raw source or error")
		}
	}
	var output bugreportBuffer
	data := bytes.Repeat([]byte("x"), 2*bugreportInputLimit)
	if n, err := output.Write(data); err != nil || n != len(data) || output.Len() != bugreportInputLimit || !output.truncated {
		t.Fatal("command output limit failed")
	}
}

func TestBugreportRoutesDoNotDumpUnrelatedMainRoutes(t *testing.T) {
	snapshot := exitnode.Snapshot{V4: exitnode.Family{Routes: []exitnode.Route{
		{Dst: "100.96.0.0/12", Dev: "CloudflareWARP", Table: "65743"},
		{Dst: "default", Dev: "eth0", Table: "main"},
	}}, V6: exitnode.Family{Routes: []exitnode.Route{{Dst: "fd6d:6573:6873::/48", Dev: "meshsecure0", Table: "main"}}}}
	queries := bugreportRouteQueries(snapshot)
	if got := strings.Join(queries, "|"); got != "table 65743|table main dev meshsecure0" {
		t.Fatalf("route selection=%s", got)
	}
}

// Scan every decompressed archive member for every encoding of every planted
// class. No secret discovery/blocklist is supplied to the real archive writer.
func TestBugreportArchiveAllowlistWithholdsUnknownAndEscapedSecrets(t *testing.T) {
	plants := map[string]string{
		"oauth_access": "oauth-access-plant", "oauth_refresh": "oauth-refresh-plant",
		"mesh_node": "mesh-node-plant", "connector": "connector-token-plant",
		"wireguard_private":    "d2lyZWd1YXJkLXByaXZhdGUta2V5LXBsYW50LWtleSE=",
		"access_client_secret": "access-service-client-plant", "acme_account_key": "acme-account-plant",
		"certificate_private_key": "certificate-private-plant", "dev_env_api_token": "dev-api-token-plant",
		"email": "alice@example.org", "unknown_hex": "f1e2d3c4b5a697887766554433221100ffeeddccbbaa99887766554433221100",
		"unknown_short": "tiny-credential", "unknown_base64": "cGxhbnRlZC11bmtub3duLWJhc2U2NC1wcml2YXRlLWtleQ==",
	}
	var raw strings.Builder
	for _, value := range plants {
		raw.WriteString(value + "\n")
	}
	// Unknown field names and known diagnostic fields with invalid types/values
	// must not turn into a second channel for arbitrary credential text.
	object := map[string]any{"enabled": true, "newSecretField": plants, "engine": plants["unknown_short"], "backend": plants["oauth_access"], "ssh": plants["acme_account_key"], plants["email"]: "private"}
	jsonData, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	escaped := `{"email":"alice\u0040example.org","nested":"{\"email\":\"alice\\u0040example.org\",\"key\":\"https:\\/\\/private\"}"}`
	if !json.Valid([]byte(escaped)) {
		t.Fatal("escaped log fixture must be valid JSON")
	}
	nested, _ := json.Marshal(map[string]string{"time": "2026-10-26T12:00:00Z", "level": "ERROR", "message": escaped})
	files := map[string][]byte{
		"status.json": jsonData, "service-config.json": jsonData, "secure-config.json": jsonData,
		"journal.txt":  []byte("2026-10-26T12:00:00+0000 host meshscale[1]: " + escaped + "\n" + string(nested) + "\n" + raw.String()),
		"versions.txt": []byte(raw.String()), "mesh-routes.json": jsonData,
		"README.txt":          []byte(raw.String()),
		"single-json-log.txt": nested,
		"malformed.json":      []byte(`{"newSecretField":"` + plants["unknown_short"] + `",oops`),
	}
	var archive bytes.Buffer
	if err := writeBugreport(&archive, files, nil); err != nil {
		t.Fatal(err)
	}
	for name, data := range readBugreportArchive(t, archive.Bytes()) {
		for class, value := range plants {
			encoded, _ := json.Marshal(value)
			for _, forbidden := range []string{value, string(encoded[1 : len(encoded)-1]), strings.ReplaceAll(value, "@", `\u0040`), strings.ReplaceAll(value, "@", `\\u0040`)} {
				if bytes.Contains(data, []byte(forbidden)) {
					t.Errorf("%s leaked %s (%q)", name, class, forbidden)
				}
			}
		}
		for _, forbidden := range []string{"newSecretField", "https:", "nested"} {
			if bytes.Contains(data, []byte(forbidden)) {
				t.Errorf("%s exported unknown content %q", name, forbidden)
			}
		}
	}
}

func TestBugreportAllowedStructureAndVersions(t *testing.T) {
	files := map[string][]byte{
		"versions.txt":     []byte("meshscale v1.2.3\nGo go1.27.3\nOS linux/arm64\nwarp-cli 2026.8.2115.0\nprivate-build-annotation\n"),
		"doctor.json":      []byte(`{"version":"v1.2.3","checks":[{"name":"connection","status":"ok","detail":"private-detail"}]}`),
		"journal.txt":      []byte(`{"time":"2026-10-26T12:00:00Z","level":"INFO","message":"private-message"}`),
		"mesh-routes.json": []byte(`{"warp_tables":{"65743":true,"private-table":true},"ip_route":"private-route"}`),
	}
	var archive bytes.Buffer
	if err := writeBugreport(&archive, files, []string{"quote\"\nplant"}); err != nil {
		t.Fatal(err)
	}
	exported := readBugreportArchive(t, archive.Bytes())
	for name, want := range map[string]string{"versions.txt": "warp-cli 2026.8.2115.0", "doctor.json": `"status": "ok"`, "journal.txt": `"level": "INFO"`, "mesh-routes.json": `"65743": true`} {
		if !bytes.Contains(exported[name], []byte(want)) {
			t.Errorf("%s lost allowed context: %s", name, exported[name])
		}
	}
	for name, data := range exported {
		if bytes.Contains(data, []byte("private")) {
			t.Errorf("%s leaked arbitrary content", name)
		}
		if strings.HasSuffix(name, ".json") && !json.Valid(data) {
			t.Errorf("%s invalid JSON", name)
		}
	}
	// Known values are scrubbed before JSON encoding, even when they collide
	// with an enum, contain quotes, or happen to equal JSON syntax.
	out := redactBugreport([]byte(`{"enabled":true,"backend":"warp"}`), []string{"true", "warp", "\""})
	if !json.Valid(out) || bytes.Contains(out, []byte("warp")) {
		t.Fatalf("invalid/leaking scrubbed JSON: %s", out)
	}
}
