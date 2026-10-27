package main

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
)

const bugreportRedacted = "[redacted]"

var (
	bugreportSecretField = regexp.MustCompile(`(?i)token|secret|password|passwd|authorization|credential|private[ _-]?key|preshared[ _-]?key|api[ _-]?key`)
	bugreportAssignment  = regexp.MustCompile(`(?im)(["']?[\w.-]*(?:token|secret|password|passwd|authorization|credential|private[ _-]?key|preshared[ _-]?key|api[ _-]?key)[\w.-]*["']?\s*(?:[:=]\s*|\s+))(?:"(?:\\.|[^"\\])*"|'[^']*'|[^\r\n,;}]+)`)
	bugreportPEM         = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	bugreportEmail       = regexp.MustCompile(`(?i)(?:"(?:\\.|[^"\\\r\n])+"|[\pL\pN.!#$%&'*+/=?^_` + "`" + `{|}~-]+)@(?:[\pL\pN](?:[\pL\pN.-]*[\pL\pN])?|\[[^\]\r\n]+\])`)
	bugreportBearer      = regexp.MustCompile(`(?i)\b(?:Bearer|Basic)\s+[^\s"'<>]+`)
	// Also suppress unlabelled WireGuard keys, JWTs, account IDs and opaque tokens.
	// Over-redacting identifiers is intentional in a bundle intended for sharing.
	bugreportOpaque = regexp.MustCompile(`[A-Za-z0-9_+/=-]{32,}(?:\.[A-Za-z0-9_+/=-]+)*`)
)

// redactBugreport is the archive export boundary. Unknown keys are dropped,
// including their names. Allowed fields also have constrained value types: a
// familiar field name must never authorize arbitrary string content.
func redactBugreport(data []byte, secrets []string) []byte {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return []byte(scrubDoctorDetail(bugreportLogStructure(string(data)), secrets))
	}
	// Scrub string values before encoding so even unusual known credentials
	// containing quotes/newlines cannot break the output JSON.
	clean := bugreportScrubAllowed(bugreportDiagnosticJSON(value, ""), secrets)
	out, _ := json.MarshalIndent(clean, "", "  ")
	return append(out, '\n')
}

func bugreportScrubAllowed(value any, secrets []string) any {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			v[key] = bugreportScrubAllowed(child, secrets)
		}
	case []any:
		for i, child := range v {
			v[i] = bugreportScrubAllowed(child, secrets)
		}
	case string:
		return scrubDoctorDetail(v, secrets)
	}
	return value
}

var bugreportVersion = regexp.MustCompile(`^(?:v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}|dev|unknown)$`)
var bugreportVersionLine = regexp.MustCompile(`^(?:meshscale (?:v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}|dev|unknown)|Go go[0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?|OS (?:linux|darwin)/(?:amd64|arm64)|warp-cli [0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}|official client version unavailable)$`)
var bugreportTable = regexp.MustCompile(`^(?:[0-9]{1,10}|main|default|local)$`)

func bugreportDiagnosticJSON(value any, path string) any {
	object, ok := value.(map[string]any)
	if !ok {
		return bugreportRedacted
	}
	out := map[string]any{}
	for key, child := range object {
		switch path + key {
		case "version":
			out[key] = bugreportRedacted
			if v, ok := child.(string); ok && bugreportVersion.MatchString(v) {
				out[key] = v
			}
		case "time":
			out[key] = bugreportRedacted
			if stamp, ok := child.(string); ok {
				if parsed, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
					out[key] = parsed.Format(time.RFC3339Nano)
				}
			}
		case "level":
			out[key] = bugreportEnum(child, "DEBUG", "INFO", "WARN", "ERROR", "debug", "info", "warn", "error")
		case "warp_tables":
			// Dynamic keys are safe only after validating the routing-table grammar.
			tables := map[string]any{}
			if values, ok := child.(map[string]any); ok {
				for table, enabled := range values {
					if b, ok := enabled.(bool); ok && bugreportTable.MatchString(table) {
						tables[table] = b
					}
				}
			}
			out[key] = tables
		case "ip_route":
			out[key] = bugreportRedacted
		case "checks":
			if checks, ok := child.([]any); ok {
				clean := make([]any, 0, len(checks))
				for _, check := range checks {
					clean = append(clean, bugreportDiagnosticJSON(check, "checks."))
				}
				out[key] = clean
			}
		case "ssh", "enabled", "userspace", "advertise_exit_node", "exit_node_allow_lan_access", "paused":
			if b, ok := child.(bool); ok {
				out[key] = b
			} else {
				out[key] = bugreportRedacted
			}
		case "engine":
			out[key] = bugreportEnum(child, "", "auto", "kernel", "userspace", "wireguard-go", "boringtun")
		case "backend":
			out[key] = bugreportEnum(child, "warp", "native")
		case "checks.status":
			out[key] = bugreportEnum(child, "ok", "warn", "fail")
		case "checks.name":
			out[key] = bugreportEnum(child, "official-client", "connection", "registration", "team-profile", "daemon", "secure", "ssh-mode", "dns", "mesh-route", "tailscale-overlap", "warp-mtu", "cloudflare-api", "peer-reachability")
		case "checks.detail", "checks.measurement", "checks.hint", "unavailable":
			out[key] = bugreportRedacted
		}
	}
	return out
}
func bugreportEnum(value any, allowed ...string) string {
	if s, ok := value.(string); ok {
		for _, candidate := range allowed {
			if s == candidate {
				return s
			}
		}
	}
	return bugreportRedacted
}

var bugreportTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})`)

// short-iso journals and JSON log records retain only parsed timestamps and
// levels. Hosts, process identifiers, unknown fields and ALL message content
// are withheld, including nested/escaped JSON and unlabelled key material.
func bugreportLogStructure(input string) string {
	var out strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(input, "\n"), "\n") {
		if bugreportVersionLine.MatchString(line) {
			out.WriteString(line + "\n")
			continue
		}
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) == nil {
			if stamp, ok := record["time"].(string); ok {
				if parsed, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
					out.WriteString(parsed.Format(time.RFC3339Nano) + " ")
				}
			}
			if level := bugreportEnum(record["level"], "DEBUG", "INFO", "WARN", "ERROR", "debug", "info", "warn", "error"); level != bugreportRedacted {
				out.WriteString(level + " ")
			}
		} else if stamp := bugreportTimestamp.FindString(line); stamp != "" {
			normalized := stamp
			if len(stamp) >= 5 && stamp[len(stamp)-3] != ':' && stamp[len(stamp)-1] != 'Z' {
				normalized = stamp[:len(stamp)-2] + ":" + stamp[len(stamp)-2:]
			}
			if parsed, err := time.Parse(time.RFC3339Nano, normalized); err == nil {
				out.WriteString(parsed.Format(time.RFC3339Nano) + " ")
			}
		}
		out.WriteString(bugreportRedacted + "\n")
	}
	return out.String()
}

// Interactive doctor details are separate from the stricter archive allowlist.
// This scrubber is defense in depth; archives never export free-form details.
func scrubDoctorDetail(s string, secrets []string) string {
	values := append([]string(nil), secrets...)
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, value := range values {
		if value != "" {
			s = strings.ReplaceAll(s, value, bugreportRedacted)
		}
	}
	s = bugreportPEM.ReplaceAllString(s, bugreportRedacted)
	s = bugreportAssignment.ReplaceAllString(s, "${1}"+bugreportRedacted)
	s = bugreportBearer.ReplaceAllString(s, bugreportRedacted)
	s = bugreportEmail.ReplaceAllString(s, bugreportRedacted)
	return bugreportOpaque.ReplaceAllString(s, bugreportRedacted)
}

func bugreportJSONSecrets(data []byte) []string {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return nil
	}
	var secrets []string
	var walk func(any, bool)
	walk = func(v any, sensitive bool) {
		switch v := v.(type) {
		case map[string]any:
			for key, child := range v {
				walk(child, sensitive || bugreportSecretField.MatchString(key))
			}
		case []any:
			for _, child := range v {
				walk(child, sensitive)
			}
		case string:
			if sensitive && v != "" {
				secrets = append(secrets, v)
			}
		}
	}
	walk(value, false)
	return secrets
}
