package localstate

import (
	"os"
	"strings"
)

// ChildEnvironment keeps local API credentials out of unrelated programs.
// It lives below config/service so both daemon and CLI executors can use it.
func ChildEnvironment() []string {
	// A nil Cmd.Env means inherit everything; an empty result must stay non-nil.
	env := []string{}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if credentialKey(name) {
			continue
		}
		env = append(env, entry)
	}
	return env
}

// CredentialEnvironmentKeys are never passed to child processes.
var CredentialEnvironmentKeys = []string{"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CF_API_TOKEN", "CF_API_KEY"}

func credentialKey(name string) bool {
	for _, k := range CredentialEnvironmentKeys {
		if strings.EqualFold(name, k) {
			return true
		}
	}
	return false
}
