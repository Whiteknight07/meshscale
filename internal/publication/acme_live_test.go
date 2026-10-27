package publication

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
)

// TestACMEStaging is explicit opt-in and cannot use the production CA. It
// creates a unique hostname, removes all recorded DNS, and keeps no live state.
func TestACMEStaging(t *testing.T) {
	if os.Getenv("MESHSCALE_ACME_LIVE") != "1" {
		t.Skip("set MESHSCALE_ACME_LIVE=1 and MESHSCALE_ACME_ZONE to exercise Let's Encrypt staging")
	}
	env, err := config.LoadEnv()
	if err != nil {
		t.Fatal(err)
	}
	if env["CLOUDFLARE_ACCOUNT_ID"] == "" || env["CLOUDFLARE_API_TOKEN"] == "" {
		t.Fatal("live staging requires Cloudflare credentials")
	}
	zone := os.Getenv("MESHSCALE_ACME_ZONE")
	if zone == "" {
		t.Fatal("MESHSCALE_ACME_ZONE is required")
	}
	dir := privateDir(t)
	client := cfapi.New(cfapi.StaticToken(env["CLOUDFLARE_API_TOKEN"]), "staging-test")
	manager, err := New(Store{Dir: dir}, env["CLOUDFLARE_ACCOUNT_ID"], client, client, &fakeProcess{}, &ACME{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, owned := range append([]OwnedRecord(nil), manager.state.Records...) {
			if err := manager.deleteRecord(ctx, owned.Record.ID); err != nil {
				t.Errorf("cleanup DNS ID %s: %v", owned.Record.ID, err)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// Issue twice: the second issuance reuses the registered account key, the
	// path every renewal takes.
	for i := range 2 {
		name := "staging-" + strconv.FormatInt(time.Now().Unix(), 10) + "-" + strconv.Itoa(i)
		cert, err := manager.Cert(ctx, CertRequest{Name: name, IP: "100.96.0.7", Zone: zone, Staging: true})
		if err != nil {
			t.Fatalf("issuance %d: %v", i+1, err)
		}
		if cert.Directory != StagingDirectory {
			t.Fatal("live test attempted non-staging issuance")
		}
		if err := validSavedCertificate(cert); err != nil {
			t.Fatal(err)
		}
		t.Logf("staging DNS-01 issued %s; expires %s; all created DNS removed by test cleanup", cert.Name, cert.NotAfter)
	}
}
