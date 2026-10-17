package config_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/fmotalleb/edged/config"
)

// acmeListenerYAML is a minimal ACME-enabled listener; DNS-01 providers are
// mandatory because of it.
const acmeListenerYAML = `
listeners:
  - name: "https"
    address: "0.0.0.0:443"
    protocol: "https"
    tls:
      enabled: true
      use_acme: true
      domains:
        - "example.com"
        - "*.example.com"
        - "cdn.example.org"
acme:
  email: "admin@example.com"
`

// loadConfig writes YAML to a temp file and loads it through config.Load.
func loadConfig(t *testing.T, yaml string) (*config.Config, error) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	return config.Load(context.Background(), path)
}

func TestLoadWithPerDomainDNSProviders(t *testing.T) {
	cfg, err := loadConfig(t, acmeListenerYAML+`
  dns_providers:
    - name: "cloudflare"
      cloudflare:
        api_token: "cf-token"
    - name: "arvancloud"
      match:
        - "example.org"
        - "*.example.org"
      arvancloud:
        api_key: "apikey 00000000-0000-0000-0000-000000000000"
`)

	assert.NoError(t, err)
	if err != nil {
		return
	}

	assert.Equal(t, "cloudflare", cfg.ACME.DNSProviders[0].Name)
	assert.Equal(t, 0, len(cfg.ACME.DNSProviders[0].Match), "the default entry may omit match")
	assert.Equal(t, []string{"example.org", "*.example.org"}, cfg.ACME.DNSProviders[1].Match)

	// Per-entry defaults are still applied to list elements.
	assert.Equal(t, 120, cfg.ACME.DNSProviders[0].Cloudflare.PropagationTimeout)
	assert.Equal(t, 300, cfg.ACME.DNSProviders[0].Cloudflare.TTL)
	assert.Equal(t, 600, cfg.ACME.DNSProviders[1].ArvanCloud.TTL)
}

func TestLoadACMEWithoutDNSProvidersFails(t *testing.T) {
	_, err := loadConfig(t, acmeListenerYAML)

	assert.Error(t, err)
	if err == nil {
		return
	}
	assert.Contains(t, err.Error(), "ACME.DNSProviders is required")
	assert.Contains(t, err.Error(), "acme.dns_providers")
}

func TestLoadWithoutACMEMeansNoDNSProviderNeeded(t *testing.T) {
	cfg, err := loadConfig(t, `
listeners:
  - name: "http"
    address: "0.0.0.0:8080"
    protocol: "http"
`)

	assert.NoError(t, err)
	if err != nil {
		return
	}
	assert.Equal(t, 0, len(cfg.ACME.DNSProviders))
}

func TestLoadRejectsLaterEntryWithoutMatch(t *testing.T) {
	_, err := loadConfig(t, acmeListenerYAML+`
  dns_providers:
    - name: "cloudflare"
      cloudflare:
        api_token: "cf-token"
    - name: "arvancloud"
      arvancloud:
        api_key: "apikey 00000000-0000-0000-0000-000000000000"
`)

	assert.Error(t, err)
	if err == nil {
		return
	}
	assert.Contains(t, err.Error(), "ACME.DNSProviders[1].Match is required")
}

func TestLoadRejectsInvalidMatchPattern(t *testing.T) {
	_, err := loadConfig(t, acmeListenerYAML+`
  dns_providers:
    - name: "cloudflare"
      match:
        - "bad["
      cloudflare:
        api_token: "cf-token"
`)

	assert.Error(t, err)
	if err == nil {
		return
	}
	assert.Contains(t, err.Error(), "ACME.DNSProviders[0].Match contains an invalid glob pattern")
}

func TestLoadRejectsMissingArvanCloudCredentials(t *testing.T) {
	_, err := loadConfig(t, acmeListenerYAML+`
  dns_providers:
    - name: "arvancloud"
      arvancloud:
        ttl: 600
`)

	assert.Error(t, err)
	if err == nil {
		return
	}
	assert.Contains(t, err.Error(), "ACME.DNSProviders[0].ArvanCloud.APIKey is required")
}

func TestLoadRejectsMissingCloudflareCredentials(t *testing.T) {
	_, err := loadConfig(t, acmeListenerYAML+`
  dns_providers:
    - name: "cloudflare"
      cloudflare:
        zone_token: "zone-token"
`)

	assert.Error(t, err)
	if err == nil {
		return
	}
	assert.Contains(t, err.Error(), "ACME.DNSProviders[0].Cloudflare is incomplete")
}

func TestLoadRejectsUnknownProviderName(t *testing.T) {
	_, err := loadConfig(t, acmeListenerYAML+`
  dns_providers:
    - name: "route53"
`)

	assert.Error(t, err)
	if err == nil {
		return
	}
	assert.Contains(t, err.Error(), "ACME.DNSProviders[0].Name must be one of [arvancloud cloudflare]")
}

func TestLoadRejectsMissingProviderName(t *testing.T) {
	_, err := loadConfig(t, acmeListenerYAML+`
  dns_providers:
    - match:
        - "example.com"
`)

	assert.Error(t, err)
	if err == nil {
		return
	}
	assert.Contains(t, err.Error(), "ACME.DNSProviders[0].Name is required")
}
