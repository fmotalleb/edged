package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration structure.
type Config struct {
	DefaultUpstreamSOCKS5Proxy string           `yaml:"default_upstream_socks5_proxy"`
	Listeners                  []ListenerConfig `yaml:"listeners"`
	ACME                       ACMEConfig       `yaml:"acme"`
}

// ListenerConfig defines a network listener (e.g., HTTP or HTTPS).
type ListenerConfig struct {
	Name                string        `yaml:"name"`
	Address             string        `yaml:"address"`
	Protocol            string        `yaml:"protocol"`              // "http" or "https"
	RedirectToHTTPS     bool          `yaml:"redirect_to_https"`     // If true on HTTP, redirects to HTTPS
	UpstreamSOCKS5Proxy string        `yaml:"upstream_socks5_proxy"` // Default SOCKS5 proxy for routes under this listener
	TLS                 TLSConfig     `yaml:"tls"`
	Routes              []RouteConfig `yaml:"routes"`
}

// TLSConfig defines TLS settings for a listener.
type TLSConfig struct {
	Enabled  bool     `yaml:"enabled"`
	UseACME  bool     `yaml:"use_acme"`
	Domains  []string `yaml:"domains"`
	CertFile string   `yaml:"cert_file"` // For manual certificates if UseACME is false
	KeyFile  string   `yaml:"key_file"`
}

// RouteConfig defines routing rules from virtual host/path to upstream backends.
type RouteConfig struct {
	Host                string            `yaml:"host"`                  // Exact domain or wildcard (*.example.com)
	PathPrefix          string            `yaml:"path_prefix"`           // e.g., "/" or "/api"
	Upstream            string            `yaml:"upstream"`              // e.g., "http://127.0.0.1:8080"
	StripPrefix         bool              `yaml:"strip_prefix"`          // If true, strips PathPrefix before forwarding
	Timeout             time.Duration     `yaml:"timeout"`               // Request timeout
	CustomHeaders       map[string]string `yaml:"custom_headers"`        // Headers to inject before sending to upstream
	UpstreamSOCKS5Proxy string            `yaml:"upstream_socks5_proxy"` // Optional SOCKS5 proxy to reach upstream
}

// ACMEConfig defines global settings for Let's Encrypt certificate acquisition.
type ACMEConfig struct {
	Email              string            `yaml:"email"`
	DirectoryURL       string            `yaml:"directory_url"`
	SOCKS5Proxy        string            `yaml:"socks5_proxy"`
	StoragePath        string            `yaml:"storage_path"`
	RenewBeforeDays    int               `yaml:"renew_before_days"`
	CheckIntervalHours int               `yaml:"check_interval_hours"`
	DNSProvider        DNSProviderConfig `yaml:"dns_provider"`
}

// DNSProviderConfig defines settings for DNS-01 challenge providers.
type DNSProviderConfig struct {
	Name       string           `yaml:"name"`       // Supported: "arvancloud", "cloudflare"
	UseSOCKS5  bool             `yaml:"use_socks5"` // If true, DNS API calls use ACME SOCKS5 proxy
	ArvanCloud ArvanCloudConfig `yaml:"arvancloud"`
	Cloudflare CloudflareConfig `yaml:"cloudflare"`
}

// ArvanCloudConfig contains credentials and timings for ArvanCloud DNS.
type ArvanCloudConfig struct {
	APIKey             string `yaml:"api_key"`
	PropagationTimeout int    `yaml:"propagation_timeout"` // in seconds
	PollingInterval    int    `yaml:"polling_interval"`    // in seconds
	TTL                int    `yaml:"ttl"`                 // in seconds
}

// CloudflareConfig contains credentials and timings for Cloudflare DNS.
type CloudflareConfig struct {
	APIToken           string `yaml:"api_token"`           // Scoped DNS API Token (Recommended)
	ZoneToken          string `yaml:"zone_token"`          // Optional Scoped Zone API Token
	AuthEmail          string `yaml:"auth_email"`          // Legacy Email
	AuthKey            string `yaml:"auth_key"`            // Legacy API Key
	PropagationTimeout int    `yaml:"propagation_timeout"` // in seconds
	PollingInterval    int    `yaml:"polling_interval"`    // in seconds
	TTL                int    `yaml:"ttl"`                 // in seconds
}

// Load reads and parses a YAML configuration file from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// setDefaults applies sensible defaults to optional configuration fields and inherits hierarchical proxy settings.
func (c *Config) setDefaults() {
	if c.ACME.DirectoryURL == "" {
		c.ACME.DirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if c.ACME.StoragePath == "" {
		c.ACME.StoragePath = "./acme_storage"
	}
	if c.ACME.RenewBeforeDays == 0 {
		c.ACME.RenewBeforeDays = 30
	}
	if c.ACME.CheckIntervalHours == 0 {
		c.ACME.CheckIntervalHours = 24
	}
	if c.ACME.DNSProvider.Name == "" {
		c.ACME.DNSProvider.Name = "cloudflare"
	}

	// ArvanCloud defaults
	if c.ACME.DNSProvider.ArvanCloud.PropagationTimeout == 0 {
		c.ACME.DNSProvider.ArvanCloud.PropagationTimeout = 120
	}
	if c.ACME.DNSProvider.ArvanCloud.PollingInterval == 0 {
		c.ACME.DNSProvider.ArvanCloud.PollingInterval = 2
	}
	if c.ACME.DNSProvider.ArvanCloud.TTL == 0 {
		c.ACME.DNSProvider.ArvanCloud.TTL = 600
	}

	// Cloudflare defaults
	if c.ACME.DNSProvider.Cloudflare.PropagationTimeout == 0 {
		c.ACME.DNSProvider.Cloudflare.PropagationTimeout = 120
	}
	if c.ACME.DNSProvider.Cloudflare.PollingInterval == 0 {
		c.ACME.DNSProvider.Cloudflare.PollingInterval = 2
	}
	if c.ACME.DNSProvider.Cloudflare.TTL == 0 {
		c.ACME.DNSProvider.Cloudflare.TTL = 300
	}

	// Override credentials from environment variables if present
	if envKey := os.Getenv("ARVANCLOUD_API_KEY"); envKey != "" {
		c.ACME.DNSProvider.ArvanCloud.APIKey = envKey
	}
	if envToken := os.Getenv("CLOUDFLARE_DNS_API_TOKEN"); envToken != "" {
		c.ACME.DNSProvider.Cloudflare.APIToken = envToken
	}
	if envZoneToken := os.Getenv("CLOUDFLARE_ZONE_API_TOKEN"); envZoneToken != "" {
		c.ACME.DNSProvider.Cloudflare.ZoneToken = envZoneToken
	}
	if envEmail := os.Getenv("CLOUDFLARE_EMAIL"); envEmail != "" {
		c.ACME.DNSProvider.Cloudflare.AuthEmail = envEmail
	}
	if envKey := os.Getenv("CLOUDFLARE_API_KEY"); envKey != "" {
		c.ACME.DNSProvider.Cloudflare.AuthKey = envKey
	}

	// Apply hierarchical SOCKS5 proxy inheritance (Global -> Listener -> Route)
	for i := range c.Listeners {
		l := &c.Listeners[i]
		if l.Protocol == "" {
			if strings.HasSuffix(l.Address, ":443") {
				l.Protocol = "https"
			} else {
				l.Protocol = "http"
			}
		}
		if l.UpstreamSOCKS5Proxy == "" && c.DefaultUpstreamSOCKS5Proxy != "" {
			l.UpstreamSOCKS5Proxy = c.DefaultUpstreamSOCKS5Proxy
		}

		for j := range l.Routes {
			r := &l.Routes[j]
			if r.PathPrefix == "" {
				r.PathPrefix = "/"
			}
			if r.Timeout == 0 {
				r.Timeout = 30 * time.Second
			}
			if r.UpstreamSOCKS5Proxy == "" && l.UpstreamSOCKS5Proxy != "" {
				r.UpstreamSOCKS5Proxy = l.UpstreamSOCKS5Proxy
			}
		}
	}
}

// validate checks the configuration for required fields and consistency.
func (c *Config) validate() error {
	if len(c.Listeners) == 0 {
		return fmt.Errorf("at least one listener must be configured under 'listeners:'")
	}

	for i, l := range c.Listeners {
		if l.Address == "" {
			return fmt.Errorf("listener[%d] ('%s') is missing required 'address' field", i, l.Name)
		}
		if l.Protocol != "http" && l.Protocol != "https" {
			return fmt.Errorf("listener[%d] ('%s') protocol must be 'http' or 'https', got '%s'", i, l.Name, l.Protocol)
		}
		if l.Protocol == "https" && l.TLS.UseACME {
			if c.ACME.Email == "" {
				return fmt.Errorf("acme.email is required when TLS with use_acme is enabled")
			}
			if len(l.TLS.Domains) == 0 {
				return fmt.Errorf("listener[%d] ('%s') has use_acme=true but no domains specified in tls.domains", i, l.Name)
			}
		}
		for j, r := range l.Routes {
			if r.Upstream == "" && !l.RedirectToHTTPS {
				return fmt.Errorf("listener[%d] route[%d] (host '%s') is missing required 'upstream'", i, j, r.Host)
			}
		}
	}

	// Check if any listener actually uses ACME with wildcard domains
	needsWildcard := false
	for _, l := range c.Listeners {
		if l.TLS.UseACME {
			for _, d := range l.TLS.Domains {
				if strings.HasPrefix(d, "*.") {
					needsWildcard = true
					break
				}
			}
		}
	}

	if needsWildcard {
		providerName := strings.ToLower(strings.TrimSpace(c.ACME.DNSProvider.Name))
		switch providerName {
		case "arvancloud":
			if c.ACME.DNSProvider.ArvanCloud.APIKey == "" {
				return fmt.Errorf("arvancloud api_key is required for wildcard certificate generation (set in yaml or ARVANCLOUD_API_KEY env var)")
			}
		case "cloudflare":
			cf := c.ACME.DNSProvider.Cloudflare
			if cf.APIToken == "" && (cf.AuthEmail == "" || cf.AuthKey == "") {
				return fmt.Errorf("cloudflare credentials required: provide api_token (or CLOUDFLARE_DNS_API_TOKEN env var), OR auth_email and auth_key")
			}
		default:
			return fmt.Errorf("unsupported dns_provider.name: '%s'. Supported providers: arvancloud, cloudflare", c.ACME.DNSProvider.Name)
		}
	}

	return nil
}

// GetAllACMEDomains collects all unique domains across all HTTPS listeners that use ACME.
func (c *Config) GetAllACMEDomains() []string {
	domainSet := make(map[string]struct{})
	for _, l := range c.Listeners {
		if l.Protocol == "https" && l.TLS.Enabled && l.TLS.UseACME {
			for _, d := range l.TLS.Domains {
				domainSet[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
			}
		}
	}
	var domains []string
	for d := range domainSet {
		domains = append(domains, d)
	}
	return domains
}
