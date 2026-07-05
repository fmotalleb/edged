package config

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	toolconfig "github.com/fmotalleb/go-tools/config"
	"github.com/fmotalleb/go-tools/log"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration structure.
type Config struct {
	DefaultUpstreamSOCKS5Proxy string           `yaml:"default_upstream_socks5_proxy" mapstructure:"default_upstream_socks5_proxy"`
	Listeners                  []ListenerConfig `yaml:"listeners" mapstructure:"listeners"`
	ACME                       ACMEConfig       `yaml:"acme" mapstructure:"acme"`
}

// ListenerConfig defines a network listener (e.g., HTTP or HTTPS).
type ListenerConfig struct {
	Name                string        `yaml:"name" mapstructure:"name"`
	Address             string        `yaml:"address" mapstructure:"address"`
	Protocol            string        `yaml:"protocol" mapstructure:"protocol"`                           // "http" or "https"
	RedirectToHTTPS     bool          `yaml:"redirect_to_https" mapstructure:"redirect_to_https"`         // If true on HTTP, redirects to HTTPS
	UpstreamSOCKS5Proxy string        `yaml:"upstream_socks5_proxy" mapstructure:"upstream_socks5_proxy"` // Default SOCKS5 proxy for routes under this listener
	TLS                 TLSConfig     `yaml:"tls" mapstructure:"tls"`
	Routes              []RouteConfig `yaml:"routes" mapstructure:"routes"`
}

// TLSConfig defines TLS settings for a listener.
type TLSConfig struct {
	Enabled  bool     `yaml:"enabled" mapstructure:"enabled"`
	UseACME  bool     `yaml:"use_acme" mapstructure:"use_acme"`
	Domains  []string `yaml:"domains" mapstructure:"domains"`
	CertFile string   `yaml:"cert_file" mapstructure:"cert_file"` // For manual certificates if UseACME is false
	KeyFile  string   `yaml:"key_file" mapstructure:"key_file"`
}

// RouteConfig defines routing rules from virtual host/path to upstream backends.
type RouteConfig struct {
	Host                string            `yaml:"host" mapstructure:"host"`                                   // Exact domain or wildcard (*.example.com)
	PathPrefix          string            `yaml:"path_prefix" mapstructure:"path_prefix"`                     // e.g., "/" or "/api"
	Upstream            string            `yaml:"upstream" mapstructure:"upstream"`                           // e.g., "http://127.0.0.1:8080"
	StripPrefix         bool              `yaml:"strip_prefix" mapstructure:"strip_prefix"`                   // If true, strips PathPrefix before forwarding
	Timeout             time.Duration     `yaml:"timeout" mapstructure:"timeout"`                             // Request timeout
	CustomHeaders       map[string]string `yaml:"custom_headers" mapstructure:"custom_headers"`               // Headers to inject before sending to upstream
	UpstreamSOCKS5Proxy string            `yaml:"upstream_socks5_proxy" mapstructure:"upstream_socks5_proxy"` // Optional SOCKS5 proxy to reach upstream
}

// ACMEConfig defines global settings for Let's Encrypt certificate acquisition.
type ACMEConfig struct {
	Email              string            `yaml:"email" mapstructure:"email"`
	DirectoryURL       string            `yaml:"directory_url" mapstructure:"directory_url"`
	SOCKS5Proxy        string            `yaml:"socks5_proxy" mapstructure:"socks5_proxy"`
	StoragePath        string            `yaml:"storage_path" mapstructure:"storage_path"`
	RenewBeforeDays    int               `yaml:"renew_before_days" mapstructure:"renew_before_days"`
	CheckIntervalHours int               `yaml:"check_interval_hours" mapstructure:"check_interval_hours"`
	DNSProvider        DNSProviderConfig `yaml:"dns_provider" mapstructure:"dns_provider"`
}

// DNSProviderConfig defines settings for DNS-01 challenge providers.
type DNSProviderConfig struct {
	Name       string           `yaml:"name" mapstructure:"name"`             // Supported: "arvancloud", "cloudflare"
	UseSOCKS5  bool             `yaml:"use_socks5" mapstructure:"use_socks5"` // If true, DNS API calls use ACME SOCKS5 proxy
	ArvanCloud ArvanCloudConfig `yaml:"arvancloud" mapstructure:"arvancloud"`
	Cloudflare CloudflareConfig `yaml:"cloudflare" mapstructure:"cloudflare"`
}

// ArvanCloudConfig contains credentials and timings for ArvanCloud DNS.
type ArvanCloudConfig struct {
	APIKey             string `yaml:"api_key" mapstructure:"api_key"`
	PropagationTimeout int    `yaml:"propagation_timeout" mapstructure:"propagation_timeout"` // in seconds
	PollingInterval    int    `yaml:"polling_interval" mapstructure:"polling_interval"`       // in seconds
	TTL                int    `yaml:"ttl" mapstructure:"ttl"`                                 // in seconds
}

// CloudflareConfig contains credentials and timings for Cloudflare DNS.
type CloudflareConfig struct {
	APIToken           string `yaml:"api_token" mapstructure:"api_token"`                     // Scoped DNS API Token (Recommended)
	ZoneToken          string `yaml:"zone_token" mapstructure:"zone_token"`                   // Optional Scoped Zone API Token
	AuthEmail          string `yaml:"auth_email" mapstructure:"auth_email"`                   // Legacy Email
	AuthKey            string `yaml:"auth_key" mapstructure:"auth_key"`                       // Legacy API Key
	PropagationTimeout int    `yaml:"propagation_timeout" mapstructure:"propagation_timeout"` // in seconds
	PollingInterval    int    `yaml:"polling_interval" mapstructure:"polling_interval"`       // in seconds
	TTL                int    `yaml:"ttl" mapstructure:"ttl"`                                 // in seconds
}

// Load reads and parses a configuration file from path using github.com/fmotalleb/go-tools/config (uses mapstructure).
func Load(ctx context.Context, path string) (*Config, error) {
	logger := log.FromContext(ctx)
	logger.Info("Loading configuration file", zap.String("path", path))

	var cfg Config
	// Use config parser from github.com/fmotalleb/go-tools/config which utilizes mapstructure
	if cfg, err := toolconfig.ReadAndMergeConfig(ctx, path); err != nil {
		logger.Debug("toolconfig.Load returned error or fallback needed, attempting direct YAML unmarshal with mapstructure struct tags", zap.Error(err))
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", path, readErr)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	}

	cfg.setDefaults(ctx)
	if err := cfg.validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	logger.Info("Configuration loaded and validated successfully", zap.Int("listener_count", len(cfg.Listeners)))
	return &cfg, nil
}

// setDefaults applies sensible defaults to optional configuration fields and inherits hierarchical proxy settings.
func (c *Config) setDefaults(ctx context.Context) {
	logger := log.FromContext(ctx)

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
		logger.Debug("Overriding ArvanCloud API key from ARVANCLOUD_API_KEY environment variable")
		c.ACME.DNSProvider.ArvanCloud.APIKey = envKey
	}
	if envToken := os.Getenv("CLOUDFLARE_DNS_API_TOKEN"); envToken != "" {
		logger.Debug("Overriding Cloudflare DNS API token from CLOUDFLARE_DNS_API_TOKEN environment variable")
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
func (c *Config) validate(ctx context.Context) error {
	logger := log.FromContext(ctx)

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
		logger.Debug("Wildcard certificate requested, validating DNS provider credentials", zap.String("provider", providerName))
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
