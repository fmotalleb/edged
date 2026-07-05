package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	toolconfig "github.com/fmotalleb/go-tools/config"
	"github.com/fmotalleb/go-tools/decoder"
	"github.com/fmotalleb/go-tools/defaulter"
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
	Name    string `yaml:"name" mapstructure:"name"`
	Address string `yaml:"address" mapstructure:"address"`
	// Protocol is intentionally left without a `default` tag: its default
	// depends on the listener's Address (":443" -> "https"), which the
	// defaulter package can't express as a static tag. It's resolved
	// manually in setDefaults after ApplyDefaults runs.
	Protocol        string `yaml:"protocol" mapstructure:"protocol"`
	RedirectToHTTPS bool   `yaml:"redirect_to_https" mapstructure:"redirect_to_https"`
	// UpstreamSOCKS5Proxy is inherited Global -> Listener, which is also
	// value-dependent on a sibling config tree rather than a static default,
	// so it's resolved manually rather than via a tag.
	UpstreamSOCKS5Proxy string        `yaml:"upstream_socks5_proxy" mapstructure:"upstream_socks5_proxy"`
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
	Host          string            `yaml:"host" mapstructure:"host"` // Exact domain or wildcard (*.example.com)
	PathPrefix    string            `yaml:"path_prefix" mapstructure:"path_prefix" default:"/"`
	Upstream      string            `yaml:"upstream" mapstructure:"upstream"`         // e.g., "http://127.0.0.1:8080"
	StripPrefix   bool              `yaml:"strip_prefix" mapstructure:"strip_prefix"` // If true, strips PathPrefix before forwarding
	Timeout       time.Duration     `yaml:"timeout" mapstructure:"timeout" default:"30s"`
	CustomHeaders map[string]string `yaml:"custom_headers" mapstructure:"custom_headers"` // Headers to inject before sending to upstream
	// UpstreamSOCKS5Proxy is inherited Listener -> Route; resolved manually
	// in setDefaults for the same reason as ListenerConfig.UpstreamSOCKS5Proxy.
	UpstreamSOCKS5Proxy string `yaml:"upstream_socks5_proxy" mapstructure:"upstream_socks5_proxy"`

	DialerTimeout         time.Duration `yaml:"dialer_timeout" mapstructure:"dialer_timeout" default:"30s"`
	DialerKeepalive       time.Duration `yaml:"dialer_keepalive" mapstructure:"dialer_keepalive" default:"30s"`
	ForceAttemptHTTP2     bool          `yaml:"force_attempt_http2" mapstructure:"force_attempt_http2" default:"true"`
	MaxIdleConns          int           `yaml:"max_idle_conns" mapstructure:"max_idle_conns" default:"100"`
	IdleConnTimeout       time.Duration `yaml:"idle_conn_timeout" mapstructure:"idle_conn_timeout" default:"90s"`
	TLSHandshakeTimeout   time.Duration `yaml:"tls_handshake_timeout" mapstructure:"tls_handshake_timeout" default:"10s"`
	ExpectContinueTimeout time.Duration `yaml:"expect_continue_timeout" mapstructure:"expect_continue_timeout" default:"1s"`
}

// ACMEConfig defines global settings for Let's Encrypt certificate acquisition.
type ACMEConfig struct {
	Email              string            `yaml:"email" mapstructure:"email"` // required; validated separately, no default
	DirectoryURL       string            `yaml:"directory_url" mapstructure:"directory_url" default:"https://acme-v02.api.letsencrypt.org/directory"`
	SOCKS5Proxy        string            `yaml:"socks5_proxy" mapstructure:"socks5_proxy"`
	StoragePath        string            `yaml:"storage_path" mapstructure:"storage_path" default:"./acme_storage"`
	RenewBeforeDays    int               `yaml:"renew_before_days" mapstructure:"renew_before_days" default:"30"`
	CheckIntervalHours int               `yaml:"check_interval_hours" mapstructure:"check_interval_hours" default:"24"`
	ClientTimeout      time.Duration     `yaml:"client_timeout" mapstructure:"client_timeout" default:"40s"`
	DNSProvider        DNSProviderConfig `yaml:"dns_provider" mapstructure:"dns_provider"`
}

// DNSProviderConfig defines settings for DNS-01 challenge providers.
type DNSProviderConfig struct {
	Name                 string           `yaml:"name" mapstructure:"name" default:"cloudflare"` // Supported: "arvancloud", "cloudflare"
	UseSOCKS5            bool             `yaml:"use_socks5" mapstructure:"use_socks5"`          // If true, DNS API calls use ACME SOCKS5 proxy
	RecursiveNameservers []string         `yaml:"recursive_nameservers" mapstructure:"recursive_nameservers"`
	ArvanCloud           ArvanCloudConfig `yaml:"arvancloud" mapstructure:"arvancloud"`
	Cloudflare           CloudflareConfig `yaml:"cloudflare" mapstructure:"cloudflare"`
}

// ArvanCloudConfig contains credentials and timings for ArvanCloud DNS.
type ArvanCloudConfig struct {
	// APIKey falls back to ARVANCLOUD_API_KEY only if not set in YAML.
	APIKey             string `yaml:"api_key" mapstructure:"api_key" env:"ARVANCLOUD_API_KEY"`
	PropagationTimeout int    `yaml:"propagation_timeout" mapstructure:"propagation_timeout" default:"120"` // in seconds
	PollingInterval    int    `yaml:"polling_interval" mapstructure:"polling_interval" default:"2"`         // in seconds
	TTL                int    `yaml:"ttl" mapstructure:"ttl" default:"600"`                                 // in seconds
}

// CloudflareConfig contains credentials and timings for Cloudflare DNS.
type CloudflareConfig struct {
	// Credential fields fall back to their env vars only if not set in YAML.
	APIToken           string `yaml:"api_token" mapstructure:"api_token" env:"CLOUDFLARE_DNS_API_TOKEN"`    // Scoped DNS API Token (Recommended)
	ZoneToken          string `yaml:"zone_token" mapstructure:"zone_token" env:"CLOUDFLARE_ZONE_API_TOKEN"` // Optional Scoped Zone API Token
	AuthEmail          string `yaml:"auth_email" mapstructure:"auth_email" env:"CLOUDFLARE_EMAIL"`          // Legacy Email
	AuthKey            string `yaml:"auth_key" mapstructure:"auth_key" env:"CLOUDFLARE_API_KEY"`            // Legacy API Key
	PropagationTimeout int    `yaml:"propagation_timeout" mapstructure:"propagation_timeout" default:"120"` // in seconds
	PollingInterval    int    `yaml:"polling_interval" mapstructure:"polling_interval" default:"2"`         // in seconds
	TTL                int    `yaml:"ttl" mapstructure:"ttl" default:"300"`                                 // in seconds
}

// Load reads and parses a configuration file from path using github.com/fmotalleb/go-tools/config (uses mapstructure).
func Load(ctx context.Context, path string) (*Config, error) {
	logger := log.FromContext(ctx)
	logger.Info("Loading configuration file", zap.String("path", path))
	var err error
	var cfgMap map[string]any
	var cfg Config
	// Use config parser from github.com/fmotalleb/go-tools/config which utilizes mapstructure
	if cfgMap, err = toolconfig.ReadAndMergeConfig(ctx, path); err != nil {
		logger.Debug("toolconfig.Load returned error or fallback needed, attempting direct YAML unmarshal with mapstructure struct tags", zap.Error(err))
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", path, readErr)
		}
		if err = yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}
	}
	if err = decoder.Decode(&cfg, cfgMap); err != nil {
		return nil, fmt.Errorf("failed to parse config object: %w", err)
	}
	if err = cfg.setDefaults(ctx); err != nil {
		return nil, fmt.Errorf("failed to apply configuration defaults: %w", err)
	}
	if err = cfg.validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	logger.Info("Configuration loaded and validated successfully", zap.Int("listener_count", len(cfg.Listeners)))
	return &cfg, nil
}

// setDefaults applies `default`/`env` tag values across the whole config tree
// via github.com/fmotalleb/go-tools/defaulter, then resolves the handful of
// values that depend on sibling/parent fields rather than a static default
// (listener protocol inference, and hierarchical SOCKS5 proxy inheritance).
func (c *Config) setDefaults(ctx context.Context) error {
	// Fills every zero-valued field tagged with `default:"..."`, falling back
	// to the corresponding `env:"..."` var first if present. Only touches
	// fields left empty by the YAML/mapstructure decode above. Returns an
	// aggregated error if any default value failed to decode into its field,
	// rather than silently leaving that field at its zero value.
	if err := defaulter.ApplyDefaults(c, nil); err != nil {
		return err
	}

	// Apply hierarchical SOCKS5 proxy inheritance (Global -> Listener -> Route)
	// and protocol inference - both depend on sibling/parent values, so they
	// can't be expressed as static `default` tags.
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
			if r.UpstreamSOCKS5Proxy == "" && l.UpstreamSOCKS5Proxy != "" {
				r.UpstreamSOCKS5Proxy = l.UpstreamSOCKS5Proxy
			}
		}
	}

	return nil
}

// validate checks the configuration for required fields and consistency.
func (c *Config) validate(ctx context.Context) error {
	logger := log.FromContext(ctx)

	if len(c.Listeners) == 0 {
		return errors.New("at least one listener must be configured under 'listeners:'")
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
				return errors.New("acme.email is required when TLS with use_acme is enabled")
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
				return errors.New("arvancloud api_key is required for wildcard certificate generation (set in yaml or ARVANCLOUD_API_KEY env var)")
			}
		case "cloudflare":
			cf := c.ACME.DNSProvider.Cloudflare
			if cf.APIToken == "" && (cf.AuthEmail == "" || cf.AuthKey == "") {
				return errors.New("cloudflare credentials required: provide api_token (or CLOUDFLARE_DNS_API_TOKEN env var), OR auth_email and auth_key")
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
