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
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// validate is the shared validator instance with custom validations registered.
var validate = func() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	// Register custom cross-field / conditional validations on the top-level Config.
	v.RegisterStructValidation(configStructLevelValidation, Config{})
	v.RegisterStructValidation(listenerStructLevelValidation, ListenerConfig{})
	return v
}()

// Config represents the top-level configuration structure.
type Config struct {
	DefaultUpstreamSOCKS5Proxy string           `yaml:"default_upstream_socks5_proxy" mapstructure:"default_upstream_socks5_proxy"`
	Listeners                  []ListenerConfig `yaml:"listeners" mapstructure:"listeners" validate:"required,min=1,dive"`
	ACME                       ACMEConfig       `yaml:"acme" mapstructure:"acme" validate:"-"`
}

// ListenerConfig defines a network listener (e.g., HTTP or HTTPS).
type ListenerConfig struct {
	Name                string        `yaml:"name" mapstructure:"name"`
	Address             string        `yaml:"address" mapstructure:"address" validate:"required"`
	Protocol            string        `yaml:"protocol" mapstructure:"protocol" validate:"required,oneof=http https"`
	RedirectToHTTPS     bool          `yaml:"redirect_to_https" mapstructure:"redirect_to_https"`
	UpstreamSOCKS5Proxy string        `yaml:"upstream_socks5_proxy" mapstructure:"upstream_socks5_proxy"`
	TLS                 TLSConfig     `yaml:"tls" mapstructure:"tls"`
	Routes              []RouteConfig `yaml:"routes" mapstructure:"routes" validate:"dive"`

	ReadTimeout  time.Duration `yaml:"read_timeout" mapstructure:"read_timeout" default:"15s"`
	WriteTimeout time.Duration `yaml:"write_timeout" mapstructure:"write_timeout" default:"60s"`
	IdleTimeout  time.Duration `yaml:"idle_timeout" mapstructure:"idle_timeout" default:"12s"`
}

// TLSConfig defines TLS settings for a listener.
type TLSConfig struct {
	Enabled  bool     `yaml:"enabled" mapstructure:"enabled"`
	UseACME  bool     `yaml:"use_acme" mapstructure:"use_acme"`
	Domains  []string `yaml:"domains" mapstructure:"domains"`
	CertFile string   `yaml:"cert_file" mapstructure:"cert_file"`
	KeyFile  string   `yaml:"key_file" mapstructure:"key_file"`
}

// RouteConfig defines routing rules from virtual host/path to upstream backends.
type RouteConfig struct {
	Host                string            `yaml:"host" mapstructure:"host"`
	PathPrefix          string            `yaml:"path_prefix" mapstructure:"path_prefix" default:"/"`
	Upstream            string            `yaml:"upstream" mapstructure:"upstream" validate:"omitempty,url"`
	VerifySSL           *bool             `yaml:"verify_ssl" mapstructure:"verify_ssl" env:"VERIFY_SSL_UPSTREAM"`
	StripPrefix         bool              `yaml:"strip_prefix" mapstructure:"strip_prefix"`
	NoTLSTermination    bool              `yaml:"no_tls_termination" mapstructure:"no_tls_termination"`
	Timeout             time.Duration     `yaml:"timeout" mapstructure:"timeout" default:"30s"`
	CustomHeaders       map[string]string `yaml:"custom_headers" mapstructure:"custom_headers"`
	Debug               bool              `yaml:"debug" mapstructure:"debug" env:"DEBUG"`
	UpstreamSOCKS5Proxy string            `yaml:"upstream_socks5_proxy" mapstructure:"upstream_socks5_proxy"`

	DialerTimeout          time.Duration `yaml:"dialer_timeout" mapstructure:"dialer_timeout" default:"30s"`
	DialerKeepalive        time.Duration `yaml:"dialer_keepalive" mapstructure:"dialer_keepalive" default:"30s"`
	ForceAttemptHTTP2      bool          `yaml:"force_attempt_http2" mapstructure:"force_attempt_http2" default:"true"`
	MaxIdleConns           int           `yaml:"max_idle_conns" mapstructure:"max_idle_conns" default:"100"`
	IdleConnTimeout        time.Duration `yaml:"idle_conn_timeout" mapstructure:"idle_conn_timeout" default:"90s"`
	TLSHandshakeTimeout    time.Duration `yaml:"tls_handshake_timeout" mapstructure:"tls_handshake_timeout" default:"10s"`
	ExpectContinueTimeout  time.Duration `yaml:"expect_continue_timeout" mapstructure:"expect_continue_timeout" default:"1s"`
	PassthroughIdleTimeout time.Duration `yaml:"passthrough_idle_timeout" mapstructure:"passthrough_idle_timeout" default:"30s"`
}

// ACMEConfig defines global settings for Let's Encrypt certificate acquisition.
// Note: Email is only *conditionally* required (when a listener uses ACME), so it
// isn't marked `required` here; that's enforced in configStructLevelValidation.
type ACMEConfig struct {
	Email              string            `yaml:"email" mapstructure:"email" validate:"omitempty,email"`
	DirectoryURL       string            `yaml:"directory_url" mapstructure:"directory_url" default:"https://acme-v02.api.letsencrypt.org/directory" validate:"omitempty,url"`
	VerifySSL          *bool             `yaml:"verify_ssl" mapstructure:"verify_ssl" env:"VERIFY_SSL_ACME"`
	SOCKS5Proxy        string            `yaml:"socks5_proxy" mapstructure:"socks5_proxy"`
	StoragePath        string            `yaml:"storage_path" mapstructure:"storage_path" default:"./acme_storage"`
	RenewBeforeDays    int               `yaml:"renew_before_days" mapstructure:"renew_before_days" default:"30" validate:"gte=1"`
	CheckIntervalHours int               `yaml:"check_interval_hours" mapstructure:"check_interval_hours" default:"24" validate:"gte=1"`
	ClientTimeout      time.Duration     `yaml:"client_timeout" mapstructure:"client_timeout" default:"40s"`
	DNSProvider        DNSProviderConfig `yaml:"dns_provider" mapstructure:"dns_provider"`
}

// DNSProviderConfig defines settings for DNS-01 challenge providers.
type DNSProviderConfig struct {
	Name                 string           `yaml:"name" mapstructure:"name" default:"cloudflare" validate:"omitempty,oneof=arvancloud cloudflare"`
	UseSOCKS5            bool             `yaml:"use_socks5" mapstructure:"use_socks5"`
	RecursiveNameservers []string         `yaml:"recursive_nameservers" mapstructure:"recursive_nameservers"`
	ArvanCloud           ArvanCloudConfig `yaml:"arvancloud" mapstructure:"arvancloud"`
	Cloudflare           CloudflareConfig `yaml:"cloudflare" mapstructure:"cloudflare"`
}

// ArvanCloudConfig contains credentials and timings for ArvanCloud DNS.
type ArvanCloudConfig struct {
	APIKey             string `yaml:"api_key" mapstructure:"api_key" env:"ARVANCLOUD_API_KEY"`
	PropagationTimeout int    `yaml:"propagation_timeout" mapstructure:"propagation_timeout" default:"120" validate:"gte=1"`
	PollingInterval    int    `yaml:"polling_interval" mapstructure:"polling_interval" default:"2" validate:"gte=1"`
	TTL                int    `yaml:"ttl" mapstructure:"ttl" default:"600" validate:"gte=1"`
}

// CloudflareConfig contains credentials and timings for Cloudflare DNS.
type CloudflareConfig struct {
	APIToken           string `yaml:"api_token" mapstructure:"api_token" env:"CLOUDFLARE_DNS_API_TOKEN"`
	ZoneToken          string `yaml:"zone_token" mapstructure:"zone_token" env:"CLOUDFLARE_ZONE_API_TOKEN"`
	AuthEmail          string `yaml:"auth_email" mapstructure:"auth_email" env:"CLOUDFLARE_EMAIL"`
	AuthKey            string `yaml:"auth_key" mapstructure:"auth_key" env:"CLOUDFLARE_API_KEY"`
	PropagationTimeout int    `yaml:"propagation_timeout" mapstructure:"propagation_timeout" default:"120" validate:"gte=1"`
	PollingInterval    int    `yaml:"polling_interval" mapstructure:"polling_interval" default:"2" validate:"gte=1"`
	TTL                int    `yaml:"ttl" mapstructure:"ttl" default:"300" validate:"gte=1"`
}

// listenerStructLevelValidation covers rules that can't be expressed as simple tags
// on a single field of ListenerConfig.
func listenerStructLevelValidation(sl validator.StructLevel) {
	l := sl.Current().Interface().(ListenerConfig)

	// use_acme requires at least one domain
	if l.Protocol == "https" && l.TLS.UseACME && len(l.TLS.Domains) == 0 {
		sl.ReportError(l.TLS.Domains, "Domains", "Domains", "required_with_acme", "")
	}

	// A route without an upstream is only valid when the listener redirects to HTTPS.
	for i, r := range l.Routes {
		if r.Upstream == "" && !l.RedirectToHTTPS {
			sl.ReportError(l.Routes[i].Upstream, fmt.Sprintf("Routes[%d].Upstream", i), "Upstream", "required_without_redirect", "")
		}
	}
}

// configStructLevelValidation handles cross-cutting rules that span multiple
// sub-structs (e.g. ACME email required when any listener uses ACME, DNS
// provider credentials required when wildcard domains are requested).
func configStructLevelValidation(sl validator.StructLevel) {
	c := sl.Current().Interface().(Config)

	usesACME := false
	needsWildcard := false
	for _, l := range c.Listeners {
		if l.TLS.UseACME {
			usesACME = true
			for _, d := range l.TLS.Domains {
				if strings.HasPrefix(d, "*.") {
					needsWildcard = true
				}
			}
		}
	}

	if usesACME && c.ACME.Email == "" {
		sl.ReportError(c.ACME.Email, "ACME.Email", "Email", "required_with_acme", "")
	}

	if !needsWildcard {
		return
	}

	providerName := strings.ToLower(strings.TrimSpace(c.ACME.DNSProvider.Name))
	switch providerName {
	case "arvancloud":
		if c.ACME.DNSProvider.ArvanCloud.APIKey == "" {
			sl.ReportError(
				c.ACME.DNSProvider.ArvanCloud.APIKey,
				"ACME.DNSProvider.ArvanCloud.APIKey",
				"APIKey",
				"required_for_wildcard",
				"",
			)
		}
	case "cloudflare":
		cf := c.ACME.DNSProvider.Cloudflare
		if cf.APIToken == "" && (cf.AuthEmail == "" || cf.AuthKey == "") {
			sl.ReportError(
				cf.APIToken,
				"ACME.DNSProvider.Cloudflare",
				"Cloudflare",
				"credentials_required_for_wildcard",
				"",
			)
		}
	default:
		sl.ReportError(
			c.ACME.DNSProvider.Name,
			"ACME.DNSProvider.Name",
			"Name",
			"unsupported_provider",
			"",
		)
	}
}

// Load reads and parses a configuration file from path.
func Load(ctx context.Context, path string) (*Config, error) {
	logger := log.FromContext(ctx)
	logger.Info("Loading configuration file", zap.String("path", path))

	var (
		err    error
		cfgMap map[string]any
		cfg    Config
	)

	if cfgMap, err = toolconfig.ReadAndMergeConfig(ctx, path); err != nil {
		logger.Debug("toolconfig.Load returned error, falling back to direct YAML unmarshal", zap.Error(err))
		// #nosec G304 -- This variable is loaded from config.
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

// setDefaults applies `default`/`env` tag values via defaulter, then resolves
// the values that depend on sibling/parent fields (protocol inference and
// hierarchical SOCKS5 proxy inheritance).
func (c *Config) setDefaults(_ context.Context) error {
	if err := defaulter.ApplyDefaults(c, nil); err != nil {
		return err
	}

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

// validate runs go-playground/validator over the config tree and turns any
// validation errors into a readable, aggregated error.
func (c *Config) validate(_ context.Context) error {
	if err := validate.Struct(c); err != nil {
		var invalid *validator.InvalidValidationError
		if errors.As(err, &invalid) {
			return fmt.Errorf("invalid validation target: %w", err)
		}
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			msgs := make([]string, 0, len(ve))
			for _, fe := range ve {
				msgs = append(msgs, formatFieldError(fe))
			}
			return fmt.Errorf("configuration validation failed: %s", strings.Join(msgs, "; "))
		}
		return err
	}
	return nil
}

// formatFieldError converts a single FieldError into a human-friendly message
// with hints for the custom tags we register above.
func formatFieldError(fe validator.FieldError) string {
	ns := fe.Namespace()
	switch fe.Tag() {
	case "required":
		return ns + " is required"
	case "min":
		return fmt.Sprintf("%s must have at least %s items", ns, fe.Param())
	case "gte":
		return fmt.Sprintf("%s must be >= %s", ns, fe.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of [%s], got '%v'", ns, fe.Param(), fe.Value())
	case "url":
		return fmt.Sprintf("%s must be a valid URL, got '%v'", ns, fe.Value())
	case "email":
		return fmt.Sprintf("%s must be a valid email, got '%v'", ns, fe.Value())
	case "required_with_acme":
		return ns + " is required when TLS use_acme is enabled"
	case "required_without_redirect":
		return ns + " is required (route has no upstream and listener does not redirect_to_https)"
	case "required_for_wildcard":
		return ns + " is required for wildcard certificate generation"
	case "credentials_required_for_wildcard":
		return "cloudflare credentials required for wildcard: provide api_token OR (auth_email and auth_key)"
	case "unsupported_provider":
		return fmt.Sprintf("%s has unsupported value '%v' (supported: arvancloud, cloudflare)", ns, fe.Value())
	default:
		return fmt.Sprintf("%s failed '%s' validation", ns, fe.Tag())
	}
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
	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}
	return domains
}
