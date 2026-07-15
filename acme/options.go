package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fmotalleb/go-tools/log"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/arvancloud"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"go.uber.org/zap"

	"github.com/fmotalleb/edged/config"
)

const (
	defaultHttpTimeout    = 45 * time.Second
	defaultDNSHTTPTimeout = 30 * time.Second
)

type ManagerOption func(*managerOptions) error

type managerOptions struct {
	cfg config.ACMEConfig

	transport  *http.Transport
	httpClient *http.Client

	httpTimeout    time.Duration
	dnsHTTPTimeout time.Duration

	certKeyType certcrypto.KeyType

	registerAccount      bool
	termsOfServiceAgreed bool
	loadExistingCerts    bool

	recursiveNameservers []string
}

func defaultManagerOptions() managerOptions {
	return managerOptions{
		httpTimeout:          defaultHttpTimeout,
		dnsHTTPTimeout:       defaultDNSHTTPTimeout,
		certKeyType:          certcrypto.RSA2048,
		registerAccount:      true,
		termsOfServiceAgreed: true,
		loadExistingCerts:    true,
	}
}

func WithConfig(cfg config.ACMEConfig) ManagerOption {
	return func(o *managerOptions) error {
		o.cfg = cfg
		return nil
	}
}

// Useful when you want options pattern without exposing every nested config type.
func WithConfigFunc(fn func(*config.ACMEConfig)) ManagerOption {
	return func(o *managerOptions) error {
		if fn == nil {
			return errors.New("nil ACME config mutation function")
		}

		fn(&o.cfg)
		return nil
	}
}

func WithEmail(email string) ManagerOption {
	return func(o *managerOptions) error {
		o.cfg.Email = email
		return nil
	}
}

func WithStoragePath(path string) ManagerOption {
	return func(o *managerOptions) error {
		o.cfg.StoragePath = path
		return nil
	}
}

func WithDirectoryURL(url string) ManagerOption {
	return func(o *managerOptions) error {
		o.cfg.DirectoryURL = url
		return nil
	}
}

func WithSOCKS5Proxy(proxy string) ManagerOption {
	return func(o *managerOptions) error {
		o.cfg.SOCKS5Proxy = proxy
		return nil
	}
}

func WithRenewBeforeDays(days int) ManagerOption {
	return func(o *managerOptions) error {
		o.cfg.RenewBeforeDays = days
		return nil
	}
}

func WithCheckIntervalHours(hours int) ManagerOption {
	return func(o *managerOptions) error {
		o.cfg.CheckIntervalHours = hours
		return nil
	}
}

func WithHTTPTransport(transport *http.Transport) ManagerOption {
	return func(o *managerOptions) error {
		if transport == nil {
			return errors.New("nil HTTP transport")
		}

		o.transport = transport
		return nil
	}
}

func WithHTTPClient(client *http.Client) ManagerOption {
	return func(o *managerOptions) error {
		if client == nil {
			return errors.New("nil HTTP client")
		}

		o.httpClient = client
		return nil
	}
}

func WithHTTPTimeout(timeout time.Duration) ManagerOption {
	return func(o *managerOptions) error {
		if timeout <= 0 {
			return errors.New("HTTP timeout must be positive")
		}

		o.httpTimeout = timeout
		return nil
	}
}

func WithDNSHTTPTimeout(timeout time.Duration) ManagerOption {
	return func(o *managerOptions) error {
		if timeout <= 0 {
			return errors.New("DNS HTTP timeout must be positive")
		}

		o.dnsHTTPTimeout = timeout
		return nil
	}
}

func WithCertificateKeyType(keyType certcrypto.KeyType) ManagerOption {
	return func(o *managerOptions) error {
		o.certKeyType = keyType
		return nil
	}
}

func WithRecursiveNameservers(nameservers ...string) ManagerOption {
	return func(o *managerOptions) error {
		o.recursiveNameservers = append([]string(nil), nameservers...)
		return nil
	}
}

func WithAccountRegistration(enabled bool) ManagerOption {
	return func(o *managerOptions) error {
		o.registerAccount = enabled
		return nil
	}
}

func WithTermsOfServiceAgreed(agreed bool) ManagerOption {
	return func(o *managerOptions) error {
		o.termsOfServiceAgreed = agreed
		return nil
	}
}

func WithLoadExistingCertificates(enabled bool) ManagerOption {
	return func(o *managerOptions) error {
		o.loadExistingCerts = enabled
		return nil
	}
}

// NewManager initializes the ACME manager using functional options.
func NewManager(ctx context.Context, opts ...ManagerOption) (*Manager, error) {
	logger := log.FromContext(ctx)

	options := defaultManagerOptions()
	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt(&options); err != nil {
			return nil, err
		}
	}

	cfg := options.cfg

	if strings.TrimSpace(cfg.StoragePath) == "" {
		return nil, errors.New("ACME storage path is required")
	}

	m := &Manager{
		cfg:      cfg,
		certs:    make(map[string]*tls.Certificate),
		certMeta: make(map[string]time.Time),
	}

	err := mkStorageDirs(cfg)
	if err != nil {
		return m, err
	}

	transport := options.transport
	if transport == nil {
		transport, err = newACMETransport(ctx, cfg)
		if err != nil {
			return nil, err
		}
	}

	m.transport = transport

	accountKeyPath := filepath.Join(cfg.StoragePath, "accounts", "private.key")

	accountKey, err := loadOrCreatePrivateKey(accountKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to manage account private key: %w", err)
	}

	userPath := filepath.Join(cfg.StoragePath, "accounts", "user.json")

	user, err := loadUser(userPath, accountKey)
	if err != nil {
		user = &User{
			Email: cfg.Email,
			key:   accountKey,
		}
	}

	m.user = user

	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = cfg.DirectoryURL
	legoCfg.Certificate.KeyType = options.certKeyType

	if options.httpClient != nil {
		legoCfg.HTTPClient = options.httpClient
	} else {
		legoCfg.HTTPClient = &http.Client{
			Transport: transport,
			Timeout:   options.httpTimeout,
		}
	}

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	m.client = client

	if err = m.configureDNS01Provider(ctx, options); err != nil {
		return nil, err
	}

	if options.registerAccount && user.Registration == nil {
		err = registerUser(logger, cfg, client, options, user, userPath)
		if err != nil {
			return m, err
		}
	}

	if options.loadExistingCerts {
		if err := m.loadCertificatesFromDisk(ctx); err != nil {
			logger.Warn("Warning during loading certificates from disk", zap.Error(err))
		}
	}

	return m, nil
}

func registerUser(logger *zap.Logger, cfg config.ACMEConfig, client *lego.Client, options managerOptions, user *User, userPath string) error {
	logger.Info("Registering new ACME account", zap.String("email", cfg.Email))

	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: options.termsOfServiceAgreed,
	})
	if err != nil {
		return fmt.Errorf("failed to register ACME account: %w", err)
	}

	user.Registration = reg

	if err := saveUser(userPath, user); err != nil {
		logger.Warn("Failed to save account registration to disk", zap.Error(err))
	}

	logger.Info("ACME Account registered successfully", zap.String("uri", reg.URI))
	return nil
}

func mkStorageDirs(cfg config.ACMEConfig) error {
	if err := os.MkdirAll(filepath.Join(cfg.StoragePath, "accounts"), 0o700); err != nil {
		return fmt.Errorf("failed to create storage dir: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(cfg.StoragePath, "certs"), 0o700); err != nil {
		return fmt.Errorf("failed to create certs dir: %w", err)
	}
	return nil
}

// Optional compatibility helper if you still want config-first call sites.
func NewManagerFromConfig(ctx context.Context, cfg config.ACMEConfig, opts ...ManagerOption) (*Manager, error) {
	allOpts := make([]ManagerOption, 0, len(opts)+1)
	allOpts = append(allOpts, WithConfig(cfg))
	allOpts = append(allOpts, opts...)

	return NewManager(ctx, allOpts...)
}

func newACMETransport(ctx context.Context, cfg config.ACMEConfig) (*http.Transport, error) {
	logger := log.FromContext(ctx)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Disable ACME server certificate verification when explicitly set to false.
	if cfg.VerifySSL != nil && !*cfg.VerifySSL {
		tlsConfig.InsecureSkipVerify = true //nolint:gosec
		logger.Warn("ACME server TLS verification is disabled (VERIFY_SSL_ACME=false)")
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if cfg.SOCKS5Proxy == "" {
		return transport, nil
	}

	proxyURL, err := url.Parse(cfg.SOCKS5Proxy)
	if err != nil {
		return nil, fmt.Errorf("invalid socks5_proxy URL %q: %w", cfg.SOCKS5Proxy, err)
	}

	logger.Info(
		"Configuring Let's Encrypt HTTP client to use SOCKS5 proxy",
		zap.String("proxy", cfg.SOCKS5Proxy),
	)

	transport.Proxy = http.ProxyURL(proxyURL)

	return transport, nil
}

func (m *Manager) configureDNS01Provider(ctx context.Context, options managerOptions) error {
	logger := log.FromContext(ctx)

	cfg := m.cfg

	providerName := strings.ToLower(strings.TrimSpace(cfg.DNSProvider.Name))
	if providerName == "" {
		return nil
	}

	recursiveServers := options.recursiveNameservers
	if len(recursiveServers) == 0 {
		recursiveServers = cfg.DNSProvider.RecursiveNameservers
	}

	if len(recursiveServers) == 0 {
		recursiveServers = defaultRecursiveNS
	}

	switch providerName {
	case "arvancloud":
		return m.configureArvanCloudDNS01Provider(ctx, options, recursiveServers)

	case "cloudflare":
		return m.configureCloudflareDNS01Provider(ctx, options, recursiveServers)

	default:
		logger.Warn("Unknown ACME DNS provider; DNS-01 provider was not configured", zap.String("provider", providerName))
		return nil
	}
}

func (m *Manager) configureArvanCloudDNS01Provider(
	ctx context.Context,
	options managerOptions,
	recursiveServers []string,
) error {
	logger := log.FromContext(ctx)

	cfg := m.cfg

	if cfg.DNSProvider.ArvanCloud.APIKey == "" {
		logger.Warn("ArvanCloud DNS provider selected but API key is empty")
		return nil
	}

	logger.Info("Configuring ArvanCloud DNS-01 challenge provider...")

	arvConfig := arvancloud.NewDefaultConfig()
	arvConfig.APIKey = cfg.DNSProvider.ArvanCloud.APIKey

	if cfg.DNSProvider.ArvanCloud.PropagationTimeout > 0 {
		arvConfig.PropagationTimeout = time.Duration(cfg.DNSProvider.ArvanCloud.PropagationTimeout) * time.Second
	}

	if cfg.DNSProvider.ArvanCloud.PollingInterval > 0 {
		arvConfig.PollingInterval = time.Duration(cfg.DNSProvider.ArvanCloud.PollingInterval) * time.Second
	}

	if cfg.DNSProvider.ArvanCloud.TTL > 0 {
		arvConfig.TTL = cfg.DNSProvider.ArvanCloud.TTL
	}

	if cfg.DNSProvider.UseSOCKS5 && m.transport != nil {
		logger.Info("Routing ArvanCloud DNS API requests via SOCKS5 proxy")

		arvConfig.HTTPClient = &http.Client{
			Transport: m.transport,
			Timeout:   options.dnsHTTPTimeout,
		}
	}

	provider, err := arvancloud.NewDNSProviderConfig(arvConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize ArvanCloud DNS provider: %w", err)
	}

	if err := m.client.Challenge.SetDNS01Provider(
		provider,
		dns01.AddRecursiveNameservers(dns01.ParseNameservers(recursiveServers)),
	); err != nil {
		return fmt.Errorf("failed to set ArvanCloud DNS-01 provider: %w", err)
	}

	return nil
}

func (m *Manager) configureCloudflareDNS01Provider(
	ctx context.Context,
	options managerOptions,
	recursiveServers []string,
) error {
	logger := log.FromContext(ctx)

	cfg := m.cfg

	logger.Info("Configuring Cloudflare DNS-01 challenge provider...")

	cfConfig := cloudflare.NewDefaultConfig()

	if cfg.DNSProvider.Cloudflare.APIToken != "" {
		cfConfig.AuthToken = cfg.DNSProvider.Cloudflare.APIToken
		cfConfig.ZoneToken = cfg.DNSProvider.Cloudflare.ZoneToken
	} else {
		cfConfig.AuthEmail = cfg.DNSProvider.Cloudflare.AuthEmail
		cfConfig.AuthKey = cfg.DNSProvider.Cloudflare.AuthKey
	}

	if cfg.DNSProvider.Cloudflare.PropagationTimeout > 0 {
		cfConfig.PropagationTimeout = time.Duration(cfg.DNSProvider.Cloudflare.PropagationTimeout) * time.Second
	}

	if cfg.DNSProvider.Cloudflare.PollingInterval > 0 {
		cfConfig.PollingInterval = time.Duration(cfg.DNSProvider.Cloudflare.PollingInterval) * time.Second
	}

	if cfg.DNSProvider.Cloudflare.TTL > 0 {
		cfConfig.TTL = cfg.DNSProvider.Cloudflare.TTL
	}

	if cfg.DNSProvider.UseSOCKS5 && m.transport != nil {
		logger.Info("Routing Cloudflare DNS API requests via SOCKS5 proxy")

		cfConfig.HTTPClient = &http.Client{
			Transport: m.transport,
			Timeout:   options.dnsHTTPTimeout,
		}
	}

	provider, err := cloudflare.NewDNSProviderConfig(cfConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize Cloudflare DNS provider: %w", err)
	}

	if err := m.client.Challenge.SetDNS01Provider(
		provider,
		dns01.AddRecursiveNameservers(dns01.ParseNameservers(recursiveServers)),
	); err != nil {
		return fmt.Errorf("failed to set Cloudflare DNS-01 provider: %w", err)
	}

	return nil
}
