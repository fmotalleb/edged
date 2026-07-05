package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fmotalleb/go-tools/log"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/arvancloud"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"go.uber.org/zap"

	"github.com/fmotalleb/edged/config"
)

var defaultRecursiveNS = []string{"8.8.8.8:53", "1.1.1.1:53"}

// Manager handles automatic TLS certificate acquisition, renewal, and serving via Lego and Let's Encrypt.
type Manager struct {
	cfg       config.ACMEConfig
	client    *lego.Client
	user      *User
	certs     map[string]*tls.Certificate // Map from domain name / wildcard pattern to TLS cert
	certMeta  map[string]time.Time        // Map from domain name to expiration time
	mu        sync.RWMutex
	obtainMu  sync.Mutex // Mutex to prevent duplicate concurrent obtain requests
	transport *http.Transport
}

// NewManager initializes the ACME manager, configuring SOCKS5 proxy and DNS challenge providers.
func NewManager(ctx context.Context, cfg config.ACMEConfig) (*Manager, error) {
	logger := log.FromContext(ctx)
	m := &Manager{
		cfg:      cfg,
		certs:    make(map[string]*tls.Certificate),
		certMeta: make(map[string]time.Time),
	}

	if err := os.MkdirAll(filepath.Join(cfg.StoragePath, "accounts"), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create storage dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.StoragePath, "certs"), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create certs dir: %w", err)
	}

	// 1. Configure SOCKS5 Proxy Transport if specified
	if cfg.SOCKS5Proxy != "" {
		proxyURL, err := url.Parse(cfg.SOCKS5Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid socks5_proxy URL '%s': %w", cfg.SOCKS5Proxy, err)
		}
		logger.Info("Configuring Let's Encrypt HTTP client to use SOCKS5 proxy", zap.String("proxy", cfg.SOCKS5Proxy))
		m.transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
	} else {
		m.transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
	}

	// 2. Load or create user account private key
	accountKeyPath := filepath.Join(cfg.StoragePath, "accounts", "private.key")
	accountKey, err := loadOrCreatePrivateKey(accountKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to manage account private key: %w", err)
	}

	// 3. Load or initialize User registration
	userPath := filepath.Join(cfg.StoragePath, "accounts", "user.json")
	user, err := loadUser(userPath, accountKey)
	if err != nil {
		user = &User{
			Email: cfg.Email,
			key:   accountKey,
		}
	}
	m.user = user

	// 4. Create Lego configuration
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = cfg.DirectoryURL
	legoCfg.Certificate.KeyType = certcrypto.RSA2048
	legoCfg.HTTPClient = &http.Client{
		Transport: m.transport,
		Timeout:   45 * time.Second,
	}

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}
	m.client = client

	// 5. Setup DNS-01 Provider (ArvanCloud or Cloudflare) for wildcard certificate support
	providerName := strings.ToLower(strings.TrimSpace(cfg.DNSProvider.Name))
	recursiveServers := cfg.DNSProvider.RecursiveNameservers
	if len(recursiveServers) == 0 {
		recursiveServers = defaultRecursiveNS
	}
	switch providerName {
	case "arvancloud":
		if cfg.DNSProvider.ArvanCloud.APIKey != "" {
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
					Timeout:   30 * time.Second,
				}
			}

			provider, err := arvancloud.NewDNSProviderConfig(arvConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize ArvanCloud DNS provider: %w", err)
			}

			err = client.Challenge.SetDNS01Provider(provider,
				dns01.AddRecursiveNameservers(
					dns01.ParseNameservers(recursiveServers),
				),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to set ArvanCloud DNS-01 provider: %w", err)
			}
		}
	case "cloudflare":
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
				Timeout:   30 * time.Second,
			}
		}

		provider, err := cloudflare.NewDNSProviderConfig(cfConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Cloudflare DNS provider: %w", err)
		}

		err = client.Challenge.SetDNS01Provider(provider,
			dns01.AddRecursiveNameservers(dns01.ParseNameservers(recursiveServers)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to set Cloudflare DNS-01 provider: %w", err)
		}
	}

	// 6. Register ACME Account if not registered yet
	if user.Registration == nil {
		logger.Info("Registering new ACME account", zap.String("email", cfg.Email))
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("failed to register ACME account: %w", err)
		}
		user.Registration = reg
		if err := saveUser(userPath, user); err != nil {
			logger.Warn("Failed to save account registration to disk", zap.Error(err))
		}
		logger.Info("ACME Account registered successfully", zap.String("uri", reg.URI))
	}

	// 7. Load existing certificates from disk into memory
	if err := m.loadCertificatesFromDisk(ctx); err != nil {
		logger.Warn("Warning during loading certificates from disk", zap.Error(err))
	}

	return m, nil
}

// GetCertificate is the callback for tls.Config.GetCertificate during TLS handshakes.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := strings.ToLower(strings.TrimSpace(hello.ServerName))
	if serverName == "" {
		m.mu.RLock()
		for _, cert := range m.certs {
			m.mu.RUnlock()
			return cert, nil
		}
		m.mu.RUnlock()
		return nil, errors.New("no SNI provided and no default TLS certificate available")
	}

	m.mu.RLock()
	if cert, ok := m.certs[serverName]; ok {
		m.mu.RUnlock()
		return cert, nil
	}

	parts := strings.Split(serverName, ".")
	if len(parts) >= 2 {
		wildcardName := "*." + strings.Join(parts[1:], ".")
		if cert, ok := m.certs[wildcardName]; ok {
			m.mu.RUnlock()
			return cert, nil
		}
	}
	m.mu.RUnlock()

	return nil, fmt.Errorf("no TLS certificate configured or loaded for domain: %s", serverName)
}

// EnsureDomains checks that all specified domains have valid certificates, obtaining them if needed.
func (m *Manager) EnsureDomains(ctx context.Context, domains []string) error {
	if len(domains) == 0 {
		return nil
	}

	logger := log.FromContext(ctx)
	var missingOrExpiring []string
	m.mu.RLock()
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		exp, exists := m.certMeta[domain]
		if !exists {
			missingOrExpiring = append(missingOrExpiring, domain)
			continue
		}
		daysLeft := time.Until(exp).Hours() / 24.0
		if daysLeft < float64(m.cfg.RenewBeforeDays) {
			logger.Info("Certificate is nearing expiration, marking for renewal",
				zap.String("domain", domain),
				zap.Float64("days_left", daysLeft),
				zap.Int("threshold_days", m.cfg.RenewBeforeDays))
			missingOrExpiring = append(missingOrExpiring, domain)
		}
	}
	m.mu.RUnlock()

	if len(missingOrExpiring) == 0 {
		return nil
	}

	return m.obtainCertificate(ctx, domains)
}

// obtainCertificate requests a new or renewed certificate from Let's Encrypt for the domain bundle.
func (m *Manager) obtainCertificate(ctx context.Context, domains []string) error {
	m.obtainMu.Lock()
	defer m.obtainMu.Unlock()

	logger := log.FromContext(ctx)

	needsObtain := false
	m.mu.RLock()
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		exp, exists := m.certMeta[d]
		if !exists || time.Until(exp).Hours()/24.0 < float64(m.cfg.RenewBeforeDays) {
			needsObtain = true
			break
		}
	}
	m.mu.RUnlock()

	if !needsObtain {
		return nil
	}

	logger.Info("Requesting certificate via Let's Encrypt", zap.Strings("domains", domains))
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate for %v: %w", domains, err)
	}

	logger.Info("Successfully obtained certificate bundle", zap.Strings("domains", domains))

	primaryDomain := strings.ReplaceAll(strings.ToLower(domains[0]), "*", "_wildcard")
	certPath := filepath.Join(m.cfg.StoragePath, "certs", primaryDomain+".crt")
	keyPath := filepath.Join(m.cfg.StoragePath, "certs", primaryDomain+".key")

	if err := os.WriteFile(certPath, certificates.Certificate, 0o600); err != nil {
		return fmt.Errorf("failed to save cert to disk: %w", err)
	}
	if err := os.WriteFile(keyPath, certificates.PrivateKey, 0o600); err != nil {
		return fmt.Errorf("failed to save key to disk: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse X509 key pair: %w", err)
	}

	var expTime time.Time
	if len(tlsCert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err == nil {
			expTime = x509Cert.NotAfter
		}
	}
	if expTime.IsZero() {
		expTime = time.Now().AddDate(0, 3, 0)
	}

	m.mu.Lock()
	for _, d := range domains {
		dLower := strings.ToLower(strings.TrimSpace(d))
		m.certs[dLower] = &tlsCert
		m.certMeta[dLower] = expTime
	}
	m.mu.Unlock()

	return nil
}

// StartRenewalDaemon starts a background goroutine that periodically checks and renews certificates.
func (m *Manager) StartRenewalDaemon(ctx context.Context, domains []string) {
	interval := time.Duration(m.cfg.CheckIntervalHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	logger := log.FromContext(ctx)
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				logger.Info("Running scheduled certificate renewal check", zap.Strings("domains", domains))
				if err := m.EnsureDomains(ctx, domains); err != nil {
					logger.Error("Error during scheduled certificate renewal check", zap.Error(err))
				}
			}
		}
	}()
}

// loadCertificatesFromDisk scans the certs directory and loads existing certs into memory.
func (m *Manager) loadCertificatesFromDisk(ctx context.Context) error {
	logger := log.FromContext(ctx)
	certDir := filepath.Join(m.cfg.StoragePath, "certs")
	files, err := os.ReadDir(certDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".crt") {
			continue
		}
		baseName := strings.TrimSuffix(file.Name(), ".crt")
		certPath := filepath.Join(certDir, file.Name())
		keyPath := filepath.Join(certDir, baseName+".key")

		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			continue
		}

		tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			logger.Warn("Failed to load X509 key pair from disk", zap.String("base_name", baseName), zap.Error(err))
			continue
		}

		var expTime time.Time
		var dnsNames []string
		if len(tlsCert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
			if err == nil {
				expTime = x509Cert.NotAfter
				dnsNames = x509Cert.DNSNames
			}
		}

		if len(dnsNames) == 0 {
			domain := strings.ReplaceAll(baseName, "_wildcard", "*")
			dnsNames = []string{domain}
		}

		m.mu.Lock()
		for _, d := range dnsNames {
			dLower := strings.ToLower(strings.TrimSpace(d))
			m.certs[dLower] = &tlsCert
			m.certMeta[dLower] = expTime
			logger.Info("Loaded certificate from disk", zap.String("domain", dLower), zap.Time("expires", expTime))
		}
		m.mu.Unlock()
	}
	return nil
}

// loadOrCreatePrivateKey loads an ECDSA private key from disk or generates a new P-256 key.
func loadOrCreatePrivateKey(path string) (crypto.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return key, nil
			}
			if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return nil, err
	}

	return key, nil
}
