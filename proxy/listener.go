package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/fmotalleb/go-tools/log"
	"go.uber.org/zap"

	"github.com/fmotalleb/edged/acme"
	"github.com/fmotalleb/edged/config"
)

// Server manages all configured HTTP and HTTPS listener instances.
type Server struct {
	cfg     *config.Config
	acmeMgr *acme.Manager
	servers []*http.Server
	mu      sync.Mutex
}

// NewServer initializes the listener manager with configuration and ACME certificate manager.
func NewServer(cfg *config.Config, acmeMgr *acme.Manager) *Server {
	return &Server{
		cfg:     cfg,
		acmeMgr: acmeMgr,
	}
}

// Start boots up all network listeners in separate goroutines.
func (s *Server) Start(ctx context.Context) error {
	logger := log.FromContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, l := range s.cfg.Listeners {
		var handler http.Handler

		if l.Protocol == "http" && l.RedirectToHTTPS {
			logger.Info("Configuring HTTP -> HTTPS Redirector", zap.String("listener", l.Name), zap.String("address", l.Address))
			handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				host := req.Host
				if idx := strings.Index(host, ":"); idx != -1 {
					host = host[:idx]
				}
				targetURL := "https://" + host + req.URL.RequestURI()
				// #nosec G710 -- Reverse proxy intentionally redirects to the same user-requested host.
				http.Redirect(w, req, targetURL, http.StatusMovedPermanently)
			})
		} else {
			router, err := NewProxyRouter(ctx, l.Name, l.Protocol, l.Routes)
			if err != nil {
				return fmt.Errorf("failed to create proxy router for listener '%s': %w", l.Name, err)
			}
			handler = router
		}

		srv := &http.Server{
			Addr:         l.Address,
			Handler:      handler,
			ReadTimeout:  l.ReadTimeout,
			WriteTimeout: l.WriteTimeout,
			IdleTimeout:  l.IdleTimeout,
			BaseContext: func(_ net.Listener) context.Context {
				return ctx
			},
		}

		if l.Protocol == "https" {
			tlsConfig := &tls.Config{
				MinVersion:               tls.VersionTLS12,
				PreferServerCipherSuites: true,
			}

			if l.TLS.Enabled {
				if l.TLS.UseACME {
					if s.acmeMgr == nil {
						return fmt.Errorf("listener '%s' requested ACME TLS but ACME manager is not initialized", l.Name)
					}
					logger.Info("Enabling Let's Encrypt ACME TLS on HTTPS listener",
						zap.String("listener", l.Name),
						zap.String("address", l.Address),
						zap.Strings("domains", l.TLS.Domains))
					tlsConfig.GetCertificate = s.acmeMgr.GetCertificate
				} else if l.TLS.CertFile != "" && l.TLS.KeyFile != "" {
					logger.Info("Loading static TLS certificates on HTTPS listener",
						zap.String("listener", l.Name),
						zap.String("cert_file", l.TLS.CertFile),
						zap.String("key_file", l.TLS.KeyFile))
					cert, err := tls.LoadX509KeyPair(l.TLS.CertFile, l.TLS.KeyFile)
					if err != nil {
						return fmt.Errorf("failed to load static TLS certs for listener '%s': %w", l.Name, err)
					}
					tlsConfig.Certificates = []tls.Certificate{cert}
				}
			}
			srv.TLSConfig = tlsConfig

			s.servers = append(s.servers, srv)
			go func(name, addr string, s *http.Server) {
				logger.Info("Starting HTTPS reverse proxy listener", zap.String("listener", name), zap.String("address", addr))
				if err := s.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					logger.Fatal("Fatal HTTPS server error", zap.String("listener", name), zap.Error(err))
				}
			}(l.Name, l.Address, srv)
		} else {
			s.servers = append(s.servers, srv)
			go func(name, addr string, s *http.Server) {
				logger.Info("Starting HTTP server listener", zap.String("listener", name), zap.String("address", addr))
				if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Fatal("Fatal HTTP server error", zap.String("listener", name), zap.Error(err))
				}
			}(l.Name, l.Address, srv)
		}
	}

	return nil
}

// Stop gracefully shuts down all running HTTP/HTTPS listeners.
func (s *Server) Stop(ctx context.Context) error {
	logger := log.FromContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	logger.Info("Initiating graceful shutdown of all listeners...")
	var wg sync.WaitGroup
	var errs []string
	var errMu sync.Mutex

	for _, srv := range s.servers {
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			if err := s.Shutdown(ctx); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Sprintf("server on %s shutdown error: %v", s.Addr, err))
				errMu.Unlock()
			}
		}(srv)
	}

	wg.Wait()
	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %s", strings.Join(errs, "; "))
	}
	logger.Info("All listeners stopped successfully")
	return nil
}

// GetListenersAddrs returns the actual network addresses being listened on (useful for 0 port testing).
func (s *Server) GetListenersAddrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var addrs []string
	for _, srv := range s.servers {
		addrs = append(addrs, srv.Addr)
	}
	return addrs
}
