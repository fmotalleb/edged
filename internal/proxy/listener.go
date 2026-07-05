package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fmotalleb/edged/internal/acme"
	"github.com/fmotalleb/edged/internal/config"
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
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, l := range s.cfg.Listeners {
		var handler http.Handler

		if l.Protocol == "http" && l.RedirectToHTTPS {
			log.Printf("[Listener: %s] Configured as HTTP -> HTTPS Redirector on %s", l.Name, l.Address)
			handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				host := req.Host
				if idx := strings.Index(host, ":"); idx != -1 {
					host = host[:idx]
				}
				targetURL := "https://" + host + req.URL.RequestURI()
				http.Redirect(w, req, targetURL, http.StatusMovedPermanently)
			})
		} else {
			router, err := NewProxyRouter(l.Name, l.Protocol, l.Routes)
			if err != nil {
				return fmt.Errorf("failed to create proxy router for listener '%s': %w", l.Name, err)
			}
			handler = router
		}

		srv := &http.Server{
			Addr:         l.Address,
			Handler:      handler,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
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
					log.Printf("[Listener: %s] Enabling Let's Encrypt ACME TLS on %s for domains: %v", l.Name, l.Address, l.TLS.Domains)
					tlsConfig.GetCertificate = s.acmeMgr.GetCertificate
				} else if l.TLS.CertFile != "" && l.TLS.KeyFile != "" {
					log.Printf("[Listener: %s] Loading static TLS certificates from %s / %s", l.Name, l.TLS.CertFile, l.TLS.KeyFile)
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
				log.Printf("[Listener: %s] Starting HTTPS reverse proxy on %s", name, addr)
				if err := s.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					log.Fatalf("[Listener: %s] Fatal HTTPS server error: %v", name, err)
				}
			}(l.Name, l.Address, srv)
		} else {
			s.servers = append(s.servers, srv)
			go func(name, addr string, s *http.Server) {
				log.Printf("[Listener: %s] Starting HTTP server on %s", name, addr)
				if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Fatalf("[Listener: %s] Fatal HTTP server error: %v", name, err)
				}
			}(l.Name, l.Address, srv)
		}
	}

	return nil
}

// Stop gracefully shuts down all running HTTP/HTTPS listeners.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Println("[Server] Initiating graceful shutdown of all listeners...")
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
	log.Println("[Server] All listeners stopped successfully.")
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
