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
	"github.com/pires/go-proxyproto"
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

	tlsPassthroughServers []*TLSPassThroughListener
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
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, l := range s.cfg.Listeners {
		handler, err := s.buildHandler(ctx, l)
		if err != nil {
			return err
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
			if err := s.startHTTPSListener(ctx, l, srv, handler); err != nil {
				return err
			}
		} else {
			s.startHTTPListener(ctx, l, srv)
		}
	}

	return nil
}

// buildHandler creates the HTTP handler for a listener, handling HTTPS redirect or proxy routing.
func (s *Server) buildHandler(ctx context.Context, l config.ListenerConfig) (http.Handler, error) {
	logger := log.FromContext(ctx)

	if l.Protocol == "http" && l.RedirectToHTTPS {
		logger.Info("Configuring HTTP -> HTTPS Redirector", zap.String("listener", l.Name), zap.String("address", l.Address))
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			host := req.Host
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}
			targetURL := "https://" + host + req.URL.RequestURI()
			// #nosec G710 -- Reverse proxy intentionally redirects to the same user-requested host.
			http.Redirect(w, req, targetURL, http.StatusMovedPermanently)
		}), nil
	}

	return NewProxyRouter(ctx, l.Name, l.Protocol, l.Routes)
}

// buildTLSConfig constructs the TLS configuration for an HTTPS listener.
func (s *Server) buildTLSConfig(ctx context.Context, l config.ListenerConfig) (*tls.Config, error) {
	logger := log.FromContext(ctx)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if !l.TLS.Enabled {
		return tlsConfig, nil
	}

	if l.TLS.UseACME {
		if s.acmeMgr == nil {
			return nil, fmt.Errorf("listener '%s' requested ACME TLS but ACME manager is not initialized", l.Name)
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
			return nil, fmt.Errorf("failed to load static TLS certs for listener '%s': %w", l.Name, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// startTLSProxyProtocol creates a proxy protocol listener, appends the server, and starts it.
func (s *Server) startTLSProxyProtocol(ctx context.Context, l config.ListenerConfig, srv *http.Server, tlsConfig *tls.Config, logger *zap.Logger) error {
	rawListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", l.Address)
	if err != nil {
		return fmt.Errorf("tcp listen on %s for PROXY protocol: %w", l.Address, err)
	}
	srv.TLSConfig = tlsConfig
	srvppListener := &proxyproto.Listener{Listener: rawListener}
	s.servers = append(s.servers, srv)
	go func(name string, s *http.Server) {
		logger.Info("Starting HTTPS reverse proxy listener with PROXY protocol",
			zap.String("listener", name),
			zap.String("address", rawListener.Addr().String()),
			zap.String("proxy_protocol", l.ProxyProtocol))
		if err := s.ServeTLS(srvppListener, "", ""); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Fatal HTTPS server error", zap.String("listener", name), zap.Error(err))
		}
	}(l.Name, srv)
	return nil
}

// startHTTPProxyProtocol creates a proxy protocol listener, appends the server, and starts it.
func (s *Server) startHTTPProxyProtocol(ctx context.Context, l config.ListenerConfig, srv *http.Server, logger *zap.Logger) error {
	rawListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", l.Address)
	if err != nil {
		return fmt.Errorf("tcp listen on %s for PROXY protocol: %w", l.Address, err)
	}
	srvppListener := &proxyproto.Listener{Listener: rawListener}
	s.servers = append(s.servers, srv)
	go func(name string, s *http.Server) {
		logger.Info("Starting HTTP server listener with PROXY protocol",
			zap.String("listener", name),
			zap.String("address", rawListener.Addr().String()),
			zap.String("proxy_protocol", l.ProxyProtocol))
		if err := s.Serve(srvppListener); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Fatal HTTP server error", zap.String("listener", name), zap.Error(err))
		}
	}(l.Name, srv)
	return nil
}

// startHTTPSListener configures and starts an HTTPS listener.
func (s *Server) startHTTPSListener(ctx context.Context, l config.ListenerConfig, srv *http.Server, handler http.Handler) error {
	logger := log.FromContext(ctx)

	tlsConfig, err := s.buildTLSConfig(ctx, l)
	if err != nil {
		return err
	}

	// If any route has no_tls_termination enabled, we must use a raw TCP
	// listener that inspects the SNI to decide between TLS passthrough
	// and TLS termination on a per-connection basis.
	if hasPassthroughRoutes(l.Routes) {
		passthroughSrv := NewTLSPassThroughListener(ctx, l.Address, l.Routes, handler, tlsConfig,
			l.ReadTimeout, l.WriteTimeout, l.IdleTimeout,
			l.ProxyProtocol)
		s.tlsPassthroughServers = append(s.tlsPassthroughServers, passthroughSrv)
		go func(name, addr string, p *TLSPassThroughListener) {
			logger.Info("Starting HTTPS listener with TLS passthrough support",
				zap.String("listener", name),
				zap.String("address", addr))
			if err := p.ListenAndServe(); err != nil {
				logger.Fatal("Fatal TLS passthrough proxy error", zap.String("listener", name), zap.Error(err))
			}
		}(l.Name, l.Address, passthroughSrv)
		return nil
	}

	if proxyProtocolEnabled(l.ProxyProtocol) {
		return s.startTLSProxyProtocol(ctx, l, srv, tlsConfig, logger)
	}

	srv.TLSConfig = tlsConfig
	s.servers = append(s.servers, srv)
	go func(name, addr string, s *http.Server) {
		logger.Info("Starting HTTPS reverse proxy listener", zap.String("listener", name), zap.String("address", addr))
		if err := s.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Fatal HTTPS server error", zap.String("listener", name), zap.Error(err))
		}
	}(l.Name, l.Address, srv)
	return nil
}

// startHTTPListener configures and starts an HTTP listener.
func (s *Server) startHTTPListener(ctx context.Context, l config.ListenerConfig, srv *http.Server) {
	logger := log.FromContext(ctx)

	if proxyProtocolEnabled(l.ProxyProtocol) {
		if err := s.startHTTPProxyProtocol(ctx, l, srv, logger); err != nil {
			logger.Fatal("Failed to start HTTP listener with PROXY protocol", zap.String("listener", l.Name), zap.Error(err))
		}
		return
	}

	s.servers = append(s.servers, srv)
	go func(name, addr string, s *http.Server) {
		logger.Info("Starting HTTP server listener", zap.String("listener", name), zap.String("address", addr))
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Fatal HTTP server error", zap.String("listener", name), zap.Error(err))
		}
	}(l.Name, l.Address, srv)
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

	// Shut down standard HTTP servers.
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

	// Shut down TLS passthrough listeners.
	for _, p := range s.tlsPassthroughServers {
		wg.Add(1)
		go func(p *TLSPassThroughListener) {
			defer wg.Done()
			if err := p.Shutdown(); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Sprintf("tls passthrough server on %s shutdown error: %v", p.address, err))
				errMu.Unlock()
			}
		}(p)
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
