package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fmotalleb/go-tools/log"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"

	"github.com/fmotalleb/edged/config"
)

// ProxyRouter manages routing rules and ReverseProxy instances for a listener.
type ProxyRouter struct {
	listenerName string
	protocol     string
	routes       []routeEntry
	mu           sync.RWMutex
}

type routeEntry struct {
	config  config.RouteConfig
	target  *url.URL
	handler *httputil.ReverseProxy
}

// NewProxyRouter builds a proxy router with dedicated reverse proxies for each route.
func NewProxyRouter(ctx context.Context, listenerName, protocol string, routes []config.RouteConfig) (*ProxyRouter, error) {
	logger := log.FromContext(ctx)
	r := &ProxyRouter{
		listenerName: listenerName,
		protocol:     protocol,
	}

	for i, rc := range routes {
		targetURL, err := url.Parse(rc.Upstream)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream URL '%s' for route[%d]: %w", rc.Upstream, i, err)
		}

		// Configure custom transport with aggressive timeout thresholds
		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		// Upgrade to explicit SOCKS5 socket dialing if upstream_socks5_proxy is configured
		if rc.UpstreamSOCKS5Proxy != "" {
			proxyURL, err := url.Parse(rc.UpstreamSOCKS5Proxy)
			if err != nil {
				return nil, fmt.Errorf("invalid upstream_socks5_proxy '%s' for route[%d]: %w", rc.UpstreamSOCKS5Proxy, i, err)
			}
			logger.Info("Configuring route to use SOCKS5 upstream tunnel",
				zap.String("listener", listenerName),
				zap.String("host", rc.Host),
				zap.String("path_prefix", rc.PathPrefix),
				zap.String("upstream", rc.Upstream),
				zap.String("socks5_proxy", rc.UpstreamSOCKS5Proxy))

			dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize SOCKS5 dialer for route[%d]: %w", i, err)
			}

			// Ensure HTTP transport dials directly via the SOCKS5 TCP connection without HTTP CONNECT attempts
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				transport.DialContext = contextDialer.DialContext
			} else {
				transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				}
			}
			transport.Proxy = nil
		}

		proxyHandler := httputil.NewSingleHostReverseProxy(targetURL)
		proxyHandler.Transport = transport
		proxyHandler.ErrorHandler = r.createErrorHandler(rc)
		proxyHandler.Director = r.createDirector(targetURL, rc, proxyHandler.Director)

		r.routes = append(r.routes, routeEntry{
			config:  rc,
			target:  targetURL,
			handler: proxyHandler,
		})
	}

	return r, nil
}

// ServeHTTP handles incoming requests, matching host and path prefix to the best route.
func (r *ProxyRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logger := log.FromContext(req.Context())
	host := req.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	host = strings.ToLower(strings.TrimSpace(host))
	path := req.URL.Path

	r.mu.RLock()
	var bestMatch *routeEntry
	bestPrefixLen := -1

	for i := range r.routes {
		entry := &r.routes[i]
		if r.matchHost(host, entry.config.Host) {
			if strings.HasPrefix(path, entry.config.PathPrefix) {
				prefixLen := len(entry.config.PathPrefix)
				if prefixLen > bestPrefixLen {
					bestPrefixLen = prefixLen
					bestMatch = entry
				}
			}
		}
	}
	r.mu.RUnlock()

	if bestMatch == nil {
		logger.Warn("404 No route matched for request",
			zap.String("listener", r.listenerName),
			zap.String("host", host),
			zap.String("path", path))
		http.Error(w, fmt.Sprintf("404 Not Found: No reverse proxy route configured for host '%s'", host), http.StatusNotFound)
		return
	}

	// Apply request timeout if configured
	if bestMatch.config.Timeout > 0 {
		ctx, cancel := context.WithTimeout(req.Context(), bestMatch.config.Timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	bestMatch.handler.ServeHTTP(w, req)
}

// matchHost checks exact host matching and wildcard (*.example.com) matching.
func (r *ProxyRouter) matchHost(requestHost, routeHost string) bool {
	routeHost = strings.ToLower(strings.TrimSpace(routeHost))
	if routeHost == "" || routeHost == "*" || requestHost == routeHost {
		return true
	}

	if strings.HasPrefix(routeHost, "*.") {
		domainSuffix := routeHost[1:] // e.g., ".example.com"
		if strings.HasSuffix(requestHost, domainSuffix) {
			return true
		}
	}

	return false
}

// createDirector wraps the default Director to inject custom headers and strip prefixes.
func (r *ProxyRouter) createDirector(target *url.URL, rc config.RouteConfig, defaultDirector func(*http.Request)) func(*http.Request) {
	return func(req *http.Request) {
		defaultDirector(req)

		// Set standard forwarding headers
		req.Header.Set("X-Forwarded-Proto", r.protocol)
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
				req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
			} else {
				req.Header.Set("X-Forwarded-For", clientIP)
			}
			req.Header.Set("X-Real-IP", clientIP)
		}

		// Inject custom headers from configuration
		for k, v := range rc.CustomHeaders {
			req.Header.Set(k, v)
		}

		// Strip path prefix if requested
		if rc.StripPrefix && rc.PathPrefix != "/" && rc.PathPrefix != "" {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, rc.PathPrefix)
			if !strings.HasPrefix(req.URL.Path, "/") {
				req.URL.Path = "/" + req.URL.Path
			}
			req.URL.RawPath = ""
		}

		// Preserve target host header or override
		req.Host = target.Host
	}
}

// createErrorHandler handles upstream connection failures and timeouts gracefully.
func (r *ProxyRouter) createErrorHandler(rc config.RouteConfig) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		logger := log.FromContext(req.Context())
		logger.Error("Proxy forwarding error to upstream",
			zap.String("listener", r.listenerName),
			zap.String("upstream", rc.Upstream),
			zap.String("socks5_proxy", rc.UpstreamSOCKS5Proxy),
			zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `{"error": "502 Bad Gateway", "message": "Failed to reach upstream service", "upstream": "%s", "socks5_proxy": "%s"}`, rc.Upstream, rc.UpstreamSOCKS5Proxy)
	}
}
