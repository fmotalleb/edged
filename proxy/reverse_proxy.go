package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/fmotalleb/go-tools/log"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"

	"github.com/fmotalleb/edged/config"
)

// Router manages routing rules and ReverseProxy instances for a listener.
type Router struct {
	listenerName string
	protocol     string
	routes       []routeEntry
	mu           sync.RWMutex

	// baseCtx is the context the server/listener was started with. Every
	// request handled by this router is tied to it, so that shutting down
	// the server (canceling baseCtx) cancels in-flight proxied requests too.
	baseCtx context.Context
}

type routeEntry struct {
	config  config.RouteConfig
	target  *url.URL
	handler *httputil.ReverseProxy
}

// NewProxyRouter builds a proxy router with dedicated reverse proxies for each route.
// ctx is the server's lifetime context; it is used both for logging during setup
// and as the parent context for every request the router later handles.
func NewProxyRouter(ctx context.Context, listenerName, protocol string, routes []config.RouteConfig) (*Router, error) {
	logger := log.FromContext(ctx)
	r := &Router{
		listenerName: listenerName,
		protocol:     protocol,
		baseCtx:      ctx,
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
				Timeout:   rc.DialerTimeout,
				KeepAlive: rc.DialerKeepalive,
			}).DialContext,
			ForceAttemptHTTP2:     rc.ForceAttemptHTTP2,
			MaxIdleConns:          rc.MaxIdleConns,
			IdleConnTimeout:       rc.IdleConnTimeout,
			TLSHandshakeTimeout:   rc.TLSHandshakeTimeout,
			ExpectContinueTimeout: rc.ExpectContinueTimeout,
			TLSClientConfig:       upstreamTLSConfig(rc.VerifySSL),
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
				transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				}
			}
			transport.Proxy = nil
		}

		// NOTE: We intentionally build *httputil.ReverseProxy directly instead of
		// using httputil.NewSingleHostReverseProxy, which sets the legacy Director
		// field. ReverseProxy panics if both Director and Rewrite are set, and we
		// need Rewrite so we can read pr.In and correctly mutate pr.Out (the
		// request that's actually sent upstream).
		proxyHandler := &httputil.ReverseProxy{
			Transport:    transport,
			Rewrite:      r.createDirector(targetURL, rc),
			ErrorHandler: r.createErrorHandler(rc),
		}

		r.routes = append(r.routes, routeEntry{
			config:  rc,
			target:  targetURL,
			handler: proxyHandler,
		})
	}

	return r, nil
}

// ServeHTTP handles incoming requests, matching host and path prefix to the best route.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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

	// Tie this request's context to the server's lifetime context, so that
	// shutting down the server cancels any requests still being proxied.
	ctx, cancel := r.deriveContext(req.Context())
	defer cancel()
	req = req.WithContext(ctx)

	// Apply request timeout if configured
	if bestMatch.config.Timeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(req.Context(), bestMatch.config.Timeout)
		defer timeoutCancel()
		req = req.WithContext(ctx)
	}

	bestMatch.handler.ServeHTTP(w, req)
}

// deriveContext returns a context that carries reqCtx's values/deadline but is
// also canceled if the router's baseCtx (the server's lifetime context) is
// canceled first - e.g. on graceful shutdown.
func (r *Router) deriveContext(reqCtx context.Context) (context.Context, context.CancelFunc) {
	if r.baseCtx == nil {
		return reqCtx, func() {}
	}

	ctx, cancel := context.WithCancel(reqCtx)
	stop := context.AfterFunc(r.baseCtx, cancel)

	return ctx, func() {
		stop()
		cancel()
	}
}

// matchHost checks exact host matching and wildcard (*.example.com) matching.
func (r *Router) matchHost(requestHost, routeHost string) bool {
	return matchHostShared(requestHost, routeHost)
}

// createDirector returns a Rewrite function for ReverseProxy. It reads the
// original request from pr.In and mutates the outbound clone pr.Out - pr.Out
// is what actually gets sent upstream, so all header/path/host changes must
// be applied there.
func (r *Router) createDirector(target *url.URL, rc config.RouteConfig) func(*httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		// Equivalent of the legacy Director: sets scheme/host and joins the
		// target's path with the incoming request's path onto pr.Out.URL.
		pr.SetURL(target)

		out := pr.Out
		in := pr.In

		// Set standard forwarding headers
		out.Header.Set("X-Forwarded-Proto", r.protocol)
		if clientIP, _, err := net.SplitHostPort(in.RemoteAddr); err == nil {
			if prior := in.Header.Get("X-Forwarded-For"); prior != "" {
				out.Header.Set("X-Forwarded-For", prior+", "+clientIP)
			} else {
				out.Header.Set("X-Forwarded-For", clientIP)
			}
			out.Header.Set("X-Real-IP", clientIP)
		}

		// Inject custom headers from configuration
		for k, v := range rc.CustomHeaders {
			out.Header.Set(k, v)
		}

		// Strip path prefix if requested
		if rc.StripPrefix && rc.PathPrefix != "/" && rc.PathPrefix != "" {
			out.URL.Path = strings.TrimPrefix(out.URL.Path, rc.PathPrefix)
			if !strings.HasPrefix(out.URL.Path, "/") {
				out.URL.Path = "/" + out.URL.Path
			}
			out.URL.RawPath = ""
		}

		// Preserve request host header or override
		out.Host = in.Host
	}
}

// upstreamTLSConfig creates the TLS client config for upstream connections.
// It disables certificate verification when verifySSL is explicitly set to false.
func upstreamTLSConfig(verifySSL *bool) *tls.Config {
	if verifySSL != nil && !*verifySSL {
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		}
	}
	return nil
}

// createErrorHandler handles upstream connection failures and timeouts gracefully.
func (r *Router) createErrorHandler(rc config.RouteConfig) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		logger := log.FromContext(req.Context())
		logger.Error("Proxy forwarding error to upstream",
			zap.String("listener", r.listenerName),
			zap.String("upstream", rc.Upstream),
			zap.String("socks5_proxy", rc.UpstreamSOCKS5Proxy),
			zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Error-Source", "edge")
		w.WriteHeader(http.StatusBadGateway)
		errResponse := map[string]any{
			"error":   "502 Bad Gateway",
			"message": "Failed to reach upstream service",
			"client":  strings.Split(req.RemoteAddr, ":")[0],
		}
		if rc.Debug {
			errResponse["upstream"] = rc.Upstream
			if rc.UpstreamSOCKS5Proxy != "" {
				errResponse["socks5_proxy"] = rc.UpstreamSOCKS5Proxy
			} else {
				errResponse["socks5_proxy"] = "none"
			}
		}
		body, err := json.Marshal(errResponse)
		if err != nil {
			logger.Warn("Failed to marshal upstream error response", zap.Error(err))
			fmt.Fprint(w, "Server Error!")
		}
		if _, err = w.Write(body); err != nil {
			logger.Warn("Failed to write error response to user", zap.Error(err))
		}
	}
}
