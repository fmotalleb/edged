package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fmotalleb/go-tools/log"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"

	"github.com/fmotalleb/edged/config"
	edgedtls "github.com/fmotalleb/edged/crypto/tls"
)

// TLSPassThroughListener is a TCP-level listener that provides both TLS
// passthrough (for routes with no_tls_termination enabled) and standard TLS
// termination (for normal routes) on the same port.
//
// It accepts raw TCP connections, reads the TLS ClientHello to extract the
// SNI (Server Name Indication), matches it against the configured routes,
// and then either:
//   - Pipes the raw encrypted bytes to the upstream server (passthrough)
//   - Terminates TLS and serves the HTTP request via the router (termination)
type TLSPassThroughListener struct {
	address   string
	routes    []config.RouteConfig
	handler   http.Handler
	tlsConfig *tls.Config
	baseCtx   context.Context
	cancel    context.CancelFunc
	listener  net.Listener
	mu        sync.Mutex
	wg        sync.WaitGroup

	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
}

// NewTLSPassThroughListener creates a new TLS-aware TCP listener.
func NewTLSPassThroughListener(
	ctx context.Context,
	addr string,
	routes []config.RouteConfig,
	handler http.Handler,
	tlsConfig *tls.Config,
	readTimeout, writeTimeout, idleTimeout time.Duration,
) *TLSPassThroughListener {
	ctx, cancel := context.WithCancel(ctx)
	return &TLSPassThroughListener{
		address:      addr,
		routes:       routes,
		handler:      handler,
		tlsConfig:    tlsConfig,
		baseCtx:      ctx,
		cancel:       cancel,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
		idleTimeout:  idleTimeout,
	}
}

// ListenAndServe starts the raw TCP listener and begins accepting connections.
func (l *TLSPassThroughListener) ListenAndServe() error {
	listener, err := net.Listen("tcp", l.address)
	if err != nil {
		return fmt.Errorf("tcp listen on %s: %w", l.address, err)
	}

	l.mu.Lock()
	l.listener = listener
	l.mu.Unlock()

	logger := log.FromContext(l.baseCtx)
	logger.Info("Starting TLS-aware proxy (passthrough + termination on same port)",
		zap.String("address", l.address))

	go func() {
		<-l.baseCtx.Done()
		l.mu.Lock()
		if l.listener != nil {
			l.listener.Close()
		}
		l.mu.Unlock()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if the listener was closed due to context cancellation.
			if l.baseCtx.Err() != nil {
				return nil //nolint:nilerr // normal shutdown
			}
			return fmt.Errorf("accept on %s: %w", l.address, err)
		}
		l.wg.Add(1)
		go l.handleConn(conn)
	}
}

// handleConn processes a single raw TCP connection by extracting the SNI,
// matching a route, and either proxying raw bytes or terminating TLS.
func (l *TLSPassThroughListener) handleConn(conn net.Conn) {
	defer l.wg.Done()
	defer conn.Close()

	logger := log.FromContext(l.baseCtx)

	// Read enough bytes to extract the SNI from the TLS ClientHello.
	peekBuf := make([]byte, 4096)

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		logger.Debug("Failed to set read deadline on incoming conn", zap.Error(err))
		return
	}
	n, err := conn.Read(peekBuf)
	if err != nil {
		logger.Debug("Failed to read ClientHello from incoming conn", zap.Error(err))
		return
	}
	// Clear the deadline once we have data.
	_ = conn.SetReadDeadline(time.Time{})

	data := peekBuf[:n]
	sni := edgedtls.ExtractSNI(data)

	host := ""
	if sni != nil {
		host = string(sni)
	}

	logger.Debug("Extracted SNI from connection",
		zap.String("sni", host),
		zap.Int("bytes_read", n))

	// Match against the configured routes.
	route, matched := matchRouteBySNI(host, l.routes)
	if !matched {
		logger.Warn("No route matched for SNI",
			zap.String("sni", host),
			zap.String("listener_addr", l.address))
		return
	}

	logger.Info("Routed connection via SNI",
		zap.String("sni", host),
		zap.String("route_host", route.Host),
		zap.Bool("passthrough", route.NoTLSTermination),
		zap.String("upstream", route.Upstream))

	// Wrap the connection so that the already-read bytes are replayed first.
	wrappedConn := &prependReaderConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(data), conn),
	}

	if route.NoTLSTermination {
		l.proxyTCP(wrappedConn, *route)
	} else {
		l.serveTLS(wrappedConn, *route)
	}
}

// prependReaderConn is a net.Conn wrapper that first reads from a prepended
// io.Reader (the buffered ClientHello bytes) and then from the underlying
// network connection.
type prependReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *prependReaderConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// proxyTCP performs a raw TCP proxy (TLS passthrough). It dials the upstream
// server and pipes data bidirectionally. The wrapped connection replays the
// ClientHello first, so the upstream TLS layer receives the complete handshake.
//
// If the route has upstream_socks5_proxy configured, the upstream connection
// is established through the SOCKS5 proxy instead of directly.
func (l *TLSPassThroughListener) proxyTCP(conn net.Conn, route config.RouteConfig) {
	logger := log.FromContext(l.baseCtx)

	// Parse upstream URL consistently with the rest of the codebase.
	upstreamURL, err := url.Parse(route.Upstream)
	if err != nil {
		logger.Error("Invalid upstream URL for TLS passthrough",
			zap.String("upstream", route.Upstream),
			zap.Error(err))
		return
	}

	// Use Host portion (host:port) for TCP dialing.
	upstreamAddr := upstreamURL.Host
	if upstreamAddr == "" {
		upstreamAddr = upstreamURL.Path // fallback for bare "host:port" strings
	}

	var upstream net.Conn
	if route.UpstreamSOCKS5Proxy != "" {
		// Dial via SOCKS5 proxy.
		proxyURL, proxyErr := url.Parse(route.UpstreamSOCKS5Proxy)
		if proxyErr != nil {
			logger.Error("Invalid upstream_socks5_proxy URL",
				zap.String("socks5_proxy", route.UpstreamSOCKS5Proxy),
				zap.Error(proxyErr))
			return
		}

		logger.Debug("TLS passthrough: dialing upstream via SOCKS5",
			zap.String("upstream", route.Upstream),
			zap.String("socks5_proxy", route.UpstreamSOCKS5Proxy))

		dialer, dialerErr := proxy.FromURL(proxyURL, proxy.Direct)
		if dialerErr != nil {
			logger.Error("Failed to create SOCKS5 dialer",
				zap.String("socks5_proxy", route.UpstreamSOCKS5Proxy),
				zap.Error(dialerErr))
			return
		}

		upstream, err = dialer.Dial("tcp", upstreamAddr)
	} else {
		upstream, err = net.DialTimeout("tcp", upstreamAddr, 10*time.Second)
	}
	if err != nil {
		logger.Error("Failed to connect to upstream for TLS passthrough",
			zap.String("upstream", route.Upstream),
			zap.String("socks5_proxy", route.UpstreamSOCKS5Proxy),
			zap.Error(err))
		return
	}
	defer upstream.Close()

	logger.Debug("TLS passthrough: proxying TCP connection",
		zap.String("upstream", route.Upstream),
		zap.String("host", route.Host))

	// Determine the passthrough idle timeout. The route's setting overrides the
	// default of 30s set by config defaults.
	idleTimeout := route.PassthroughIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}

	// Use context-aware copy so shutdown cancels in-flight transfers.
	// A read deadline is periodically applied so that a blocked Read() does
	// not prevent goroutine shutdown when the context is cancelled.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := l.copyContext(l.baseCtx, upstream, conn, idleTimeout); err != nil && err != io.EOF && err != context.Canceled {
			logger.Debug("TLS passthrough upstream write error", zap.Error(err))
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := l.copyContext(l.baseCtx, conn, upstream, idleTimeout); err != nil && err != io.EOF && err != context.Canceled {
			logger.Debug("TLS passthrough downstream write error", zap.Error(err))
		}
	}()

	wg.Wait()
}

// copyContext copies from src to dst until either EOF is reached on src,
// an error occurs, or ctx is cancelled. It returns the number of bytes
// copied and the first error encountered.
//
// idleTimeout controls how long the copy waits between reads before
// treating the connection as idle. A timeout fires the read deadline,
// which wakes up the loop to check ctx.Done() for graceful shutdown.
// If idleTimeout is zero, no read deadline is set (no idle timeout).
func (l *TLSPassThroughListener) copyContext(ctx context.Context, dst io.Writer, src io.Reader, idleTimeout time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64

	// If src supports deadlines, apply the idle timeout periodically.
	srcConn, canDeadline := src.(net.Conn)

	for {
		// Apply a read deadline so a blocked Read() unblocks periodically
		// and the ctx.Done() check below takes effect.
		if canDeadline && idleTimeout > 0 {
			_ = srcConn.SetReadDeadline(time.Now().Add(idleTimeout))
		}

		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}

		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			written += int64(nw)
			if werr != nil {
				return written, werr
			}
		}
		if rerr != nil {
			// Timeout errors are expected when a deadline expires;
			// loop back and check ctx.Done() instead of returning.
			if isTimeoutError(rerr) {
				continue
			}
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

// isTimeoutError reports whether err is a net.Error with Timeout() == true.
func isTimeoutError(err error) bool {
	e, ok := err.(net.Error)
	return ok && e.Timeout()
}

// serveTLS terminates TLS on the connection and serves the HTTP request through
// the router handler. The wrapped connection replays the ClientHello so the
// tls.Server can complete the handshake.
func (l *TLSPassThroughListener) serveTLS(conn net.Conn, _ config.RouteConfig) {
	if l.handler == nil || l.tlsConfig == nil {
		log.FromContext(l.baseCtx).Warn("Cannot serve TLS: handler or TLS config is nil")
		return
	}

	tlsConn := tls.Server(conn, l.tlsConfig)

	if err := tlsConn.Handshake(); err != nil {
		log.FromContext(l.baseCtx).Debug("TLS handshake failed", zap.Error(err))
		return
	}

	// Serve the single TLS-wrapped connection through the router handler.
	// We use a minimal http.Server with the listener's configured timeouts
	// to prevent slow-client attacks.
	srv := &http.Server{
		Handler:      l.handler,
		ReadTimeout:  l.readTimeout,
		WriteTimeout: l.writeTimeout,
		IdleTimeout:  l.idleTimeout,
		BaseContext: func(_ net.Listener) context.Context {
			return l.baseCtx
		},
	}
	_ = srv.Serve(&singleConnListener{conn: tlsConn})
}

// singleConnListener wraps a single net.Conn as a net.Listener that yields
// exactly one connection then closes.
type singleConnListener struct {
	conn net.Conn
	used bool
	mu   sync.Mutex
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used || l.conn == nil {
		return nil, fmt.Errorf("listener closed")
	}
	l.used = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// matchRouteBySNI finds the route whose host matches the given SNI hostname.
// It supports exact matching and wildcard (*.example.com) matching.
func matchRouteBySNI(host string, routes []config.RouteConfig) (*config.RouteConfig, bool) {
	host = strings.ToLower(strings.TrimSpace(host))

	for i := range routes {
		if matchHostShared(host, routes[i].Host) {
			return &routes[i], true
		}
	}
	return nil, false
}

// matchHostShared checks if requestHost matches routeHost, supporting exact
// match, wildcard "*", and glob pattern "*.example.com".
func matchHostShared(requestHost, routeHost string) bool {
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

// Shutdown stops the listener and waits for all active connections to finish.
func (l *TLSPassThroughListener) Shutdown() error {
	l.cancel()

	l.mu.Lock()
	if l.listener != nil {
		l.listener.Close()
	}
	l.mu.Unlock()

	l.wg.Wait()
	return nil
}

// hasPassthroughRoutes returns true if any route in the list has
// no_tls_termination enabled.
func hasPassthroughRoutes(routes []config.RouteConfig) bool {
	for i := range routes {
		if routes[i].NoTLSTermination {
			return true
		}
	}
	return false
}
