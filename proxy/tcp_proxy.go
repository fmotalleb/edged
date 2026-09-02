package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fmotalleb/go-tools/log"
	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"

	"github.com/fmotalleb/edged/config"
	edgedtls "github.com/fmotalleb/edged/crypto/tls"
)

// proxyProtocolEnabled reports whether the proxy_protocol config value is
// set to a valid version ("1" or "2"). The default "none" means disabled.
func proxyProtocolEnabled(pp string) bool {
	return pp == "1" || pp == "2"
}

// proxyProtocolVersion parses the proxy_protocol config string and returns
// the integer version (1 or 2). Returns 0 if the value is invalid.
func proxyProtocolVersion(pp string) int {
	v, _ := strconv.Atoi(pp)
	if v != 1 && v != 2 {
		return 0
	}
	return v
}

const (
	// defaultPassthroughIdleTimeout is the fallback idle timeout when the route
	// does not configure passthrough_idle_timeout.
	defaultPassthroughIdleTimeout = 30 * time.Second

	// defaultUpstreamDialTimeout is the timeout for dialing the upstream
	// connection in TLS passthrough mode.
	defaultUpstreamDialTimeout = 10 * time.Second
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
	address       string
	routes        []config.RouteConfig
	handler       http.Handler
	tlsConfig     *tls.Config
	baseCtx       context.Context
	cancel        context.CancelFunc
	listener      net.Listener
	mu            sync.Mutex
	wg            sync.WaitGroup
	proxyProtocol string // "none", "1", or "2"

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
	proxyProtocol string,
) *TLSPassThroughListener {
	ctx, cancel := context.WithCancel(ctx)
	return &TLSPassThroughListener{
		address:       addr,
		routes:        routes,
		handler:       handler,
		tlsConfig:     tlsConfig,
		baseCtx:       ctx,
		cancel:        cancel,
		readTimeout:   readTimeout,
		writeTimeout:  writeTimeout,
		idleTimeout:   idleTimeout,
		proxyProtocol: proxyProtocol,
	}
}

// ListenAndServe starts the raw TCP listener and begins accepting connections.
func (l *TLSPassThroughListener) ListenAndServe() error {
	listener, err := (&net.ListenConfig{}).Listen(l.baseCtx, "tcp", l.address)
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
			_ = l.listener.Close()
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
//
// When proxy protocol inbound is enabled on the listener, the connection is
// first wrapped to detect and parse PROXY protocol v1/v2 headers from
// upstream load balancers (e.g., HAProxy, AWS NLB). The real client address
// extracted from the header is then forwarded to upstream servers when
// proxy_protocol_outbound is enabled on the matched route.
func (l *TLSPassThroughListener) handleConn(conn net.Conn) {
	defer l.wg.Done()
	defer conn.Close()

	logger := log.FromContext(l.baseCtx)

	// Optionally wrap the connection to detect and parse PROXY protocol
	// v1/v2 headers from an upstream load balancer. After wrapping, the
	// first Read() on rawConn automatically skips the PROXY protocol header
	// and RemoteAddr() returns the real client address.
	rawConn := conn
	if proxyProtocolEnabled(l.proxyProtocol) {
		rawConn = proxyproto.NewConn(conn)
	}

	// Read enough bytes to extract the SNI from the TLS ClientHello.
	peekBuf := make([]byte, 4096)

	if err := rawConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		logger.Debug("Failed to set read deadline on incoming conn", zap.Error(err))
		return
	}
	n, err := rawConn.Read(peekBuf)
	if err != nil {
		logger.Debug("Failed to read ClientHello from incoming conn", zap.Error(err))
		return
	}
	// Clear the deadline once we have data.
	_ = rawConn.SetReadDeadline(time.Time{})

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

	// Extract the real client address. When proxy protocol inbound is
	// enabled, this is the address carried by the PROXY protocol header.
	// Otherwise it is the direct peer address.
	clientAddr := rawConn.RemoteAddr()

	// Wrap the connection so that the already-read bytes are replayed first.
	wrappedConn := &prependReaderConn{
		Conn:   rawConn,
		reader: io.MultiReader(bytes.NewReader(data), rawConn),
	}

	if route.NoTLSTermination {
		l.proxyTCP(wrappedConn, *route, clientAddr)
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

// dialUpstream establishes a TCP connection to the upstream server.
// When upstreamSOCKS5Proxy is set, the connection is tunneled through the
// SOCKS5 proxy; otherwise a direct dial is used.
func (l *TLSPassThroughListener) dialUpstream(upstream, upstreamSOCKS5Proxy string) (net.Conn, error) {
	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL '%s': %w", upstream, err)
	}

	// Use Host portion (host:port) for TCP dialing.
	upstreamAddr := upstreamURL.Host
	if upstreamAddr == "" {
		upstreamAddr = upstreamURL.Path // fallback for bare "host:port" strings
	}

	if upstreamSOCKS5Proxy != "" {
		proxyURL, proxyErr := url.Parse(upstreamSOCKS5Proxy)
		if proxyErr != nil {
			return nil, fmt.Errorf("invalid upstream_socks5_proxy '%s': %w", upstreamSOCKS5Proxy, proxyErr)
		}
		dialer, dialerErr := proxy.FromURL(proxyURL, proxy.Direct)
		if dialerErr != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer for '%s': %w", upstreamSOCKS5Proxy, dialerErr)
		}
		return dialer.Dial("tcp", upstreamAddr)
	}

	return (&net.Dialer{Timeout: defaultUpstreamDialTimeout}).DialContext(l.baseCtx, "tcp", upstreamAddr)
}

// proxyTCP performs a raw TCP proxy (TLS passthrough). It dials the upstream
// server and pipes data bidirectionally. The wrapped connection replays the
// ClientHello first, so the upstream TLS layer receives the complete handshake.
//
// If the route has upstream_socks5_proxy configured, the upstream connection
// is established through the SOCKS5 proxy instead of directly.
func (l *TLSPassThroughListener) proxyTCP(conn net.Conn, route config.RouteConfig, clientAddr net.Addr) {
	logger := log.FromContext(l.baseCtx)

	upstream, err := l.dialUpstream(route.Upstream, route.UpstreamSOCKS5Proxy)
	if err != nil {
		logger.Error("Failed to connect to upstream for TLS passthrough",
			zap.String("upstream", route.Upstream),
			zap.String("socks5_proxy", route.UpstreamSOCKS5Proxy),
			zap.Error(err))
		return
	}
	defer upstream.Close()

	// If proxy protocol outbound is enabled on the route, send a PROXY
	// protocol header to the upstream server before piping application data.
	// The header carries the real client address extracted from the inbound
	// connection (either from a PROXY protocol header or the direct peer).
	if proxyProtocolEnabled(route.ProxyProtocol) {
		version := proxyProtocolVersion(route.ProxyProtocol)
		if err := sendProxyProtocolHeader(upstream, clientAddr, version); err != nil {
			logger.Error("Failed to send PROXY protocol header to upstream",
				zap.String("upstream", route.Upstream),
				zap.String("version", route.ProxyProtocol),
				zap.Error(err))
			return
		}
		logger.Debug("Sent PROXY protocol header to upstream",
			zap.String("upstream", route.Upstream),
			zap.Int("version", version),
			zap.String("client_addr", clientAddr.String()))
	}

	logger.Debug("TLS passthrough: proxying TCP connection",
		zap.String("upstream", route.Upstream),
		zap.String("host", route.Host))

	// Determine the passthrough idle timeout. The route's setting overrides the
	// default of 30s set by config defaults.
	idleTimeout := route.PassthroughIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultPassthroughIdleTimeout
	}

	// Use context-aware copy so shutdown cancels in-flight transfers.
	// A read deadline is periodically applied so that a blocked Read() does
	// not prevent goroutine shutdown when the context is canceled.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := l.copyContext(l.baseCtx, upstream, conn, idleTimeout); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
			logger.Debug("TLS passthrough upstream write error", zap.Error(err))
		}
	}()
	go func() {
		defer wg.Done()
		if err := l.copyContext(l.baseCtx, conn, upstream, idleTimeout); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
			logger.Debug("TLS passthrough downstream write error", zap.Error(err))
		}
	}()

	wg.Wait()
}

// copyContext copies from src to dst until either EOF is reached on src,
// an error occurs, or ctx is canceled. It returns the number of bytes
// copied and the first error encountered.
//
// idleTimeout controls how long the copy waits between reads before
// treating the connection as idle. A timeout fires the read deadline,
// which wakes up the loop to check ctx.Done() for graceful shutdown.
// If idleTimeout is zero, no read deadline is set (no idle timeout).
func (l *TLSPassThroughListener) copyContext(ctx context.Context, dst io.Writer, src io.Reader, idleTimeout time.Duration) error {
	buf := make([]byte, 32*1024)

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
			return ctx.Err()
		default:
		}

		nr, rerr := src.Read(buf)
		if nr > 0 {
			if _, werr := dst.Write(buf[:nr]); werr != nil {
				return werr
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
			return rerr
		}
	}
}

// isTimeoutError reports whether err is a net.Error with Timeout() == true.
func isTimeoutError(err error) bool {
	var e net.Error
	ok := errors.As(err, &e)
	return ok && e.Timeout()
}

// sendProxyProtocolHeader writes a PROXY protocol header (v1 or v2) to the
// given connection, carrying the source (client) and destination (upstream)
// addresses. This should be called immediately after establishing the upstream
// connection, before any application data is sent.
//
// Version 1 sends a human-readable ASCII header:
//
//	PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n
//
// Version 2 sends a binary header with additional proxy information.
func sendProxyProtocolHeader(conn net.Conn, clientAddr net.Addr, version int) error {
	upstreamAddr := conn.RemoteAddr()

	header := proxyproto.HeaderProxyFromAddrs(uint8(version), clientAddr, upstreamAddr) //nolint:gosec // version is validated to 1 or 2 by proxyProtocolVersion
	_, err := header.WriteTo(conn)
	return err
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

	if err := tlsConn.HandshakeContext(l.baseCtx); err != nil {
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
		return nil, errors.New("listener closed")
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
		_ = l.listener.Close()
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
