# Golang Reverse Proxy with ACME TLS & DNS-01 Wildcard Support

A production-grade, high-performance Golang web server designed specifically to **always act as a reverse proxy**. It features automated TLS certificate acquisition and renewal via **Let's Encrypt (ACME v2)**, comprehensive **SOCKS5 proxy tunneling** across all layers (Let's Encrypt API, DNS challenge APIs, and upstream backends), and first-class integration with **ArvanCloud CDN** and **Cloudflare** for generating **wildcard certificates (`*.example.com`)** via the DNS-01 challenge.

---

## 🌟 Key Features

1. **Dedicated Reverse Proxy Architecture**:
   - Built on Go's robust `httputil.ReverseProxy` engine with custom timeout thresholds.
   - **Virtual Host Routing**: Exact host match (`example.com`), wildcard subdomain match (`*.example.com`), and fallback routing.
   - **Path Prefix Routing**: Longest prefix matching with optional path prefix stripping (`strip_prefix: true`).
   - **Standard & Custom Header Injection**: Automatic handling of `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP`, plus user-defined custom headers.
   - **HTTP $\rightarrow$ HTTPS Redirection**: Configurable redirector on HTTP port 80.

2. **Comprehensive SOCKS5 Proxy Support Across All Layers**:
   - **Upstream Reverse Proxy Tunneling**: Uses `golang.org/x/net/proxy` to establish explicit SOCKS5 TCP socket connections to backend services. Whether your backend is HTTP, HTTPS, or upgraded WebSockets, traffic dials cleanly through your SOCKS5 proxy without proxy-header interference.
   - **Hierarchical Inheritance**: Configure a SOCKS5 proxy globally (`default_upstream_socks5_proxy`), override it per listener (`upstream_socks5_proxy`), or specialize it per route.
   - **ACME & DNS API Tunneling**: Route Let's Encrypt account validation and DNS provider API calls (`https://api.cloudflare.com` or `https://napi.arvancloud.ir`) through your SOCKS5 proxy (`acme.socks5_proxy` and `use_socks5: true`).

3. **Automated TLS Handling via Let's Encrypt (ACME v2)**:
   - Uses `github.com/go-acme/lego/v4` for reliable ACME v2 communication.
   - **On-Demand & Startup Acquisition**: Validates and acquires missing certificates on boot and during TLS handshakes without blocking active traffic.
   - **Background Renewal Daemon**: Automatically checks and renews certificates when they enter the renewal window (default: 30 days remaining).
   - **Disk & Memory Caching**: Persists certificates and ECDSA account keys securely to disk (`acme_storage/`).

4. **Multi-Provider DNS-01 Challenge Support (Wildcard Certificates)**:
   - **Cloudflare DNS**: Implements Let's Encrypt DNS-01 challenges via Cloudflare v4 API using scoped API tokens (`CLOUDFLARE_DNS_API_TOKEN`) or legacy global API keys.
   - **ArvanCloud CDN DNS**: Integrated with ArvanCloud API (`ARVANCLOUD_API_KEY`) for seamless TXT record creation and cleanup.
   - Automatically generates wildcard certificates (`*.example.com`) without manual intervention.

---

## ⚙️ Configuration Structure (`config.yaml`)

The configuration file is structured cleanly around network **`listeners:`** and global **`acme:`** settings.

### Example Configuration

```yaml
# Global default SOCKS5 proxy for connecting to upstream backends.
# Can be overridden per listener or per individual route.
default_upstream_socks5_proxy: "" # e.g., "socks5://127.0.0.1:1080"

listeners:
  # HTTP Listener (Port 80) - Redirects traffic to HTTPS
  - name: "http-listener"
    address: "0.0.0.0:80"
    protocol: "http"
    redirect_to_https: true
    routes:
      - host: "example.com"
        path_prefix: "/"
        upstream: "http://127.0.0.1:8080"

  # HTTPS Listener (Port 443) - Reverse Proxy with Automated ACME Wildcard TLS
  - name: "https-listener"
    address: "0.0.0.0:443"
    protocol: "https"
    # Optional listener-level SOCKS5 proxy for all routes under this listener
    upstream_socks5_proxy: ""
    tls:
      enabled: true
      use_acme: true
      domains:
        - "example.com"
        - "*.example.com"
        - "cdn.example.org"
        - "*.cdn.example.org"
    routes:
      # Route 1: Exact host matching to main application
      - host: "example.com"
        path_prefix: "/"
        upstream: "http://127.0.0.1:8080"
        strip_prefix: false
        timeout: 30s
        custom_headers:
          X-Proxy-Engine: "Go-Advanced-Proxy"

      # Route 2: API endpoint with path stripping
      - host: "api.example.com"
        path_prefix: "/v1"
        upstream: "http://127.0.0.1:3000"
        strip_prefix: false

      # Route 3: Wildcard subdomain routing via SOCKS5 Upstream Proxy
      - host: "*.example.com"
        path_prefix: "/"
        upstream: "http://10.0.0.10:8081"
        # Route-level SOCKS5 tunnel: establishes TCP connection to 10.0.0.10:8081 via SOCKS5
        upstream_socks5_proxy: "socks5://user:pass@127.0.0.1:1080"

# Global ACME Let's Encrypt Configuration
acme:
  email: "admin@example.com"
  directory_url: "https://acme-v02.api.letsencrypt.org/directory"
  
  # Route Let's Encrypt requests through SOCKS5 proxy (leave empty for direct connection)
  socks5_proxy: "socks5://127.0.0.1:1080"
  
  storage_path: "./acme_storage"
  renew_before_days: 30
  check_interval_hours: 24

  # DNS-01 Challenge Provider Configuration for Wildcard Certificates
  dns_provider:
    # Supported providers: "arvancloud" or "cloudflare"
    name: "cloudflare"       # Switch between providers easily
    use_socks5: true         # Also route DNS API requests via socks5_proxy

    # 1. ArvanCloud Configuration
    arvancloud:
      api_key: "Apikey xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" # Or ARVANCLOUD_API_KEY env var
      propagation_timeout: 120
      polling_interval: 2
      ttl: 600

    # 2. Cloudflare Configuration
    cloudflare:
      # Recommended: Scoped API Token with Zone:Read and DNS:Edit permissions
      # Can also be provided via CLOUDFLARE_DNS_API_TOKEN environment variable
      api_token: "your_cloudflare_dns_api_token_here"
      zone_token: ""           # Optional if permissions are split across tokens
      
      # Legacy Authentication (Use ONLY if api_token above is empty)
      auth_email: ""           # Or CLOUDFLARE_EMAIL env var
      auth_key: ""             # Or CLOUDFLARE_API_KEY env var

      propagation_timeout: 120
      polling_interval: 2
      ttl: 300
```

---

## 🔐 How SOCKS5 Reverse Proxy Tunneling Works

When `upstream_socks5_proxy` is specified on a route, listener, or globally:
1. The proxy engine parses the URL (`socks5://user:password@host:port`) and creates an explicit SOCKS5 socket dialer via `golang.org/x/net/proxy`.
2. The reverse proxy's custom `http.Transport` overrides its `DialContext` with the SOCKS5 dialer and disables standard HTTP proxy headers (`transport.Proxy = nil`).
3. When an incoming request (HTTP/1.1, HTTP/2, or WebSocket upgrade) matches the route, Go connects directly to your SOCKS5 server, authenticates, and requests a TCP stream to your target upstream address (`http://10.0.0.10:8081`).
4. Traffic flows seamlessly through the encrypted/tunneled SOCKS5 connection.

---

## 🔐 How Wildcard Certificate Generation Works

To issue a wildcard certificate (`*.example.com`), Let's Encrypt requires domain verification via the **DNS-01 challenge**.

1. **Challenge Initialization**: When requesting a certificate for `*.example.com`, Let's Encrypt issues a DNS challenge token.
2. **TXT Record Creation**: The server uses either the Cloudflare API (`https://api.cloudflare.com/client/v4/zones/.../dns_records`) or ArvanCloud API (`https://napi.arvancloud.ir/...`) to create a DNS TXT record at `_acme-challenge.example.com`.
3. **SOCKS5 Proxy Routing**: If `acme.dns_provider.use_socks5` is enabled, all DNS provider API calls are tunneled through `acme.socks5_proxy`.
4. **Propagation Verification**: The server queries public recursive DNS resolvers (`8.8.8.8:53` and `1.1.1.1:53`) every `polling_interval` seconds until the TXT record propagates globally.
5. **Challenge Finalization**: Once verified, Let's Encrypt issues the TLS certificate bundle. The server downloads the certificates over SOCKS5, persists them to `./acme_storage/certs/`, loads them into active memory, and cleans up the DNS TXT record.

---

## 🚀 Building & Running

### 1. Local Development (Using Go / Makefile)

```bash
# Tidy modules and download dependencies
make tidy

# Build the executable
make build

# Validate your configuration YAML
make validate

# Run the reverse proxy
make run
```

### 2. Running with Docker

Build the Docker image:
```bash
make docker-build
```

Run the container (example with Cloudflare API Token):
```bash
docker run -d \
  --name edged \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -v $(pwd)/acme_storage:/app/acme_storage \
  -e CLOUDFLARE_DNS_API_TOKEN="your_cloudflare_token_here" \
  arvan-acme-proxy:latest
```

---

## 🛠️ Environment Variable Overrides

You can keep sensitive API tokens out of your YAML file by setting these environment variables:

| Environment Variable | Provider | Description |
| :--- | :--- | :--- |
| `ARVANCLOUD_API_KEY` | ArvanCloud | Format: `"Apikey xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` |
| `CLOUDFLARE_DNS_API_TOKEN` | Cloudflare | Scoped API token with `DNS:Edit` and `Zone:Read` permissions |
| `CLOUDFLARE_ZONE_API_TOKEN` | Cloudflare | Scoped zone token (if permissions are split across two tokens) |
| `CLOUDFLARE_EMAIL` | Cloudflare | Legacy account email address (used with `CLOUDFLARE_API_KEY`) |
| `CLOUDFLARE_API_KEY` | Cloudflare | Legacy global API key |
