# edged - Golang Reverse Proxy with ACME TLS & DNS-01 Wildcard Support

`edged` (`github.com/fmotalleb/edged`) is a production-grade, high-performance Golang web server designed specifically to **always act as a reverse proxy**. Built with **Cobra CLI**, structured **zap logging from context** (`github.com/fmotalleb/go-tools/log`), and robust **mapstructure configuration parsing** (`github.com/fmotalleb/go-tools/config`), it delivers automated Let's Encrypt TLS certificate management, hierarchical SOCKS5 tunneling across all layers, and automated wildcard certificate generation (`*.example.com`) via Cloudflare and ArvanCloud DNS-01 challenges.

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

5. **Modern Go Tools Integration (`fmotalleb/go-tools`) & Cobra CLI**:
   - **Cobra CLI**: Powerful command-line interface with persistent flags and subcommands (`edged run`, `edged validate`).
   - **Context-Scoped Zap Logging**: Uses `github.com/fmotalleb/go-tools/log` to retrieve structured `*zap.Logger` instances directly from `context.Context`.
   - **Strict Mapstructure Parsing**: Uses `github.com/fmotalleb/go-tools/config` with comprehensive `mapstructure:"..."` struct tags to ensure type-safe configuration decoding.

---

## 📁 Project Structure

```text
.
├── cmd/
│   └── edged/
│       └── main.go              # Cobra CLI entrypoint, commands, signal handling
├── acme/
│   ├── manager.go           # ACME client, SOCKS5 proxy setup, DNS-01 providers, cert caching
│   └── user.go              # Registration account user implementation for Lego
├── config/
│   └── config.go            # Mapstructure config loader, defaults, validation
├── proxy/
│       ├── listener.go          # HTTP/HTTPS listener manager, TLS GetCertificate binding
│       └── reverse_proxy.go     # ReverseProxy routing engine, custom director, error handling
├── config.yaml                  # Example production YAML configuration
├── Dockerfile                   # Multi-stage optimized build for Docker deployment
├── Makefile                     # Build, run, and validation automation
├── go.mod                       # Go module definition (github.com/fmotalleb/edged)
└── README.md                    # Project documentation
```

---

## ⚙️ Configuration Structure (`config.yaml`)

```yaml
# Global default SOCKS5 proxy for connecting to upstream backends.
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
      - host: "example.com"
        path_prefix: "/"
        upstream: "http://127.0.0.1:8080"
        strip_prefix: false
        timeout: 30s
        custom_headers:
          X-Proxy-Engine: "edged"

      - host: "api.example.com"
        path_prefix: "/v1"
        upstream: "http://127.0.0.1:3000"
        strip_prefix: false

      # Wildcard subdomain routing via SOCKS5 Upstream Proxy
      - host: "*.example.com"
        path_prefix: "/"
        upstream: "http://10.0.0.10:8081"
        upstream_socks5_proxy: "socks5://user:pass@127.0.0.1:1080"

# Global ACME Let's Encrypt Configuration
acme:
  email: "admin@example.com"
  directory_url: "https://acme-v02.api.letsencrypt.org/directory"
  socks5_proxy: "socks5://127.0.0.1:1080"
  storage_path: "./acme_storage"
  renew_before_days: 30
  check_interval_hours: 24

  dns_provider:
    name: "cloudflare"       # Switch between "cloudflare" and "arvancloud"
    use_socks5: true

    arvancloud:
      api_key: "Apikey xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      propagation_timeout: 120
      polling_interval: 2
      ttl: 600

    cloudflare:
      api_token: "your_cloudflare_dns_api_token_here"
      zone_token: ""
      auth_email: ""
      auth_key: ""
      propagation_timeout: 120
      polling_interval: 2
      ttl: 300
```

---

## 🚀 Building & Running with Cobra CLI

### 1. Local Development (Using Go / Makefile)

```bash
# Download dependencies
make tidy

# Build the executable binary
make build

# Validate your configuration YAML using Cobra subcommand
./edged validate --config config.yaml
# OR:
make validate

# Run the reverse proxy
./edged --config config.yaml
# OR:
make run
```

### 2. Cobra CLI Usage

`edged` provides clean command-line flags and subcommands:
```text
Usage:
  edged [command] [flags]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  validate    Validate configuration file syntax and structure, then exit

Flags:
  -c, --config string   Path to YAML configuration file (default "config.yaml")
  -h, --help            help for edged
  -v, --validate        Validate configuration file and exit
```

---

## 🛠️ Environment Variable Overrides

| Environment Variable | Provider | Description |
| :--- | :--- | :--- |
| `ARVANCLOUD_API_KEY` | ArvanCloud | Format: `"Apikey xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` |
| `CLOUDFLARE_DNS_API_TOKEN` | Cloudflare | Scoped API token with `DNS:Edit` and `Zone:Read` permissions |
| `CLOUDFLARE_ZONE_API_TOKEN` | Cloudflare | Scoped zone token (if permissions are split across two tokens) |
| `CLOUDFLARE_EMAIL` | Cloudflare | Legacy account email address |
| `CLOUDFLARE_API_KEY` | Cloudflare | Legacy global API key |
