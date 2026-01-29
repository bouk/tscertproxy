# tscertproxy

A proxy server for ACME DNS-01 challenges with Tailscale authentication.

tscertproxy allows machines on your Tailscale network to obtain TLS certificates from Let's Encrypt (or any ACME-compatible CA) without exposing your DNS credentials to every host that needs a certificate.

It uses Tailscale's `whois` API to identify which machine is making the request, and only allows certificates for domains matching the machine's Tailscale node name.

## How It Works

1. A machine on your Tailnet (e.g., `testmachine`) needs a TLS certificate
2. It sends a DNS-01 challenge request to tscertproxy over Tailscale
3. tscertproxy uses Tailscale whois to identify the caller as `testmachine`
4. If the configured domain suffix is `node.example.com`, tscertproxy only allows certificates for `testmachine.node.example.com`
5. tscertproxy creates the DNS TXT record using your DNS provider credentials
6. The ACME CA validates the challenge and issues the certificate

### Services Authorization

In addition to hostname-based authorization, tscertproxy supports **Tailscale services-based authorization**. When configured with Tailscale OAuth credentials, nodes can request certificates for [Tailscale services](https://tailscale.com/kb/1390/services) they are approved to host.

For example, if a node is approved to host the service `svc:myapp`, it can request a certificate for `myapp.node.example.com` regardless of its hostname.

Both authorization methods are checked in order:

1. **Hostname-based** (default): A node named `testmachine` can get certs for `testmachine.<domain-suffix>`. Disabled with `-disable-hostname`.
2. **Services-based** (optional): If hostname authorization fails (or is disabled), tscertproxy checks whether the node is approved to host the service matching the requested subdomain via the Tailscale API.

## Installation

### Build from Source

```bash
go install github.com/BuildMonumental/tscertproxy@latest
```

## Tailscale Service Setup

tscertproxy is designed to run as a [Tailscale service](https://tailscale.com/kb/1552/tailscale-services). It listens on localhost and relies on Tailscale's service proxy to forward traffic from your tailnet, using `X-Forwarded-For` headers to identify the original caller.

1. Run tscertproxy on the host (it listens on `127.0.0.1:30800` by default).
2. Register tscertproxy as a Tailscale service so it is accessible from your tailnet:

   ```bash
   tailscale serve --service=svc:tscertproxy --https=443 127.0.0.1:30800
   ```

3. Clients on your tailnet can now reach tscertproxy via the Tailscale service address.

See the [Tailscale services documentation](https://tailscale.com/kb/1552/tailscale-services) for more details on configuring services.

## Usage

```bash
tscertproxy -dns-provider cloudflare -domains node.example.com
```

### Flags

| Flag | Env Variable | Description |
|------|--------------|-------------|
| `-listen` | `TSCERTPROXY_LISTEN` | Address to listen on (default: `127.0.0.1:30800`) |
| `-domains` | `TSCERTPROXY_DOMAINS` | Comma-separated list of allowed domain suffixes |
| `-dns-provider` | `TSCERTPROXY_DNS_PROVIDER` | DNS provider name (e.g., `cloudflare`, `route53`) |
| `-debug` | `TSCERTPROXY_DEBUG` | Enable debug logging |
| `-disable-hostname` | `TSCERTPROXY_DISABLE_HOSTNAME` | Disable hostname-based authorization (only allow services-based) |
| `-ts-client-id` | `TSCERTPROXY_TS_CLIENT_ID` | Tailscale OAuth client ID for services API |
| `-ts-client-secret` | `TSCERTPROXY_TS_CLIENT_SECRET` | Tailscale OAuth client secret for services API |
| `-tailnet` | `TSCERTPROXY_TAILNET` | Tailnet name (e.g., `example.com`) |
| `-version` | | Show version information |

Flags take precedence over environment variables.

The `-ts-client-id`, `-ts-client-secret`, and `-tailnet` flags must all be provided together or all be omitted.

### Example

```bash
# Using environment variables
export TSCERTPROXY_DOMAINS=node.example.com
export TSCERTPROXY_DNS_PROVIDER=cloudflare
export CF_API_TOKEN=your-api-token
tscertproxy

# With Tailscale services authorization
tscertproxy \
  -domains node.example.com \
  -dns-provider cloudflare \
  -ts-client-id tskey-client-xxxxx \
  -ts-client-secret tskey-client-secret-xxxxx \
  -tailnet example.com

# Services-only mode (disable hostname-based authorization)
tscertproxy \
  -domains node.example.com \
  -dns-provider cloudflare \
  -disable-hostname \
  -ts-client-id tskey-client-xxxxx \
  -ts-client-secret tskey-client-secret-xxxxx \
  -tailnet example.com
```

## DNS Provider Configuration

DNS provider credentials are configured via environment variables, following the [lego DNS provider conventions](https://go-acme.github.io/lego/dns/).

**Cloudflare:**
```bash
export CF_API_TOKEN="your-api-token"
```

**Route53:**
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"
```

**DigitalOcean:**
```bash
export DO_AUTH_TOKEN="your-auth-token"
```

See the [lego DNS providers documentation](https://go-acme.github.io/lego/dns/) for a complete list of supported providers and their environment variables.

## Client Configuration

tscertproxy implements the [lego httpreq DNS provider](https://go-acme.github.io/lego/dns/httpreq/) RAW mode API.

### lego Example

```bash
HTTPREQ_ENDPOINT="http://localhost:30800" \
HTTPREQ_MODE="RAW" \
lego --dns httpreq --domains myhost.node.example.com run
```

## API

tscertproxy exposes the following HTTP endpoints:

### POST /present

Creates a DNS TXT record for an ACME challenge.

**Request:**
```json
{
    "domain": "myhost.node.example.com",
    "token": "acme-token",
    "keyAuth": "key-authorization-string"
}
```

### POST /cleanup

Removes the DNS TXT record after the challenge is complete.

**Request:**
```json
{
    "domain": "myhost.node.example.com",
    "token": "acme-token",
    "keyAuth": "key-authorization-string"
}
```

### GET /health

Returns the health status of the service.

**Response:**
```json
{
    "status": "ok"
}
```

## License

Apache 2.0
