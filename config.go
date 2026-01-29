package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config represents the application configuration.
type Config struct {
	// Listen address (e.g., ":443", "127.0.0.1:8443").
	Listen string

	// Domain suffixes that nodes are allowed to get certificates for.
	Domains []string

	// DNSProvider is the name of the lego DNS provider to use.
	DNSProvider string

	// Debug enables debug logging.
	Debug bool

	// DisableHostname disables using the node's hostname as a subdomain.
	// When true, only services-based authorization is used.
	DisableHostname bool

	// Tailscale API OAuth credentials for services authorization.
	// When set, nodes can request certs for services they are allowed to host.
	TailscaleClientID     string
	TailscaleClientSecret string
	Tailnet               string
}

// ParseConfig parses configuration from flags and environment variables.
// Flags take precedence over environment variables.
func ParseConfig() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.Listen, "listen", envOrDefault("TSCERTPROXY_LISTEN", "127.0.0.1:30800"), "Address to listen on (env: TSCERTPROXY_LISTEN)")
	flag.StringVar(&cfg.DNSProvider, "dns-provider", os.Getenv("TSCERTPROXY_DNS_PROVIDER"), "DNS provider name, e.g. cloudflare, route53 (env: TSCERTPROXY_DNS_PROVIDER)")
	flag.BoolVar(&cfg.Debug, "debug", envBool("TSCERTPROXY_DEBUG"), "Enable debug logging (env: TSCERTPROXY_DEBUG)")
	flag.BoolVar(&cfg.DisableHostname, "disable-hostname", envBool("TSCERTPROXY_DISABLE_HOSTNAME"), "Disallow using the node's hostname as a subdomain (env: TSCERTPROXY_DISABLE_HOSTNAME)")
	flag.StringVar(&cfg.TailscaleClientID, "ts-client-id", os.Getenv("TSCERTPROXY_TS_CLIENT_ID"), "Tailscale OAuth client ID for services API (env: TSCERTPROXY_TS_CLIENT_ID)")
	flag.StringVar(&cfg.TailscaleClientSecret, "ts-client-secret", os.Getenv("TSCERTPROXY_TS_CLIENT_SECRET"), "Tailscale OAuth client secret for services API (env: TSCERTPROXY_TS_CLIENT_SECRET)")
	flag.StringVar(&cfg.Tailnet, "tailnet", os.Getenv("TSCERTPROXY_TAILNET"), "Tailnet name, e.g. example.com or org name (env: TSCERTPROXY_TAILNET)")

	var domains string
	flag.StringVar(&domains, "domains", os.Getenv("TSCERTPROXY_DOMAINS"), "Comma-separated list of allowed domain suffixes (env: TSCERTPROXY_DOMAINS)")

	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Show version information")

	flag.Parse()

	if showVersion {
		return nil, errShowVersion
	}

	// Parse domains.
	if domains != "" {
		cfg.Domains = splitAndTrim(domains)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if len(c.Domains) == 0 {
		return fmt.Errorf("at least one domain must be specified (-domains or TSCERTPROXY_DOMAINS)")
	}

	if c.DNSProvider == "" {
		return fmt.Errorf("DNS provider must be specified (-dns-provider or TSCERTPROXY_DNS_PROVIDER)")
	}

	// If any Tailscale API credential is provided, all must be provided.
	hasClientID := c.TailscaleClientID != ""
	hasClientSecret := c.TailscaleClientSecret != ""
	hasTailnet := c.Tailnet != ""
	if hasClientID || hasClientSecret || hasTailnet {
		if !hasClientID || !hasClientSecret || !hasTailnet {
			return fmt.Errorf("all Tailscale API options must be specified together: -ts-client-id, -ts-client-secret, -tailnet")
		}
	}

	return nil
}

// ServicesAPIEnabled returns true if the Tailscale services API is configured.
func (c *Config) ServicesAPIEnabled() bool {
	return c.TailscaleClientID != "" && c.TailscaleClientSecret != "" && c.Tailnet != ""
}

// envOrDefault returns the environment variable value or a default.
func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// envBool returns true if the environment variable is set to a truthy value.
func envBool(key string) bool {
	v := os.Getenv(key)
	return v == "1" || v == "true" || v == "yes"
}

// splitAndTrim splits a string by comma and trims whitespace.
func splitAndTrim(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// errShowVersion is returned when -version flag is used.
var errShowVersion = fmt.Errorf("show version")
