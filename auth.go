package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"tailscale.com/client/local"
)

// DenyReason represents why a request was denied.
type DenyReason string

const (
	// DenyNotTailscale indicates the request did not come from a Tailscale IP.
	DenyNotTailscale DenyReason = "not a tailscale request"

	// DenyWhoisFailed indicates that the Tailscale whois lookup failed.
	DenyWhoisFailed DenyReason = "tailscale whois failed"

	// DenyDomainNotAllowed indicates the requested domain is not allowed for this node.
	DenyDomainNotAllowed DenyReason = "requested domain denied by policy"

	// DenyServiceLookupFailed indicates the service lookup API call failed.
	DenyServiceLookupFailed DenyReason = "service lookup failed"
)

// TailscaleAuth handles authentication and authorization via Tailscale whois.
type TailscaleAuth struct {
	// Domain suffixes that are allowed, e.g., "node.example.com".
	// A node named "testmachine" would be allowed to get certs for
	// "testmachine.node.example.com".
	Domains []string

	// LocalClient is used to communicate with the local Tailscale daemon.
	LocalClient *local.Client

	// DisableHostname disables hostname-based authorization.
	// When true, nodes cannot use their hostname as a subdomain.
	DisableHostname bool

	// ServicesClient is used to check if a node is allowed to host a service.
	// If nil, only hostname-based authorization is used.
	ServicesClient *ServicesClient
}

// AuthResult contains the result of authentication.
type AuthResult struct {
	// NodeName is the computed name of the Tailscale node (e.g., "testmachine").
	NodeName string

	// NodeID is the Tailscale node ID (e.g., "nXXXXXXXXXXCNTRL").
	NodeID string

	// AllowedDomains are the domains this node is allowed to get certs for.
	AllowedDomains []string
}

// Authenticate performs Tailscale whois on the request and returns the node info.
func (t *TailscaleAuth) Authenticate(req *http.Request) (*AuthResult, DenyReason, error) {
	// Get the remote address. If the request is from localhost, use
	// X-Forwarded-For to determine the original client IP.
	remoteAddr := req.RemoteAddr
	if isLocalhost(remoteAddr) {
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For may contain multiple IPs; use the first one.
			if ip, _, ok := strings.Cut(xff, ","); ok {
				remoteAddr = strings.TrimSpace(ip)
			} else {
				remoteAddr = strings.TrimSpace(xff)
			}
		}
	}

	// Perform whois lookup.
	whois, err := t.LocalClient.WhoIs(req.Context(), remoteAddr)
	if err != nil {
		return nil, DenyWhoisFailed, fmt.Errorf("tailscale whois failed for %s: %w", remoteAddr, err)
	}

	if whois.Node == nil {
		return nil, DenyNotTailscale, fmt.Errorf("no node info for %s", remoteAddr)
	}

	// Get the computed name (e.g., "testmachine").
	nodeName := whois.Node.ComputedName
	if nodeName == "" {
		// Fallback to the hostname if ComputedName is empty.
		nodeName = whois.Node.Hostinfo.Hostname()
	}

	// Normalize the node name (lowercase, remove any trailing dots).
	nodeName = strings.ToLower(strings.TrimSuffix(nodeName, "."))

	// Build the list of allowed domains for this node.
	allowedDomains := make([]string, 0, len(t.Domains))
	for _, suffix := range t.Domains {
		// Each node can get certs for <nodename>.<suffix>.
		allowedDomain := nodeName + "." + suffix
		allowedDomains = append(allowedDomains, allowedDomain)
	}

	// Get the stable node ID for service authorization.
	// The StableID has the format "n123456CNTRL" and is stable across tagging/untagging.
	nodeID := string(whois.Node.StableID)

	return &AuthResult{
		NodeName:       nodeName,
		NodeID:         nodeID,
		AllowedDomains: allowedDomains,
	}, "", nil
}

// AuthorizeDomain checks if the given domain is allowed for the node.
// The domain is the certificate domain (e.g., "testmachine.node.example.com"),
// not the challenge FQDN.
func (t *TailscaleAuth) AuthorizeDomain(auth *AuthResult, domain string) DenyReason {
	return t.AuthorizeDomainWithContext(context.Background(), auth, domain)
}

// AuthorizeDomainWithContext checks if the given domain is allowed for the node.
func (t *TailscaleAuth) AuthorizeDomainWithContext(ctx context.Context, auth *AuthResult, domain string) DenyReason {
	// Normalize the domain.
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check if the domain matches any of the allowed hostname-based domains.
	if !t.DisableHostname {
		for _, allowed := range auth.AllowedDomains {
			if domain == allowed {
				return ""
			}
		}
	}

	// If services API is not configured, deny.
	if t.ServicesClient == nil {
		return DenyDomainNotAllowed
	}

	// Extract the service name from the domain.
	// The domain format is <servicename>.<suffix>, e.g., "myservice.node.example.com"
	serviceName := t.extractServiceName(domain)
	if serviceName == "" {
		return DenyDomainNotAllowed
	}

	// Check if this node is allowed to host the service.
	allowed, err := t.isNodeAllowedForService(ctx, auth.NodeID, serviceName)
	if err != nil {
		return DenyServiceLookupFailed
	}

	if !allowed {
		return DenyDomainNotAllowed
	}

	return ""
}

// extractServiceName extracts the service name from a domain by matching against configured suffixes.
// Returns empty string if no suffix matches.
func (t *TailscaleAuth) extractServiceName(domain string) string {
	// Normalize the domain.
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for _, suffix := range t.Domains {
		suffix = strings.ToLower(suffix)
		if strings.HasSuffix(domain, "."+suffix) {
			// Extract everything before the suffix.
			serviceName := strings.TrimSuffix(domain, "."+suffix)
			if serviceName != "" {
				return serviceName
			}
		}
	}
	return ""
}

// isNodeAllowedForService checks if a node is approved to host a service.
func (t *TailscaleAuth) isNodeAllowedForService(ctx context.Context, nodeID, serviceName string) (bool, error) {
	approval, err := t.ServicesClient.GetServiceDeviceApproval(ctx, "svc:"+serviceName, nodeID)
	if err != nil {
		return false, err
	}

	return approval.Approved, nil
}

// isLocalhost returns true if the address is a loopback address.
func isLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
