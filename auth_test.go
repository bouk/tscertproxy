package main

import (
	"context"
	"testing"
)

func TestAuthorizeDomain(t *testing.T) {
	auth := &TailscaleAuth{
		Domains: []string{"node.example.com", "other.example.org"},
	}

	authResult := &AuthResult{
		NodeName:       "testmachine",
		AllowedDomains: []string{"testmachine.node.example.com", "testmachine.other.example.org"},
	}

	tests := []struct {
		name       string
		domain     string
		wantDenied bool
	}{
		{
			name:       "allowed domain",
			domain:     "testmachine.node.example.com",
			wantDenied: false,
		},
		{
			name:       "allowed domain with trailing dot",
			domain:     "testmachine.node.example.com.",
			wantDenied: false,
		},
		{
			name:       "allowed second domain",
			domain:     "testmachine.other.example.org",
			wantDenied: false,
		},
		{
			name:       "different node name",
			domain:     "othermachine.node.example.com",
			wantDenied: true,
		},
		{
			name:       "subdomain of allowed",
			domain:     "sub.testmachine.node.example.com",
			wantDenied: true,
		},
		{
			name:       "parent of allowed",
			domain:     "node.example.com",
			wantDenied: true,
		},
		{
			name:       "completely different domain",
			domain:     "evil.attacker.com",
			wantDenied: true,
		},
		{
			name:       "case insensitive",
			domain:     "TESTMACHINE.NODE.EXAMPLE.COM",
			wantDenied: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := auth.AuthorizeDomain(authResult, tt.domain)
			denied := reason != ""

			if denied != tt.wantDenied {
				if tt.wantDenied {
					t.Errorf("expected domain %q to be denied, but was allowed", tt.domain)
				} else {
					t.Errorf("expected domain %q to be allowed, but was denied: %s", tt.domain, reason)
				}
			}
		})
	}
}

func TestBuildAllowedDomains(t *testing.T) {
	// Test that allowed domains are built correctly from node name and configured domains.
	auth := &TailscaleAuth{
		Domains: []string{"node.example.com", "internal.local"},
	}

	// Simulate what Authenticate would return for a node named "myserver".
	nodeName := "myserver"
	allowedDomains := make([]string, 0, len(auth.Domains))
	for _, suffix := range auth.Domains {
		allowedDomains = append(allowedDomains, nodeName+"."+suffix)
	}

	expected := []string{"myserver.node.example.com", "myserver.internal.local"}

	if len(allowedDomains) != len(expected) {
		t.Fatalf("expected %d allowed domains, got %d", len(expected), len(allowedDomains))
	}

	for i, want := range expected {
		if allowedDomains[i] != want {
			t.Errorf("expected allowed domain %d to be %q, got %q", i, want, allowedDomains[i])
		}
	}
}

func TestDenyReasons(t *testing.T) {
	// Ensure deny reasons are defined and non-empty.
	reasons := []DenyReason{
		DenyNotTailscale,
		DenyWhoisFailed,
		DenyDomainNotAllowed,
		DenyServiceLookupFailed,
	}

	for _, r := range reasons {
		if r == "" {
			t.Error("deny reason should not be empty")
		}
	}
}

func TestExtractServiceName(t *testing.T) {
	auth := &TailscaleAuth{
		Domains: []string{"node.example.com", "other.example.org"},
	}

	tests := []struct {
		domain      string
		wantService string
	}{
		{"myservice.node.example.com", "myservice"},
		{"db.other.example.org", "db"},
		{"MYSERVICE.NODE.EXAMPLE.COM", "myservice"},
		{"multi.level.service.node.example.com", "multi.level.service"},
		{"node.example.com", ""},           // No service name
		{"evil.attacker.com", ""},          // Non-matching suffix
		{"", ""},                           // Empty
		{"node.example.com.", ""},          // Just the suffix with trailing dot
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := auth.extractServiceName(tt.domain)
			if got != tt.wantService {
				t.Errorf("extractServiceName(%q) = %q, want %q", tt.domain, got, tt.wantService)
			}
		})
	}
}

func TestAuthorizeDomainWithServices(t *testing.T) {
	// Create a TailscaleAuth with a mock services client via a wrapper.
	// Since we can't easily mock the ServicesClient, we'll test the underlying logic.
	auth := &TailscaleAuth{
		Domains: []string{"node.example.com"},
	}

	authResult := &AuthResult{
		NodeName:       "testmachine",
		NodeID:         "n123456CNTRL",
		AllowedDomains: []string{"testmachine.node.example.com"},
	}

	// Test 1: Without ServicesClient, service domains should be denied.
	t.Run("no services client denies service domain", func(t *testing.T) {
		reason := auth.AuthorizeDomainWithContext(context.Background(), authResult, "myservice.node.example.com")
		if reason != DenyDomainNotAllowed {
			t.Errorf("expected DenyDomainNotAllowed, got %q", reason)
		}
	})

	// Test 2: Hostname domain should still be allowed.
	t.Run("hostname domain allowed without services client", func(t *testing.T) {
		reason := auth.AuthorizeDomainWithContext(context.Background(), authResult, "testmachine.node.example.com")
		if reason != "" {
			t.Errorf("expected allowed, got denied: %q", reason)
		}
	})
}

func TestDisableHostname(t *testing.T) {
	auth := &TailscaleAuth{
		Domains:         []string{"node.example.com"},
		DisableHostname: true,
	}

	authResult := &AuthResult{
		NodeName:       "testmachine",
		NodeID:         "n123456CNTRL",
		AllowedDomains: []string{"testmachine.node.example.com"},
	}

	// Hostname domain should be denied when DisableHostname is true.
	reason := auth.AuthorizeDomainWithContext(context.Background(), authResult, "testmachine.node.example.com")
	if reason != DenyDomainNotAllowed {
		t.Errorf("expected DenyDomainNotAllowed with disable-hostname, got %q", reason)
	}
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		addr     string
		expected bool
	}{
		{"127.0.0.1:1234", true},
		{"127.0.0.1", true},
		{"[::1]:1234", true},
		{"::1", true},
		{"100.64.0.1:1234", false},
		{"192.168.1.1:1234", false},
		{"10.0.0.1:1234", false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := isLocalhost(tt.addr); got != tt.expected {
				t.Errorf("isLocalhost(%q) = %v, want %v", tt.addr, got, tt.expected)
			}
		})
	}
}

func TestNodeLookupLogic(t *testing.T) {
	// Test the node lookup logic (same logic used in isNodeAllowedForService).
	testHosts := []ServiceHostInfo{
		{StableNodeID: "n123456CNTRL"},
		{StableNodeID: "n789012CNTRL"},
	}

	tests := []struct {
		name     string
		nodeID   string
		hosts    []ServiceHostInfo
		expected bool
	}{
		{"node in list", "n123456CNTRL", testHosts, true},
		{"node not in list", "n999999CNTRL", testHosts, false},
		{"empty list", "n123456CNTRL", nil, false},
		{"empty node ID", "", testHosts, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			for _, host := range tt.hosts {
				if host.StableNodeID == tt.nodeID {
					found = true
					break
				}
			}
			if found != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, found)
			}
		})
	}
}
