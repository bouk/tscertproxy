package main

import (
	"os"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		expectError bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Listen:      "127.0.0.1:30800",
				Domains:     []string{"node.example.com"},
				DNSProvider: "cloudflare",
			},
			expectError: false,
		},
		{
			name: "missing domains",
			cfg: Config{
				Listen:      "127.0.0.1:30800",
				DNSProvider: "cloudflare",
			},
			expectError: true,
		},
		{
			name: "missing dns provider",
			cfg: Config{
				Listen:  "127.0.0.1:30800",
				Domains: []string{"node.example.com"},
			},
			expectError: true,
		},
		{
			name: "valid config with services API",
			cfg: Config{
				Listen:                "127.0.0.1:30800",
				Domains:               []string{"node.example.com"},
				DNSProvider:           "cloudflare",
				TailscaleClientID:     "client-id",
				TailscaleClientSecret: "client-secret",
				Tailnet:               "example.com",
			},
			expectError: false,
		},
		{
			name: "partial services API config - missing tailnet",
			cfg: Config{
				Listen:                "127.0.0.1:30800",
				Domains:               []string{"node.example.com"},
				DNSProvider:           "cloudflare",
				TailscaleClientID:     "client-id",
				TailscaleClientSecret: "client-secret",
			},
			expectError: true,
		},
		{
			name: "partial services API config - missing client secret",
			cfg: Config{
				Listen:            "127.0.0.1:30800",
				Domains:           []string{"node.example.com"},
				DNSProvider:       "cloudflare",
				TailscaleClientID: "client-id",
				Tailnet:           "example.com",
			},
			expectError: true,
		},
		{
			name: "partial services API config - missing client id",
			cfg: Config{
				Listen:                "127.0.0.1:30800",
				Domains:               []string{"node.example.com"},
				DNSProvider:           "cloudflare",
				TailscaleClientSecret: "client-secret",
				Tailnet:               "example.com",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestServicesAPIEnabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		expected bool
	}{
		{
			name: "all credentials provided",
			cfg: Config{
				TailscaleClientID:     "client-id",
				TailscaleClientSecret: "client-secret",
				Tailnet:               "example.com",
			},
			expected: true,
		},
		{
			name:     "no credentials",
			cfg:      Config{},
			expected: false,
		},
		{
			name: "missing client id",
			cfg: Config{
				TailscaleClientSecret: "client-secret",
				Tailnet:               "example.com",
			},
			expected: false,
		},
		{
			name: "missing client secret",
			cfg: Config{
				TailscaleClientID: "client-id",
				Tailnet:           "example.com",
			},
			expected: false,
		},
		{
			name: "missing tailnet",
			cfg: Config{
				TailscaleClientID:     "client-id",
				TailscaleClientSecret: "client-secret",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.ServicesAPIEnabled(); got != tt.expected {
				t.Errorf("ServicesAPIEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEnvOrDefault(t *testing.T) {
	os.Setenv("TEST_ENV_VAR", "test-value")
	defer os.Unsetenv("TEST_ENV_VAR")

	if v := envOrDefault("TEST_ENV_VAR", "default"); v != "test-value" {
		t.Errorf("expected 'test-value', got %q", v)
	}

	if v := envOrDefault("NONEXISTENT_VAR", "default"); v != "default" {
		t.Errorf("expected 'default', got %q", v)
	}
}

func TestEnvBool(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"1", true},
		{"true", true},
		{"yes", true},
		{"0", false},
		{"false", false},
		{"no", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			os.Setenv("TEST_BOOL", tt.value)
			defer os.Unsetenv("TEST_BOOL")

			if v := envBool("TEST_BOOL"); v != tt.expected {
				t.Errorf("envBool(%q) = %v, want %v", tt.value, v, tt.expected)
			}
		})
	}
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b, c", []string{"a", "b", "c"}},
		{"  a  ,  b  ,  c  ", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"", []string{}},
		{",,,", []string{}},
		{"a,,b", []string{"a", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := splitAndTrim(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("splitAndTrim(%q) = %v, want %v", tt.input, result, tt.expected)
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("splitAndTrim(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
				}
			}
		})
	}
}
