package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockProvider implements challenge.Provider for testing.
type mockProvider struct {
	presentCalled bool
	cleanupCalled bool
	presentErr    error
	cleanupErr    error
	lastDomain    string
	lastToken     string
	lastKeyAuth   string
}

func (m *mockProvider) Present(domain, token, keyAuth string) error {
	m.presentCalled = true
	m.lastDomain = domain
	m.lastToken = token
	m.lastKeyAuth = keyAuth
	return m.presentErr
}

func (m *mockProvider) CleanUp(domain, token, keyAuth string) error {
	m.cleanupCalled = true
	m.lastDomain = domain
	m.lastToken = token
	m.lastKeyAuth = keyAuth
	return m.cleanupErr
}

// mockAuth implements Authenticator for testing.
type mockAuth struct {
	authResult *AuthResult
	authErr    error
	denyReason DenyReason
	// authorizeDeny is returned by AuthorizeDomainWithContext when non-empty.
	authorizeDeny DenyReason
}

func (m *mockAuth) Authenticate(req *http.Request) (*AuthResult, DenyReason, error) {
	if m.authErr != nil {
		return nil, m.denyReason, m.authErr
	}
	return m.authResult, "", nil
}

func (m *mockAuth) AuthorizeDomainWithContext(ctx context.Context, auth *AuthResult, domain string) DenyReason {
	return m.authorizeDeny
}

func newTestHandler(auth Authenticator, provider *mockProvider) *Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewHandler(auth, provider, logger)
}

func TestHandlerRouting(t *testing.T) {
	provider := &mockProvider{}
	auth := &mockAuth{
		authResult: &AuthResult{
			NodeName:       "testnode",
			AllowedDomains: []string{"test.example.com"},
		},
	}
	handler := newTestHandler(auth, provider)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"present GET not allowed", http.MethodGet, "/present", http.StatusMethodNotAllowed},
		{"cleanup GET not allowed", http.MethodGet, "/cleanup", http.StatusMethodNotAllowed},
		{"unknown path", http.MethodPost, "/unknown", http.StatusNotFound},
		{"root path", http.MethodGet, "/", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestRequestBodyParsing(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "valid request",
			body:       `{"domain": "test.example.com", "token": "tok", "keyAuth": "key"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing domain",
			body:       `{"token": "tok", "keyAuth": "key"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing token",
			body:       `{"domain": "test.example.com", "keyAuth": "key"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing keyAuth",
			body:       `{"domain": "test.example.com", "token": "tok"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid JSON",
			body:       `{invalid}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty body",
			body:       ``,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockProvider{}
			auth := &mockAuth{
				authResult: &AuthResult{
					NodeName:       "testnode",
					AllowedDomains: []string{"test.example.com"},
				},
			}
			handler := newTestHandler(auth, provider)

			req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestProviderCalled(t *testing.T) {
	provider := &mockProvider{}
	auth := &mockAuth{
		authResult: &AuthResult{
			NodeName:       "testnode",
			AllowedDomains: []string{"test.example.com"},
		},
	}
	handler := newTestHandler(auth, provider)

	t.Run("present calls provider.Present", func(t *testing.T) {
		provider.presentCalled = false
		body := `{"domain": "test.example.com", "token": "mytoken", "keyAuth": "mykey"}`
		req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !provider.presentCalled {
			t.Error("expected provider.Present to be called")
		}
		if provider.lastDomain != "test.example.com" {
			t.Errorf("expected domain %q, got %q", "test.example.com", provider.lastDomain)
		}
		if provider.lastToken != "mytoken" {
			t.Errorf("expected token %q, got %q", "mytoken", provider.lastToken)
		}
		if provider.lastKeyAuth != "mykey" {
			t.Errorf("expected keyAuth %q, got %q", "mykey", provider.lastKeyAuth)
		}
	})

	t.Run("cleanup calls provider.CleanUp", func(t *testing.T) {
		provider.cleanupCalled = false
		body := `{"domain": "test.example.com", "token": "mytoken", "keyAuth": "mykey"}`
		req := httptest.NewRequest(http.MethodPost, "/cleanup", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !provider.cleanupCalled {
			t.Error("expected provider.CleanUp to be called")
		}
	})
}

func TestResponseFormat(t *testing.T) {
	provider := &mockProvider{}
	auth := &mockAuth{
		authResult: &AuthResult{
			NodeName:       "testnode",
			AllowedDomains: []string{"test.example.com"},
		},
	}
	handler := newTestHandler(auth, provider)

	body := `{"domain": "test.example.com", "token": "tok123", "keyAuth": "key456"}`
	req := httptest.NewRequest(http.MethodPost, "/present", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", contentType)
	}

	var resp RequestBody
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Domain != "test.example.com" {
		t.Errorf("expected domain in response, got %q", resp.Domain)
	}
	if resp.Token != "tok123" {
		t.Errorf("expected token in response, got %q", resp.Token)
	}
	if resp.KeyAuth != "key456" {
		t.Errorf("expected keyAuth in response, got %q", resp.KeyAuth)
	}
}

func TestDomainValidation(t *testing.T) {
	tests := []struct {
		name  string
		domain string
		valid bool
	}{
		{"valid domain", "test.example.com", true},
		{"valid with trailing dot", "test.example.com.", true},
		{"single label", "localhost", false},
		{"empty", "", false},
		{"label starts with hyphen", "-test.example.com", false},
		{"label ends with hyphen", "test-.example.com", false},
		{"label with underscore", "te_st.example.com", false},
		{"valid hyphen in middle", "my-test.example.com", true},
		{"long label over 63 chars", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", false},
		{"just right label 63 chars", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidDomain(tt.domain); got != tt.valid {
				t.Errorf("isValidDomain(%q) = %v, want %v", tt.domain, got, tt.valid)
			}
		})
	}
}
