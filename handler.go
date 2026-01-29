package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
)

// RequestBody represents the lego httpreq RAW mode request format.
type RequestBody struct {
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"keyAuth"`
}

// Authenticator provides authentication and authorization for requests.
type Authenticator interface {
	Authenticate(req *http.Request) (*AuthResult, DenyReason, error)
	AuthorizeDomainWithContext(ctx context.Context, auth *AuthResult, domain string) DenyReason
}

// Handler handles /present and /cleanup requests.
type Handler struct {
	mux      *http.ServeMux
	auth     Authenticator
	provider challenge.Provider
	logger   *slog.Logger
}

// NewHandler creates a new Handler.
func NewHandler(auth Authenticator, provider challenge.Provider, logger *slog.Logger) *Handler {
	h := &Handler{
		mux:      http.NewServeMux(),
		auth:     auth,
		provider: provider,
		logger:   logger,
	}

	h.mux.HandleFunc("POST /present", func(w http.ResponseWriter, r *http.Request) {
		h.handleDNSRequest(w, r, true)
	})
	h.mux.HandleFunc("POST /cleanup", func(w http.ResponseWriter, r *http.Request) {
		h.handleDNSRequest(w, r, false)
	})
	h.mux.HandleFunc("GET /health", h.handleHealth)

	return h
}

// ServeHTTP delegates to the internal ServeMux and logs every request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	h.mux.ServeHTTP(sw, r)
	h.logger.Info("http request",
		"method", r.Method,
		"path", r.URL.Path,
		"status", sw.status,
		"duration", time.Since(start),
		"remote_addr", r.RemoteAddr,
	)
}

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handler) handleDNSRequest(w http.ResponseWriter, r *http.Request, isPresent bool) {
	// Authenticate via Tailscale whois.
	authResult, denyReason, err := h.auth.Authenticate(r)
	if err != nil {
		h.logger.Warn("tailscale authentication failed",
			"remote_addr", r.RemoteAddr,
			"deny_reason", string(denyReason),
			"error", err,
		)
		http.Error(w, string(denyReason), http.StatusForbidden)
		return
	}

	h.logger.Debug("authenticated tailscale node",
		"node_name", authResult.NodeName,
		"allowed_domains", authResult.AllowedDomains,
	)

	// Parse request body.
	var req RequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Domain == "" || req.Token == "" || req.KeyAuth == "" {
		http.Error(w, "Missing domain, token, or keyAuth", http.StatusBadRequest)
		return
	}

	if !isValidDomain(req.Domain) {
		http.Error(w, "Invalid domain format", http.StatusBadRequest)
		return
	}

	h.logger.Debug("received DNS request",
		"is_present", isPresent,
		"domain", req.Domain,
		"node_name", authResult.NodeName,
	)

	// Authorize: check domain is allowed for this node.
	denyReason = h.auth.AuthorizeDomainWithContext(r.Context(), authResult, req.Domain)
	if denyReason != "" {
		h.logger.Warn("domain not allowed",
			"node_name", authResult.NodeName,
			"domain", req.Domain,
			"allowed_domains", authResult.AllowedDomains,
			"deny_reason", string(denyReason),
		)
		http.Error(w, string(denyReason), http.StatusForbidden)
		return
	}

	// Perform DNS operation using lego provider.
	if isPresent {
		err = h.provider.Present(req.Domain, req.Token, req.KeyAuth)
		if err != nil {
			h.logger.Error("failed to create DNS record",
				"domain", req.Domain,
				"error", err,
			)
			http.Error(w, "Failed to create DNS record", http.StatusInternalServerError)
			return
		}
		h.logger.Info("created DNS record",
			"domain", req.Domain,
			"node_name", authResult.NodeName,
		)
	} else {
		err = h.provider.CleanUp(req.Domain, req.Token, req.KeyAuth)
		if err != nil {
			h.logger.Error("failed to delete DNS record",
				"domain", req.Domain,
				"error", err,
			)
			http.Error(w, "Failed to delete DNS record", http.StatusInternalServerError)
			return
		}
		h.logger.Info("deleted DNS record",
			"domain", req.Domain,
			"node_name", authResult.NodeName,
		)
	}

	// Return success response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(req)
}

// isValidDomain checks whether a string is a valid DNS domain name.
func isValidDomain(domain string) bool {
	// Remove trailing dot (FQDN).
	domain = strings.TrimSuffix(domain, ".")

	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	for _, label := range labels {
		n := len(label)
		if n == 0 || n > 63 {
			return false
		}
		// Labels must start and end with alphanumeric.
		if !isAlnum(label[0]) || !isAlnum(label[n-1]) {
			return false
		}
		for i := 1; i < n-1; i++ {
			if !isAlnum(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
