package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"tailscale.com/client/local"
	tailscale "tailscale.com/client/tailscale/v2"
)

const (
	serverReadTimeout  = 30 * time.Second
	serverWriteTimeout = 30 * time.Second
	serverIdleTimeout  = 60 * time.Second
)

// Server is the tscertproxy HTTP server.
type Server struct {
	cfg     *Config
	handler *Handler
	server  *http.Server
	logger  *slog.Logger
}

// NewServer creates a new server.
func NewServer(cfg *Config, provider challenge.Provider, logger *slog.Logger) *Server {
	tsAuth := &TailscaleAuth{
		Domains:         cfg.Domains,
		DisableHostname: cfg.DisableHostname,
		LocalClient:     &local.Client{},
	}

	// If Tailscale API is configured, enable services authorization.
	if cfg.ServicesAPIEnabled() {
		client, err := buildTailscaleClient(cfg, logger)
		if err != nil {
			logger.Error("failed to build Tailscale API client", "error", err)
			os.Exit(1)
		}
		tsAuth.ServicesClient = NewServicesClient(client)
		logger.Info("services API enabled", "tailnet", cfg.Tailnet)
	}

	handler := NewHandler(tsAuth, provider, logger)

	return &Server{
		cfg:     cfg,
		handler: handler,
		logger:  logger,
	}
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	s.server = &http.Server{
		Addr:         s.cfg.Listen,
		Handler:      s.handler,
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
	}

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}

	s.logger.Info("server listening", "addr", s.cfg.Listen)

	go func() {
		if err := s.server.Serve(ln); err != http.ErrServerClosed {
			s.logger.Error("server error", "error", err)
		}
	}()

	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

// buildTailscaleClient creates a tailscale.Client with the appropriate auth method.
func buildTailscaleClient(cfg *Config, logger *slog.Logger) (*tailscale.Client, error) {
	client := &tailscale.Client{
		Tailnet: cfg.Tailnet,
	}

	clientID := os.Getenv("TS_CLIENT_ID")
	clientSecret := os.Getenv("TS_CLIENT_SECRET")
	apiKey := os.Getenv("TS_API_KEY")
	idFedProvider := os.Getenv("TS_IDENTITY_FEDERATION_PROVIDER")

	switch {
	case idFedProvider == "tailscale" && clientID != "":
		audience := os.Getenv("TS_IDENTITY_FEDERATION_AUDIENCE")
		if audience == "" {
			audience = "api.tailscale.com/" + clientID
		}
		lc := &local.Client{}
		client.Auth = &tailscale.IdentityFederation{
			ClientID: clientID,
			IDTokenFunc: func() (string, error) {
				resp, err := lc.IDToken(context.Background(), audience)
				if err != nil {
					return "", err
				}
				return resp.IDToken, nil
			},
		}
		logger.Info("using identity federation authentication", "audience", audience)
	case clientID != "" && clientSecret != "":
		client.Auth = &tailscale.OAuth{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}
		logger.Info("using OAuth authentication")
	case apiKey != "":
		client.APIKey = apiKey
		logger.Info("using API key authentication")
	default:
		return nil, fmt.Errorf("set TS_IDENTITY_FEDERATION_PROVIDER=tailscale + TS_CLIENT_ID, TS_CLIENT_ID + TS_CLIENT_SECRET, or TS_API_KEY")
	}

	return client, nil
}
