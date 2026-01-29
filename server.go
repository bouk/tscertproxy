package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"tailscale.com/client/local"
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

	// If Tailscale API OAuth is configured, enable services authorization.
	if cfg.ServicesAPIEnabled() {
		tsAuth.ServicesClient = NewServicesClient(
			cfg.TailscaleClientID,
			cfg.TailscaleClientSecret,
			cfg.Tailnet,
		)
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
