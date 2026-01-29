package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/providers/dns"
)

const shutdownTimeout = 30 * time.Second

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	cfg, err := ParseConfig()
	if errors.Is(err, errShowVersion) {
		printVersion()
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Set up logging.
	logLevel := slog.LevelInfo
	if cfg.Debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Create DNS provider using lego.
	provider, err := dns.NewDNSChallengeProviderByName(cfg.DNSProvider)
	if err != nil {
		logger.Error("failed to create DNS provider",
			"provider", cfg.DNSProvider,
			"error", err,
		)
		os.Exit(1)
	}

	// Create and start server.
	srv := NewServer(cfg, provider, logger)
	if err := srv.Start(); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}

	logger.Info("tscertproxy started",
		"version", version,
		"listen", cfg.Listen,
		"dns_provider", cfg.DNSProvider,
	)

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	logger.Info("shutdown complete")
}

func printVersion() {
	fmt.Printf("tscertproxy %s (%s) %s/%s\n", version, commit, runtime.GOOS, runtime.GOARCH)
}
