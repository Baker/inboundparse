package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/inboundparse/inboundparse/internal/config"
	"github.com/inboundparse/inboundparse/internal/server"
	"github.com/inboundparse/inboundparse/internal/service"
	"go.uber.org/zap"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %v\n", err)
		os.Exit(1)
	}
}

// run contains the main application logic and is testable
func run() error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	return runWithConfig(cfg)
}

// runWithConfig contains the main application logic with injected configuration
func runWithConfig(cfg *config.Config) error {
	// Initialize structured logger
	logger, err := service.NewLoggerService(cfg.Server.Verbose)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to close logger: %v\n", err)
		}
	}()

	ctx := context.Background()

	// Initialize Sentry if enabled
	if cfg.Sentry.Enabled {
		if err := initializeSentry(cfg, logger); err != nil {
			logger.Error(ctx, "Failed to initialize Sentry", zap.Error(err))
		} else {
			defer sentry.Flush(2 * time.Second)
		}
	}

	// Log server information
	logServerInfo(ctx, cfg, logger)

	// Validate webhook URL
	if cfg.Webhook.URL == "" {
		return fmt.Errorf("webhook URL is required")
	}

	// Create services
	metricsService := service.NewMetricsService(cfg.Metrics.Enabled)
	webhookService := service.NewWebhookService(cfg.Webhook.URL, cfg.Webhook.Username, cfg.Webhook.Password)
	authService := service.NewAuthService(cfg.Auth.EnableSPF, cfg.Auth.EnableDKIM, cfg.Auth.EnableDMARC, logger)

	// Create SMTP backend
	backend := service.NewSMTPBackend(cfg, webhookService, authService, metricsService, logger)

	// Create server
	srv := server.NewServer(cfg, backend, metricsService, logger)

	// Run server with graceful shutdown
	if err := srv.Run(ctx); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// initializeSentry initializes Sentry error tracking
func initializeSentry(cfg *config.Config, logger service.LoggerService) error {
	if !cfg.Sentry.Enabled {
		return nil
	}

	if cfg.Sentry.DSN == "" {
		logger.Info(context.Background(), "Sentry enabled but no DSN provided, skipping Sentry initialization")
		return nil
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              cfg.Sentry.DSN,
		Environment:      cfg.Sentry.Env,
		Release:          cfg.Sentry.Release,
		TracesSampleRate: 0.1, // Sample 10% of transactions for performance monitoring
		Debug:            cfg.Server.Verbose,
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			// Add custom tags
			event.Tags["service"] = "inboundparse"
			event.Tags["component"] = "smtp-server"
			return event
		},
	})
	if err != nil {
		return fmt.Errorf("failed to initialize Sentry: %w", err)
	}

	logger.Info(context.Background(), "Sentry initialized",
		zap.String("environment", cfg.Sentry.Env),
		zap.String("release", cfg.Sentry.Release),
	)

	return nil
}

// logServerInfo logs server configuration information
func logServerInfo(ctx context.Context, cfg *config.Config, logger service.LoggerService) {
	logger.Info(ctx, "Starting SMTP server",
		zap.String("listen_addr", cfg.Server.ListenAddr),
		zap.String("listen_addr_tls", cfg.Server.ListenAddrTLS),
		zap.String("server_name", cfg.Server.ServerName),
		zap.String("webhook_url", cfg.Webhook.URL),
		zap.Bool("spf_validation", cfg.Auth.EnableSPF),
		zap.Bool("dkim_validation", cfg.Auth.EnableDKIM),
		zap.Bool("dmarc_validation", cfg.Auth.EnableDMARC),
		zap.Bool("verbose", cfg.Server.Verbose),
		zap.String("cert_file", cfg.Server.CertFile),
		zap.String("key_file", cfg.Server.KeyFile),
		zap.Bool("metrics_enabled", cfg.Metrics.Enabled),
		zap.String("metrics_addr", cfg.Metrics.Addr),
		zap.Bool("sentry_enabled", cfg.Sentry.Enabled),
		zap.String("log_level", cfg.Logging.Level),
		zap.String("log_format", cfg.Logging.Format),
	)
}
