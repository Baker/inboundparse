package app

import (
	"context"
	"fmt"
	"inboundparse/internal/auth"
	"inboundparse/internal/config"
	"inboundparse/internal/observability"
	"inboundparse/internal/processor"
	"inboundparse/internal/smtp"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

// App represents the application
type App struct {
	config           *config.Config
	logger           observability.Logger
	metrics          observability.MetricsCollector
	sentry           observability.SentryClient
	authChecker      auth.AuthChecker
	webhookSender    processor.WebhookSender
	messageProcessor *processor.MessageProcessor
	smtpBackend      *smtp.Backend
	smtpServer       *smtp.SMTPServer
	metricsServer    observability.MetricsServer
}

// NewApp creates a new application instance
func NewApp(cfg *config.Config) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Initialize logger first
	logger := observability.NewLogger(observability.LoggerConfig{
		Verbose: cfg.Verbose,
	})

	// Initialize Sentry
	sentry := observability.NewSentryClient()
	if err := sentry.Init(observability.SentryConfig{
		EnableSentry:  cfg.EnableSentry,
		SentryDSN:     cfg.SentryDSN,
		SentryEnv:     cfg.SentryEnv,
		SentryRelease: cfg.SentryRelease,
	}); err != nil {
		logger.Error().Err(err).Msg("Failed to initialize Sentry")
		return nil, fmt.Errorf("failed to initialize Sentry: %w", err)
	}

	// Initialize metrics
	metrics := observability.NewMetricsCollector()

	// Initialize auth checker
	authChecker := auth.NewAuthChecker(auth.AuthConfig{
		EnableSPF:   cfg.EnableSPF,
		EnableDKIM:  cfg.EnableDKIM,
		EnableDMARC: cfg.EnableDMARC,
	})

	// Initialize webhook sender
	webhookSender := processor.NewWebhookSender(processor.WebhookConfig{
		URL:      cfg.WebhookURL,
		Username: cfg.WebhookUser,
		Password: cfg.WebhookPass,
		Timeout:  30 * time.Second,
	})

	// Initialize message processor
	messageProcessor := processor.NewMessageProcessor(
		processor.ProcessorConfig{
			EnableSPF:   cfg.EnableSPF,
			EnableDKIM:  cfg.EnableDKIM,
			EnableDMARC: cfg.EnableDMARC,
		},
		authChecker,
		webhookSender,
		metrics,
		sentry,
		logger,
	)

	// Initialize SMTP backend
	smtpBackend := smtp.NewBackend(
		smtp.BackendConfig{
			MaxRecipients: 100, // Default value
		},
		messageProcessor,
		metrics,
		logger,
	)

	// Initialize SMTP server
	smtpServer, err := smtp.NewSMTPServerFromConfig(cfg, smtpBackend, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create SMTP server: %w", err)
	}

	// Initialize metrics server
	metricsServer := observability.NewMetricsServer(observability.MetricsConfig{
		EnableMetrics:   cfg.EnableMetrics,
		MetricsAddr:     cfg.MetricsAddr,
		MetricsAPIKey:   cfg.MetricsAPIKey,
		MetricsUsername: cfg.MetricsUsername,
		MetricsPassword: cfg.MetricsPassword,
	})

	return &App{
		config:           cfg,
		logger:           logger,
		metrics:          metrics,
		sentry:           sentry,
		authChecker:      authChecker,
		webhookSender:    webhookSender,
		messageProcessor: messageProcessor,
		smtpBackend:      smtpBackend,
		smtpServer:       smtpServer,
		metricsServer:    metricsServer,
	}, nil
}

// Start starts the application
func (a *App) Start() error {
	// Validate configuration
	if err := a.config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Start metrics server
	if a.config.EnableMetrics {
		if err := a.metricsServer.Start(); err != nil {
			a.logger.Error().Err(err).Msg("Failed to start metrics server")
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
	}

	// Log startup information
	a.logger.Info().
		Str("smtp_address", a.config.ListenAddr).
		Str("smtp_tls_address", a.config.ListenAddrTLS).
		Str("webhook_url", a.config.WebhookURL).
		Bool("spf_enabled", a.config.EnableSPF).
		Bool("dkim_enabled", a.config.EnableDKIM).
		Bool("dmarc_enabled", a.config.EnableDMARC).
		Bool("metrics_enabled", a.config.EnableMetrics).
		Bool("sentry_enabled", a.config.EnableSentry).
		Bool("verbose", a.config.Verbose).
		Msg("Starting InboundParse SMTP server")

	if a.config.CertFile != "" && a.config.KeyFile != "" {
		a.logger.Info().
			Str("cert_file", a.config.CertFile).
			Str("key_file", a.config.KeyFile).
			Msg("TLS certificates configured")
	}

	// Start SMTP server
	if err := a.smtpServer.Start(); err != nil {
		return fmt.Errorf("failed to start SMTP server: %w", err)
	}

	return nil
}

// Run runs the application with graceful shutdown
func (a *App) Run() error {
	// Start the application
	if err := a.Start(); err != nil {
		return err
	}

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create error group for managing goroutines
	g, ctx := errgroup.WithContext(ctx)

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	g.Go(func() error {
		select {
		case sig := <-sigChan:
			a.logger.Info().
				Str("signal", sig.String()).
				Msg("Received shutdown signal")
			cancel()
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	// Wait for context cancellation
	g.Go(func() error {
		<-ctx.Done()
		return a.Stop()
	})

	// Wait for all goroutines to complete
	return g.Wait()
}

// Stop stops the application gracefully
func (a *App) Stop() error {
	a.logger.Info().Msg("Shutting down application")

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop SMTP server
	if err := a.smtpServer.Stop(); err != nil {
		a.logger.Error().Err(err).Msg("Error stopping SMTP server")
	}

	// Stop metrics server
	if a.config.EnableMetrics {
		if err := a.metricsServer.Stop(ctx); err != nil {
			a.logger.Error().Err(err).Msg("Error stopping metrics server")
		}
	}

	// Flush Sentry
	a.sentry.Flush()

	a.logger.Info().Msg("Application stopped")
	return nil
}
