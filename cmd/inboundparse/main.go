package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/getsentry/sentry-go"
	"github.com/inboundparse/inboundparse/internal/config"
	"github.com/inboundparse/inboundparse/internal/server"
	"github.com/inboundparse/inboundparse/internal/service"
	"go.uber.org/zap"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		// Use basic logging for configuration errors
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize structured logger
	logger, err := service.NewLoggerService(cfg.Server.Verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
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
		logger.Fatal(ctx, "Webhook URL is required")
	}

	// Create services
	metricsService := service.NewMetricsService(cfg.Metrics.Enabled)
	webhookService := service.NewWebhookService(cfg.Webhook.URL, cfg.Webhook.Username, cfg.Webhook.Password)
	authService := service.NewAuthService(cfg.Auth.EnableSPF, cfg.Auth.EnableDKIM, cfg.Auth.EnableDMARC)

	// Create SMTP backend with a message processor factory
	backend := &smtpBackendWithServices{
		config:         cfg,
		webhookService: webhookService,
		authService:    authService,
		metricsService: metricsService,
	}

	// Create server
	srv := server.NewServer(cfg, backend, metricsService, logger)

	// Run server with graceful shutdown
	if err := srv.Run(ctx); err != nil {
		logger.Fatal(ctx, "Server error", zap.Error(err))
	}
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

// smtpBackendWithServices implements the SMTPBackend interface
type smtpBackendWithServices struct {
	config         *config.Config
	webhookService service.WebhookService
	authService    service.AuthService
	metricsService service.MetricsService
}

// NewSession creates a new SMTP session
func (b *smtpBackendWithServices) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	// Extract remote IP
	var remoteIP net.IP
	if conn != nil {
		if addr := conn.Conn().RemoteAddr(); addr != nil {
			if tcpAddr, ok := addr.(*net.TCPAddr); ok {
				remoteIP = tcpAddr.IP
			}
		}
	}

	// Create message processor with remote IP
	processor := service.NewMessageProcessor(
		b.webhookService,
		b.authService,
		b.metricsService,
		remoteIP,
	)

	// Create session
	session := &smtpSessionWithServices{
		config:           b.config,
		messageProcessor: processor,
		metricsService:   b.metricsService,
		remoteIP:         remoteIP,
	}

	// Increment active sessions
	if b.metricsService != nil {
		b.metricsService.IncrementActiveSessions()
	}

	return session, nil
}

// smtpSessionWithServices implements the SMTP session
type smtpSessionWithServices struct {
	config           *config.Config
	messageProcessor service.MessageProcessor
	metricsService   service.MetricsService
	remoteIP         net.IP
	from             string
	to               []string
}

// AuthPlain handles PLAIN authentication
func (s *smtpSessionWithServices) AuthPlain(username, password string) error {
	// For now, we don't implement authentication
	return nil
}

// Mail handles the MAIL FROM command
func (s *smtpSessionWithServices) Mail(from string, opts *smtp.MailOptions) error {
	s.from = from
	return nil
}

// Rcpt handles the RCPT TO command
func (s *smtpSessionWithServices) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

// Data handles the DATA command
func (s *smtpSessionWithServices) Data(r io.Reader) error {
	// Process the message
	err := s.messageProcessor.ProcessMessage(context.Background(), r)
	if err != nil {
		// Record failed message
		if s.metricsService != nil {
			s.metricsService.IncrementMessagesFailed()
		}
		return fmt.Errorf("failed to process message: %w", err)
	}

	// Record successful message
	if s.metricsService != nil {
		s.metricsService.IncrementSMTPMessages()
	}

	return nil
}

// Reset resets the session state
func (s *smtpSessionWithServices) Reset() {
	s.from = ""
	s.to = nil
}

// Logout handles the QUIT command
func (s *smtpSessionWithServices) Logout() error {
	// Decrement active sessions
	if s.metricsService != nil {
		s.metricsService.DecrementActiveSessions()
	}
	return nil
}
