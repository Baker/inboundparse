package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/inboundparse/inboundparse/internal/config"
	"github.com/inboundparse/inboundparse/internal/service"
	"go.uber.org/zap"
)

// Server represents the SMTP server
type Server struct {
	config         *config.Config
	backend        service.SMTPBackend
	metricsService service.MetricsService
	logger         service.LoggerService
	smtpServer     *smtp.Server
	tlsServer      *smtp.Server
	metricsServer  *http.Server
}

// NewServer creates a new SMTP server
func NewServer(
	config *config.Config,
	backend service.SMTPBackend,
	metricsService service.MetricsService,
	logger service.LoggerService,
) *Server {
	return &Server{
		config:         config,
		backend:        backend,
		metricsService: metricsService,
		logger:         logger,
	}
}

// Start starts the SMTP server
func (s *Server) Start(ctx context.Context) error {
	// Start metrics server if enabled
	if s.config.Metrics.Enabled {
		if err := s.startMetricsServer(ctx); err != nil {
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
	}

	// Start SMTP servers
	if err := s.startSMTPServers(ctx); err != nil {
		return fmt.Errorf("failed to start SMTP servers: %w", err)
	}

	return nil
}

// startMetricsServer starts the metrics HTTP server
func (s *Server) startMetricsServer(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", service.MetricsHandler())
	mux.Handle("/health", service.HealthHandler())

	s.metricsServer = &http.Server{
		Addr:              s.config.Metrics.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}

	go func() {
		if err := s.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error(ctx, "Metrics server error", zap.Error(err))
		}
	}()

	s.logger.Info(ctx, "Starting metrics server", zap.String("addr", s.config.Metrics.Addr))
	return nil
}

// startSMTPServers starts the SMTP servers
func (s *Server) startSMTPServers(ctx context.Context) error {
	// Load TLS certificate if provided
	var tlsConfig *tls.Config
	if s.config.Server.CertFile != "" && s.config.Server.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.config.Server.CertFile, s.config.Server.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Create main SMTP server with STARTTLS support
	s.smtpServer = smtp.NewServer(s.backend)
	s.smtpServer.Addr = s.config.Server.ListenAddr
	s.smtpServer.Domain = s.config.Server.ServerName
	s.smtpServer.MaxMessageBytes = s.config.Server.MaxMessageSize
	s.smtpServer.ReadTimeout = s.config.Server.ReadTimeout
	s.smtpServer.WriteTimeout = s.config.Server.WriteTimeout
	s.smtpServer.AllowInsecureAuth = true
	
	// Enable STARTTLS if certificates are available
	if tlsConfig != nil {
		s.smtpServer.TLSConfig = tlsConfig
		s.smtpServer.EnableSMTPUTF8 = true
	}

	// Start main SMTP server with STARTTLS support
	go func() {
		s.logger.Info(ctx, "Starting SMTP server with STARTTLS", zap.String("addr", s.config.Server.ListenAddr))
		if err := s.smtpServer.ListenAndServe(); err != nil {
			s.logger.Error(ctx, "SMTP server error", zap.Error(err))
		}
	}()

	// Create separate TLS-only server on port 587 if certificates are provided
	if tlsConfig != nil {
		s.tlsServer = smtp.NewServer(s.backend)
		s.tlsServer.Addr = s.config.Server.ListenAddrTLS
		s.tlsServer.Domain = s.config.Server.ServerName
		s.tlsServer.MaxMessageBytes = s.config.Server.MaxMessageSize
		s.tlsServer.ReadTimeout = s.config.Server.ReadTimeout
		s.tlsServer.WriteTimeout = s.config.Server.WriteTimeout
		s.tlsServer.TLSConfig = tlsConfig
		s.tlsServer.AllowInsecureAuth = true
		s.tlsServer.EnableSMTPUTF8 = true

		go func() {
			s.logger.Info(ctx, "Starting TLS SMTP server", zap.String("addr", s.config.Server.ListenAddrTLS))
			if err := s.tlsServer.ListenAndServe(); err != nil {
				s.logger.Error(ctx, "TLS SMTP server error", zap.Error(err))
			}
		}()
	}

	return nil
}

// Stop stops the SMTP server
func (s *Server) Stop(ctx context.Context) error {
	var err error

	// Stop metrics server
	if s.metricsServer != nil {
		if stopErr := s.metricsServer.Shutdown(ctx); stopErr != nil {
			err = fmt.Errorf("failed to stop metrics server: %w", stopErr)
		}
	}

	// Stop SMTP servers
	if s.smtpServer != nil {
		if stopErr := s.smtpServer.Close(); stopErr != nil {
			if err != nil {
				err = fmt.Errorf("failed to stop SMTP server: %w", stopErr)
			}
		}
	}

	if s.tlsServer != nil {
		if stopErr := s.tlsServer.Close(); stopErr != nil {
			if err != nil {
				err = fmt.Errorf("failed to stop TLS SMTP server: %w", stopErr)
			}
		}
	}

	// Close metrics service
	if s.metricsService != nil {
		if closeErr := s.metricsService.Close(); closeErr != nil {
			if err != nil {
				err = fmt.Errorf("failed to close metrics service: %w", closeErr)
			}
		}
	}

	return err
}

// Run runs the server with graceful shutdown
func (s *Server) Run(ctx context.Context) error {
	// Start the server
	if err := s.Start(ctx); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	// Wait for shutdown signal
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	s.logger.Info(context.Background(), "Received shutdown signal")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Stop the server
	if err := s.Stop(shutdownCtx); err != nil {
		return fmt.Errorf("failed to stop server: %w", err)
	}

	s.logger.Info(context.Background(), "Server stopped gracefully")
	return nil
}
