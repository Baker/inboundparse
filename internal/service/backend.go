package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/inboundparse/inboundparse/internal/config"
	"go.uber.org/zap"
)

// smtpBackend implements the SMTPBackend interface
type smtpBackend struct {
	config         *config.Config
	webhookService WebhookService
	authService    AuthService
	metricsService MetricsService
	logger         LoggerService
}

// NewSMTPBackend creates a new SMTP backend
func NewSMTPBackend(
	config *config.Config,
	webhookService WebhookService,
	authService AuthService,
	metricsService MetricsService,
	logger LoggerService,
) SMTPBackend {
	return &smtpBackend{
		config:         config,
		webhookService: webhookService,
		authService:    authService,
		metricsService: metricsService,
		logger:         logger,
	}
}

// NewSession creates a new SMTP session
func (b *smtpBackend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	// Generate correlation ID for this session
	correlationID := uuid.New().String()

	// Create context with correlation ID
	ctx := WithCorrelationID(context.Background(), correlationID)

	// Extract remote IP
	var remoteIP net.IP
	var remoteAddr string
	if conn != nil {
		if addr := conn.Conn().RemoteAddr(); addr != nil {
			remoteAddr = addr.String()
			if tcpAddr, ok := addr.(*net.TCPAddr); ok {
				remoteIP = tcpAddr.IP
			}
		}
	}

	if b.logger != nil {
		b.logger.Info(ctx, "new SMTP session created",
			zap.String("remote_ip", remoteIP.String()),
			zap.String("remote_addr", remoteAddr),
			zap.String("correlation_id", correlationID),
		)
	}

	// Create message processor with remote IP and logger
	processor := NewMessageProcessor(
		b.webhookService,
		b.authService,
		b.metricsService,
		remoteIP,
		b.logger,
	)

	// Create session
	session := &smtpSession{
		config:           b.config,
		messageProcessor: processor,
		metricsService:   b.metricsService,
		logger:           b.logger,
		remoteIP:         remoteIP,
		ctx:              ctx,
		correlationID:    correlationID,
	}

	// Increment active sessions
	if b.metricsService != nil {
		b.metricsService.IncrementActiveSessions()
	}

	return session, nil
}

// smtpSession implements the SMTPHandler interface
type smtpSession struct {
	config           *config.Config
	messageProcessor MessageProcessor
	metricsService   MetricsService
	logger           LoggerService
	remoteIP         net.IP
	ctx              context.Context
	correlationID    string
	from             string
	to               []string
}

// AuthPlain handles PLAIN authentication
func (s *smtpSession) AuthPlain(username, password string) error {
	if s.logger != nil {
		s.logger.Debug(s.ctx, "SMTP AUTH PLAIN attempted",
			zap.String("username", username),
		)
	}
	// For now, we don't implement authentication
	// In a real implementation, you'd validate credentials
	return nil
}

// Mail handles the MAIL FROM command
func (s *smtpSession) Mail(from string, opts *smtp.MailOptions) error {
	s.from = from

	if s.logger != nil {
		s.logger.Info(s.ctx, "MAIL FROM command received",
			zap.String("from", from),
		)
	}

	return nil
}

// Rcpt handles the RCPT TO command
func (s *smtpSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.to = append(s.to, to)

	if s.logger != nil {
		s.logger.Info(s.ctx, "RCPT TO command received",
			zap.String("to", to),
			zap.Int("total_recipients", len(s.to)),
		)
	}

	return nil
}

// Data handles the DATA command
func (s *smtpSession) Data(r io.Reader) error {
	startTime := time.Now()

	if s.logger != nil {
		s.logger.Info(s.ctx, "DATA command received, processing message",
			zap.String("from", s.from),
			zap.Strings("to", s.to),
		)
	}

	// Process the message using session context
	err := s.messageProcessor.ProcessMessage(s.ctx, r)
	duration := time.Since(startTime)

	if err != nil {
		// Record failed message
		if s.metricsService != nil {
			s.metricsService.IncrementMessagesFailed()
		}

		if s.logger != nil {
			s.logger.Error(s.ctx, "message processing failed",
				zap.String("from", s.from),
				zap.Strings("to", s.to),
				zap.Duration("duration", duration),
				zap.Error(err),
			)
		}

		return fmt.Errorf("failed to process message: %w", err)
	}

	// Record successful message
	if s.metricsService != nil {
		s.metricsService.IncrementSMTPMessages()
	}

	if s.logger != nil {
		s.logger.Info(s.ctx, "message processed successfully",
			zap.String("from", s.from),
			zap.Strings("to", s.to),
			zap.Duration("duration", duration),
		)
	}

	return nil
}

// Reset resets the session state
func (s *smtpSession) Reset() {
	if s.logger != nil {
		s.logger.Debug(s.ctx, "RSET command received, resetting session state")
	}

	s.from = ""
	s.to = nil
}

// Logout handles the QUIT command
func (s *smtpSession) Logout() error {
	if s.logger != nil {
		s.logger.Info(s.ctx, "QUIT command received, terminating session")
	}

	// Decrement active sessions
	if s.metricsService != nil {
		s.metricsService.DecrementActiveSessions()
	}

	return nil
}
