package service

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/emersion/go-smtp"
	"github.com/inboundparse/inboundparse/internal/config"
)

// smtpBackend implements the SMTPBackend interface
type smtpBackend struct {
	config         *config.Config
	webhookService WebhookService
	authService    AuthService
	metricsService MetricsService
}

// NewSMTPBackend creates a new SMTP backend
func NewSMTPBackend(
	config *config.Config,
	webhookService WebhookService,
	authService AuthService,
	metricsService MetricsService,
) SMTPBackend {
	return &smtpBackend{
		config:         config,
		webhookService: webhookService,
		authService:    authService,
		metricsService: metricsService,
	}
}

// NewSession creates a new SMTP session
func (b *smtpBackend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
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
	processor := NewMessageProcessor(
		b.webhookService,
		b.authService,
		b.metricsService,
		remoteIP,
	)

	// Create session
	session := &smtpSession{
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

// smtpSession implements the SMTPHandler interface
type smtpSession struct {
	config           *config.Config
	messageProcessor MessageProcessor
	metricsService   MetricsService
	remoteIP         net.IP
	from             string
	to               []string
}

// AuthPlain handles PLAIN authentication
func (s *smtpSession) AuthPlain(username, password string) error {
	// For now, we don't implement authentication
	// In a real implementation, you'd validate credentials
	return nil
}

// Mail handles the MAIL FROM command
func (s *smtpSession) Mail(from string, opts *smtp.MailOptions) error {
	s.from = from
	return nil
}

// Rcpt handles the RCPT TO command
func (s *smtpSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

// Data handles the DATA command
func (s *smtpSession) Data(r io.Reader) error {
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
func (s *smtpSession) Reset() {
	s.from = ""
	s.to = nil
}

// Logout handles the QUIT command
func (s *smtpSession) Logout() error {
	// Decrement active sessions
	if s.metricsService != nil {
		s.metricsService.DecrementActiveSessions()
	}
	return nil
}
