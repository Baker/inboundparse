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
	config           *config.Config
	messageProcessor MessageProcessor
	metricsService   MetricsService
}

// NewSMTPBackend creates a new SMTP backend
func NewSMTPBackend(
	config *config.Config,
	messageProcessor MessageProcessor,
	metricsService MetricsService,
) SMTPBackend {
	return &smtpBackend{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
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

	// Create session
	session := &smtpSession{
		config:           b.config,
		messageProcessor: b.messageProcessor,
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
	heloName         string
	from             string
	to               []string
}

// Hello handles the HELO/EHLO command
func (s *smtpSession) Hello(heloName string) error {
	s.heloName = heloName
	return nil
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
	// Process the message with HELO and envelope sender information
	err := s.messageProcessor.ProcessMessage(context.Background(), r, s.heloName, s.from)
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
	// Note: heloName persists across RSET commands per RFC 5321
}

// Logout handles the QUIT command
func (s *smtpSession) Logout() error {
	// Decrement active sessions
	if s.metricsService != nil {
		s.metricsService.DecrementActiveSessions()
	}
	return nil
}
