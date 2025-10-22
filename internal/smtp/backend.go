package smtp

import (
	"context"
	"inboundparse/internal/observability"
	"inboundparse/internal/processor"
	"io"
	"net"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
)

// BackendConfig holds backend configuration
type BackendConfig struct {
	MaxRecipients int
}

// Backend implements smtp.Backend
type Backend struct {
	config           BackendConfig
	messageProcessor *processor.MessageProcessor
	metrics          observability.MetricsCollector
	logger           observability.Logger
}

// NewBackend creates a new SMTP backend
func NewBackend(
	config BackendConfig,
	messageProcessor *processor.MessageProcessor,
	metrics observability.MetricsCollector,
	logger observability.Logger,
) *Backend {
	return &Backend{
		config:           config,
		messageProcessor: messageProcessor,
		metrics:          metrics,
		logger:           logger,
	}
}

// NewSession is called when a new SMTP session is created
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	sessionID := uuid.New().String()
	remote := "<unknown>"
	if c != nil && c.Conn() != nil && c.Conn().RemoteAddr() != nil {
		remote = c.Conn().RemoteAddr().String()
	}

	// Track connection metrics
	cleanup := b.metrics.TrackConnection()

	b.logger.Debug().
		Str("session_id", sessionID).
		Str("remote_addr", remote).
		Msg("New SMTP session started")

	return &Session{
		config:           b.config,
		messageProcessor: b.messageProcessor,
		metrics:          b.metrics,
		logger:           b.logger,
		conn:             c,
		sessionID:        sessionID,
		cleanup:          cleanup,
	}, nil
}

// Session implements smtp.Session
type Session struct {
	config           BackendConfig
	messageProcessor *processor.MessageProcessor
	metrics          observability.MetricsCollector
	logger           observability.Logger
	conn             *smtp.Conn
	from             string
	to               []string
	sessionID        string
	cleanup          func() // cleanup function for connection tracking
}

// AuthPlain handles PLAIN authentication (we'll accept any or none)
func (s *Session) AuthPlain(username, password string) error {
	s.logger.Debug().
		Str("session_id", s.sessionID).
		Str("username", username).
		Msg("AUTH PLAIN attempted")
	// Accept any authentication or no authentication
	return nil
}

// Mail is called when the MAIL FROM command is received
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	s.logger.Debug().
		Str("session_id", s.sessionID).
		Str("from", from).
		Msg("MAIL FROM received")
	s.from = from
	return nil
}

// Rcpt is called when a RCPT TO command is received
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.logger.Debug().
		Str("session_id", s.sessionID).
		Str("to", to).
		Msg("RCPT TO received")
	s.to = append(s.to, to)
	return nil
}

// Data is called when the DATA command is received
func (s *Session) Data(r io.Reader) error {
	s.logger.Info().
		Str("session_id", s.sessionID).
		Str("from", s.from).
		Strs("to", s.to).
		Msg("Receiving message data")

	// Track active session
	sessionCleanup := s.metrics.TrackSession()
	defer sessionCleanup()

	// Get remote IP
	var remoteIP net.IP
	if s.conn != nil && s.conn.Conn() != nil {
		addr := s.conn.Conn().RemoteAddr()
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			remoteIP = tcpAddr.IP
		}
	}

	// Process the email message
	ctx := context.Background() // TODO: Add proper context with timeout
	return s.messageProcessor.ProcessMessage(ctx, r, s.from, s.to, s.sessionID, remoteIP)
}

// Reset is called when the RSET command is received
func (s *Session) Reset() {
	s.logger.Debug().
		Str("session_id", s.sessionID).
		Msg("Session reset")
	s.from = ""
	s.to = nil
}

// Logout is called when the session is closed
func (s *Session) Logout() error {
	s.logger.Debug().
		Str("session_id", s.sessionID).
		Msg("Session logout")

	// Clean up connection tracking
	if s.cleanup != nil {
		s.cleanup()
	}

	return nil
}
