package main

import (
	"io"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Backend implements smtp.Backend
type Backend struct {
	config *ServerConfig
}

// NewSession is called when a new SMTP session is created
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	sessionID := uuid.New().String()
	remote := "<unknown>"
	if c != nil && c.Conn() != nil && c.Conn().RemoteAddr() != nil {
		remote = c.Conn().RemoteAddr().String()
	}

	// Track connection metrics
	cleanup := TrackConnection()

	log.Debug().
		Str("session_id", sessionID).
		Str("remote_addr", remote).
		Msg("New SMTP session started")

	return &Session{
		config:    b.config,
		conn:      c,
		sessionID: sessionID,
		cleanup:   cleanup,
	}, nil
}

// Session implements smtp.Session
type Session struct {
	config    *ServerConfig
	conn      *smtp.Conn
	from      string
	to        []string
	sessionID string
	cleanup   func() // cleanup function for connection tracking
}

// AuthPlain handles PLAIN authentication (we'll accept any or none)
func (s *Session) AuthPlain(username, password string) error {
	log.Debug().
		Str("session_id", s.sessionID).
		Str("username", username).
		Msg("AUTH PLAIN attempted")
	// Accept any authentication or no authentication
	return nil
}

// Mail is called when the MAIL FROM command is received
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	log.Debug().
		Str("session_id", s.sessionID).
		Str("from", from).
		Msg("MAIL FROM received")
	s.from = from
	return nil
}

// Rcpt is called when a RCPT TO command is received
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	log.Debug().
		Str("session_id", s.sessionID).
		Str("to", to).
		Msg("RCPT TO received")
	s.to = append(s.to, to)
	return nil
}

// Data is called when the DATA command is received
func (s *Session) Data(r io.Reader) error {
	log.Info().
		Str("session_id", s.sessionID).
		Str("from", s.from).
		Strs("to", s.to).
		Msg("Receiving message data")

	// Track active session
	sessionCleanup := TrackSession()
	defer sessionCleanup()

	// Process the email message
	processor := &MessageProcessor{
		config:    s.config,
		from:      s.from,
		to:        s.to,
		conn:      s.conn,
		sessionID: s.sessionID,
	}

	return processor.ProcessMessage(r)
}

// Reset is called when the RSET command is received
func (s *Session) Reset() {
	log.Debug().
		Str("session_id", s.sessionID).
		Msg("Session reset")
	s.from = ""
	s.to = nil
}

// Logout is called when the session is closed
func (s *Session) Logout() error {
	log.Debug().
		Str("session_id", s.sessionID).
		Msg("Session logout")

	// Clean up connection tracking
	if s.cleanup != nil {
		s.cleanup()
	}

	return nil
}
