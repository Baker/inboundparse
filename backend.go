package main

import (
	"io"
	"log"

	"github.com/emersion/go-smtp"
)

// Backend implements smtp.Backend
type Backend struct {
	config *ServerConfig
}

// NewSession is called when a new SMTP session is created
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	if b.config.Verbose {
		log.Printf("New SMTP session from %s", c.Conn().RemoteAddr().String())
	}
	return &Session{
		config: b.config,
		conn:   c,
	}, nil
}

// Session implements smtp.Session
type Session struct {
	config *ServerConfig
	conn   *smtp.Conn
	from   string
	to     []string
}

// AuthPlain handles PLAIN authentication (we'll accept any or none)
func (s *Session) AuthPlain(username, password string) error {
	if s.config.Verbose {
		log.Printf("AUTH PLAIN attempted with username: %s", username)
	}
	// Accept any authentication or no authentication
	return nil
}

// Mail is called when the MAIL FROM command is received
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	if s.config.Verbose {
		log.Printf("MAIL FROM: %s", from)
	}
	s.from = from
	return nil
}

// Rcpt is called when a RCPT TO command is received
func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if s.config.Verbose {
		log.Printf("RCPT TO: %s", to)
	}
	s.to = append(s.to, to)
	return nil
}

// Data is called when the DATA command is received
func (s *Session) Data(r io.Reader) error {
	if s.config.Verbose {
		log.Printf("Receiving message data from %s to %v", s.from, s.to)
	}

	// Process the email message
	processor := &MessageProcessor{
		config: s.config,
		from:   s.from,
		to:     s.to,
		conn:   s.conn,
	}

	return processor.ProcessMessage(r)
}

// Reset is called when the RSET command is received
func (s *Session) Reset() {
	if s.config.Verbose {
		log.Println("Session reset")
	}
	s.from = ""
	s.to = nil
}

// Logout is called when the session is closed
func (s *Session) Logout() error {
	if s.config.Verbose {
		log.Println("Session logout")
	}
	return nil
}
