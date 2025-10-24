package smtp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"inboundparse/internal/config"
	"inboundparse/internal/observability"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/pires/go-proxyproto"
)

// ServerConfig holds SMTP server configuration
type ServerConfig struct {
	ListenAddr     string
	ListenAddrTLS  string
	ServerName     string
	MaxMessageSize int64
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	CertFile       string
	KeyFile        string
	MaxRecipients  int
}

// SMTPServer manages SMTP servers
type SMTPServer struct {
	config    ServerConfig
	server    *smtp.Server
	tlsServer *smtp.Server
	logger    observability.Logger
}

// NewSMTPServer creates a new SMTP server
func NewSMTPServer(
	config ServerConfig,
	backend *Backend,
	logger observability.Logger,
) (*SMTPServer, error) {
	var tlsServer *smtp.Server

	server := smtp.NewServer(backend)
	server.Addr = config.ListenAddr
	server.Domain = config.ServerName
	server.MaxMessageBytes = config.MaxMessageSize
	server.MaxRecipients = config.MaxRecipients
	server.AllowInsecureAuth = false // Disallow AUTH before TLS
	server.ReadTimeout = config.ReadTimeout
	server.WriteTimeout = config.WriteTimeout

	// Optionally enable TLS
	if config.CertFile != "" && config.KeyFile != "" {
		logger.Debug().
			Str("cert_file", config.CertFile).
			Str("key_file", config.KeyFile).
			Msg("Loading TLS certificate")
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsServer = smtp.NewServer(backend)
		tlsServer.Addr = config.ListenAddrTLS
		tlsServer.Domain = config.ServerName
		tlsServer.WriteTimeout = config.WriteTimeout
		tlsServer.ReadTimeout = config.ReadTimeout
		tlsServer.MaxMessageBytes = config.MaxMessageSize
		tlsServer.MaxRecipients = config.MaxRecipients
		tlsServer.AllowInsecureAuth = false
		tlsServer.TLSConfig = &tls.Config{
			ServerName:   config.ServerName,
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		server.TLSConfig = tlsServer.TLSConfig
	}

	return &SMTPServer{
		config:    config,
		server:    server,
		tlsServer: tlsServer,
		logger:    logger,
	}, nil
}

// Start starts the SMTP server
func (s *SMTPServer) Start() error {
	if s.tlsServer != nil {
		go func() {
			s.logger.Info().
				Str("address", s.config.ListenAddr).
				Msg("Starting plain SMTP server")
			if err := s.listenAndServeWithProxy(s.server, s.config.ListenAddr); err != nil {
				s.logger.Error().
					Err(err).
					Msg("Plain SMTP server stopped with error")
			}
		}()
		s.logger.Info().
			Str("address", s.config.ListenAddrTLS).
			Msg("Starting TLS SMTP server")
		return s.listenAndServeWithProxy(s.tlsServer, s.config.ListenAddrTLS)
	}
	s.logger.Info().
		Str("address", s.config.ListenAddr).
		Msg("Starting plain SMTP server")
	return s.listenAndServeWithProxy(s.server, s.config.ListenAddr)
}

// listenAndServeWithProxy starts the SMTP server with PROXY protocol support
func (s *SMTPServer) listenAndServeWithProxy(server *smtp.Server, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	proxyListener := &proxyproto.Listener{
		Listener: ln,
		Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
			// Accept PROXY protocol from any source
			// TODO: In production, you might want to restrict this to Fly.io's proxy IPs
			return proxyproto.USE, nil
		},
	}

	return server.Serve(proxyListener)
}

// Stop stops the SMTP server
func (s *SMTPServer) Stop() error {
	var closeErrors error
	if s.server != nil {
		if err := s.server.Close(); err != nil {
			// Ignore "server already closed" errors for idempotency
			if !strings.Contains(err.Error(), "already closed") {
				closeErrors = errors.Join(closeErrors, err)
			}
		}
	}
	if s.tlsServer != nil {
		if err := s.tlsServer.Close(); err != nil {
			// Ignore "server already closed" errors for idempotency
			if !strings.Contains(err.Error(), "already closed") {
				closeErrors = errors.Join(closeErrors, err)
			}
		}
	}
	return closeErrors
}

// NewSMTPServerFromConfig creates a new SMTP server from application config
func NewSMTPServerFromConfig(
	appConfig *config.Config,
	backend *Backend,
	logger observability.Logger,
) (*SMTPServer, error) {
	serverConfig := ServerConfig{
		ListenAddr:     appConfig.ListenAddr,
		ListenAddrTLS:  appConfig.ListenAddrTLS,
		ServerName:     appConfig.ServerName,
		MaxMessageSize: appConfig.MaxMessageSize,
		ReadTimeout:    appConfig.ReadTimeout,
		WriteTimeout:   appConfig.WriteTimeout,
		CertFile:       appConfig.CertFile,
		KeyFile:        appConfig.KeyFile,
		MaxRecipients:  100, // Default value
	}

	return NewSMTPServer(serverConfig, backend, logger)
}
