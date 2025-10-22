package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/pires/go-proxyproto"
	"github.com/rs/zerolog/log"
)

type ServerConfig struct {
	ListenAddr     string
	ListenAddrTLS  string
	WebhookURL     string
	WebhookUser    string
	WebhookPass    string
	ServerName     string
	MaxMessageSize int64
	ReadTimeout    int
	WriteTimeout   int
	EnableSPF      bool
	EnableDKIM     bool
	EnableDMARC    bool
	Verbose        bool
	CertFile       string
	KeyFile        string
	// Sentry configuration
	EnableSentry  bool
	SentryDSN     string
	SentryEnv     string
	SentryRelease string
	// Metrics configuration
	EnableMetrics   bool
	MetricsAddr     string
	MetricsAPIKey   string
	MetricsUsername string
	MetricsPassword string
}

type SMTPServer struct {
	config    *ServerConfig
	server    *smtp.Server
	tlsServer *smtp.Server
}

func NewSMTPServer(config *ServerConfig) (*SMTPServer, error) {
	var tlsServer *smtp.Server
	backend := &Backend{
		config: config,
	}

	server := smtp.NewServer(backend)
	server.Addr = config.ListenAddr
	server.Domain = config.ServerName
	server.MaxMessageBytes = config.MaxMessageSize
	server.MaxRecipients = 100       // Allow multiple recipients
	server.AllowInsecureAuth = false // Disallow AUTH before TLS
	server.ReadTimeout = time.Duration(config.ReadTimeout) * time.Second
	server.WriteTimeout = time.Duration(config.WriteTimeout) * time.Second

	// Optionally enable TLS
	if config.CertFile != "" && config.KeyFile != "" {
		log.Debug().
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
		tlsServer.WriteTimeout = time.Duration(config.WriteTimeout) * time.Second
		tlsServer.ReadTimeout = time.Duration(config.ReadTimeout) * time.Second
		tlsServer.MaxMessageBytes = config.MaxMessageSize
		tlsServer.MaxRecipients = 100
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
	}, nil
}

func (s *SMTPServer) Start() error {
	if s.tlsServer != nil {
		go func() {
			log.Info().
				Str("address", s.config.ListenAddr).
				Msg("Starting plain SMTP server")
			if err := s.listenAndServeWithProxy(s.server, s.config.ListenAddr); err != nil {
				log.Error().
					Err(err).
					Msg("Plain SMTP server stopped with error")
			}
		}()
		log.Info().
			Str("address", s.config.ListenAddrTLS).
			Msg("Starting TLS SMTP server")
		return s.listenAndServeWithProxy(s.tlsServer, s.config.ListenAddrTLS)
	}
	log.Info().
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

func (s *SMTPServer) Stop() error {
	var closeErrors error
	if s.server != nil {
		if err := s.server.Close(); err != nil {
			closeErrors = errors.Join(closeErrors, err)
		}
	}
	if s.tlsServer != nil {
		if err := s.tlsServer.Close(); err != nil {
			closeErrors = errors.Join(closeErrors, err)
		}
	}
	return closeErrors
}
