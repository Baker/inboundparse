package main

import (
	"crypto/tls"
	"log"
	"time"

	"github.com/emersion/go-smtp"
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
}

type SMTPServer struct {
	config    *ServerConfig
	server    *smtp.Server
	tlsServer *smtp.Server
}

func NewSMTPServer(config *ServerConfig) *SMTPServer {
	var tlsServer *smtp.Server
	backend := &Backend{
		config: config,
	}

	server := smtp.NewServer(backend)
	server.Addr = config.ListenAddr
	server.Domain = config.ServerName
	server.MaxMessageBytes = config.MaxMessageSize
	server.MaxRecipients = 100       // Allow multiple recipients
	server.AllowInsecureAuth = false // Allow auth without TLS
	server.ReadTimeout = time.Duration(config.ReadTimeout) * time.Second
	server.WriteTimeout = time.Duration(config.WriteTimeout) * time.Second

	// Optionally enable TLS
	if config.CertFile != "" && config.KeyFile != "" {
		log.Printf("Loading TLS certificate from %s and %s", config.CertFile, config.KeyFile)
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			log.Fatalf("Failed to load TLS certificate: %v", err)
			return nil
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
		}
		server.TLSConfig = tlsServer.TLSConfig
	}

	return &SMTPServer{
		config:    config,
		server:    server,
		tlsServer: tlsServer,
	}
}

func (s *SMTPServer) Start() error {
	log.Printf("SMTP server listening on %s", s.config.ListenAddr)
	if s.server.TLSConfig != nil {
		go func() {
			log.Printf("Starting plainServer at %s", s.config.ListenAddr)
			if err := s.server.ListenAndServe(); err != nil {
				log.Fatal(err)
			}
		}()
		log.Printf("Starting tlsServer at %s", s.config.ListenAddrTLS)
		return s.tlsServer.ListenAndServeTLS()
	}
	log.Printf("Starting plainServer at %s", s.config.ListenAddr)
	return s.server.ListenAndServe()
}

func (s *SMTPServer) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	if s.tlsServer != nil {
		return s.tlsServer.Close()
	}
	return nil
}
