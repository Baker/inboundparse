package main

import (
	"crypto/tls"
	"log"
	"time"

	"github.com/emersion/go-smtp"
)

type ServerConfig struct {
	ListenAddr     string
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
}

type SMTPServer struct {
	config *ServerConfig
	server *smtp.Server
}

func NewSMTPServer(config *ServerConfig) *SMTPServer {
	backend := &Backend{
		config: config,
	}

	server := smtp.NewServer(backend)
	server.Addr = config.ListenAddr
	server.Domain = config.ServerName
	server.MaxMessageBytes = config.MaxMessageSize
	server.MaxRecipients = 100      // Allow multiple recipients
	server.AllowInsecureAuth = true // Allow auth without TLS
	server.ReadTimeout = time.Duration(config.ReadTimeout) * time.Second
	server.WriteTimeout = time.Duration(config.WriteTimeout) * time.Second

	// Optionally enable TLS
	server.TLSConfig = &tls.Config{
		ServerName: config.ServerName,
	}

	return &SMTPServer{
		config: config,
		server: server,
	}
}

func (s *SMTPServer) Start() error {
	log.Printf("SMTP server listening on %s", s.config.ListenAddr)
	return s.server.ListenAndServe()
}

func (s *SMTPServer) Stop() error {
	return s.server.Close()
}
