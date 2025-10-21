package main

import (
	"flag"
	"log"
	"os"

	"github.com/joho/godotenv"
)

var (
	listenAddr     = flag.String("listen", "0.0.0.0:25", "SMTP server listen address")
	listenAddrTLS  = flag.String("listen-tls", "0.0.0.0:587", "SMTP server listen address for TLS")
	webhookURL     = flag.String("webhook", "", "Webhook URL to send email data to")
	webhookUser    = flag.String("webhook-user", "", "Basic auth username for webhook")
	webhookPass    = flag.String("webhook-pass", "", "Basic auth password for webhook")
	serverName     = flag.String("name", "mx.inboundparse.com", "SMTP server name")
	maxMessageSize = flag.Int64("max-size", 10*1024*1024, "Maximum message size in bytes")
	readTimeout    = flag.Int("read-timeout", 30, "Read timeout in seconds")
	writeTimeout   = flag.Int("write-timeout", 30, "Write timeout in seconds")
	enableSPF      = flag.Bool("enable-spf", true, "Enable SPF validation")
	enableDKIM     = flag.Bool("enable-dkim", true, "Enable DKIM validation")
	enableDMARC    = flag.Bool("enable-dmarc", true, "Enable DMARC validation")
	certFile       = flag.String("cert-file", "", "TLS certificate file")
	keyFile        = flag.String("key-file", "", "TLS key file")
	verbose        = flag.Bool("verbose", false, "Enable verbose logging")
)

func main() {
	if os.Getenv("INBOUNDPARSE_TEST_EXIT") == "1" {
		return
	}
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using default values")
	}

	flag.Parse()

	// Override with environment variables if set
	if env := os.Getenv("LISTEN_ADDR"); env != "" {
		*listenAddr = env
	}
	if env := os.Getenv("LISTEN_ADDR_TLS"); env != "" {
		*listenAddrTLS = env
	}
	if env := os.Getenv("WEBHOOK_URL"); env != "" {
		*webhookURL = env
	}
	if env := os.Getenv("WEBHOOK_USER"); env != "" {
		*webhookUser = env
	}
	if env := os.Getenv("WEBHOOK_PASS"); env != "" {
		*webhookPass = env
	}
	if env := os.Getenv("ENABLE_SPF"); env != "" {
		*enableSPF = env == "true"
	}
	if env := os.Getenv("ENABLE_DKIM"); env != "" {
		*enableDKIM = env == "true"
	}
	if env := os.Getenv("ENABLE_DMARC"); env != "" {
		*enableDMARC = env == "true"
	}
	if env := os.Getenv("VERBOSE"); env != "" {
		*verbose = env == "true"
	}
	if env := os.Getenv("CERT_FILE"); env != "" {
		*certFile = env
	}
	if env := os.Getenv("KEY_FILE"); env != "" {
		*keyFile = env
	}

	if *webhookURL == "" {
		log.Fatal("Webhook URL is required. Use -webhook flag or WEBHOOK_URL environment variable")
	}

	config := &ServerConfig{
		ListenAddr:     *listenAddr,
		ListenAddrTLS:  *listenAddrTLS,
		WebhookURL:     *webhookURL,
		WebhookUser:    *webhookUser,
		WebhookPass:    *webhookPass,
		ServerName:     *serverName,
		MaxMessageSize: *maxMessageSize,
		ReadTimeout:    *readTimeout,
		WriteTimeout:   *writeTimeout,
		EnableSPF:      *enableSPF,
		EnableDKIM:     *enableDKIM,
		EnableDMARC:    *enableDMARC,
		Verbose:        *verbose,
		CertFile:       *certFile,
		KeyFile:        *keyFile,
	}

	server, err := NewSMTPServer(config)
	if err != nil {
		log.Fatal("Failed to initialize SMTP server:", err)
	}

	log.Printf("Starting SMTP server on %s", *listenAddr)
	if *certFile != "" && *keyFile != "" {
		log.Printf("Starting TLS SMTP server on %s", *listenAddrTLS)
	}
	log.Printf("Webhook URL: %s", *webhookURL)
	log.Printf("SPF validation: %v", *enableSPF)
	log.Printf("DKIM validation: %v", *enableDKIM)
	log.Printf("DMARC validation: %v", *enableDMARC)
	log.Printf("Verbose: %v", *verbose)
	log.Printf("Cert File: %s", *certFile)
	log.Printf("Key File: %s", *keyFile)

	if err := server.Start(); err != nil {
		log.Fatal("Failed to start SMTP server:", err)
	}
}
