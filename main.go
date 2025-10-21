package main

import (
	"flag"
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
	// Sentry flags
	enableSentry  = flag.Bool("enable-sentry", false, "Enable Sentry error tracking")
	sentryDSN     = flag.String("sentry-dsn", "", "Sentry DSN for error tracking")
	sentryEnv     = flag.String("sentry-env", "production", "Sentry environment")
	sentryRelease = flag.String("sentry-release", "", "Sentry release version")
	// Metrics flags
	enableMetrics   = flag.Bool("enable-metrics", false, "Enable Prometheus metrics")
	metricsAddr     = flag.String("metrics-addr", "0.0.0.0:9090", "Metrics server listen address")
	metricsAPIKey   = flag.String("metrics-api-key", "", "Metrics API key for Bearer token authentication")
	metricsUsername = flag.String("metrics-username", "", "Metrics username for Basic authentication")
	metricsPassword = flag.String("metrics-password", "", "Metrics password for Basic authentication")
)

// setEnvString sets a string flag from environment variable if present
func setEnvString(envKey string, target *string) {
	if env := os.Getenv(envKey); env != "" {
		*target = env
	}
}

// setEnvBool sets a bool flag from environment variable if present
func setEnvBool(envKey string, target *bool) {
	if env := os.Getenv(envKey); env != "" {
		*target = env == "true"
	}
}

// loadEnvOverrides loads configuration from environment variables
func loadEnvOverrides() {
	loadCoreConfig()
	loadAuthConfig()
	loadSentryConfig()
	loadMetricsConfig()
}

// loadCoreConfig loads core SMTP configuration from environment
func loadCoreConfig() {
	setEnvString("LISTEN_ADDR", listenAddr)
	setEnvString("LISTEN_ADDR_TLS", listenAddrTLS)
	setEnvString("WEBHOOK_URL", webhookURL)
	setEnvString("WEBHOOK_USER", webhookUser)
	setEnvString("WEBHOOK_PASS", webhookPass)
	setEnvString("SERVER_NAME", serverName)
	setEnvString("CERT_FILE", certFile)
	setEnvString("KEY_FILE", keyFile)
	setEnvBool("VERBOSE", verbose)
}

// loadAuthConfig loads email authentication configuration from environment
func loadAuthConfig() {
	setEnvBool("ENABLE_SPF", enableSPF)
	setEnvBool("ENABLE_DKIM", enableDKIM)
	setEnvBool("ENABLE_DMARC", enableDMARC)
}

// loadSentryConfig loads Sentry configuration from environment
func loadSentryConfig() {
	setEnvBool("ENABLE_SENTRY", enableSentry)
	setEnvString("SENTRY_DSN", sentryDSN)
	setEnvString("SENTRY_ENV", sentryEnv)
	setEnvString("SENTRY_RELEASE", sentryRelease)
}

// loadMetricsConfig loads Prometheus metrics configuration from environment
func loadMetricsConfig() {
	setEnvBool("ENABLE_METRICS", enableMetrics)
	setEnvString("METRICS_ADDR", metricsAddr)
	setEnvString("METRICS_API_KEY", metricsAPIKey)
	setEnvString("METRICS_USERNAME", metricsUsername)
	setEnvString("METRICS_PASSWORD", metricsPassword)
}

func main() {
	if os.Getenv("INBOUNDPARSE_TEST_EXIT") == "1" {
		return
	}
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		logger.Info().Err(err).Msg("Failed to load .env file")
	}

	flag.Parse()

	// Initialize logger first so all subsequent logs are structured
	InitLogger(*verbose)

	// Override with environment variables if set
	loadEnvOverrides()

	if *webhookURL == "" {
		logger.Fatal().Msg("Webhook URL is required. Use -webhook flag or WEBHOOK_URL environment variable")
	}

	config := &ServerConfig{
		ListenAddr:      *listenAddr,
		ListenAddrTLS:   *listenAddrTLS,
		WebhookURL:      *webhookURL,
		WebhookUser:     *webhookUser,
		WebhookPass:     *webhookPass,
		ServerName:      *serverName,
		MaxMessageSize:  *maxMessageSize,
		ReadTimeout:     *readTimeout,
		WriteTimeout:    *writeTimeout,
		EnableSPF:       *enableSPF,
		EnableDKIM:      *enableDKIM,
		EnableDMARC:     *enableDMARC,
		Verbose:         *verbose,
		CertFile:        *certFile,
		KeyFile:         *keyFile,
		EnableSentry:    *enableSentry,
		SentryDSN:       *sentryDSN,
		SentryEnv:       *sentryEnv,
		SentryRelease:   *sentryRelease,
		EnableMetrics:   *enableMetrics,
		MetricsAddr:     *metricsAddr,
		MetricsAPIKey:   *metricsAPIKey,
		MetricsUsername: *metricsUsername,
		MetricsPassword: *metricsPassword,
	}

	// Initialize Sentry
	if err := InitSentry(config); err != nil {
		logger.Error().Err(err).Msg("Failed to initialize Sentry")
	}
	defer FlushSentry()

	// Initialize and start metrics server
	if config.EnableMetrics {
		metricsServer := NewMetricsServer(config)
		if err := metricsServer.Start(); err != nil {
			logger.Error().Err(err).Msg("Failed to start metrics server")
		}
	}

	server, err := NewSMTPServer(config)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize SMTP server")
	}

	logger.Info().
		Str("smtp_address", *listenAddr).
		Str("smtp_tls_address", *listenAddrTLS).
		Str("webhook_url", *webhookURL).
		Bool("spf_enabled", *enableSPF).
		Bool("dkim_enabled", *enableDKIM).
		Bool("dmarc_enabled", *enableDMARC).
		Bool("metrics_enabled", *enableMetrics).
		Bool("sentry_enabled", *enableSentry).
		Bool("verbose", *verbose).
		Msg("Starting InboundParse SMTP server")

	if *certFile != "" && *keyFile != "" {
		logger.Info().
			Str("cert_file", *certFile).
			Str("key_file", *keyFile).
			Msg("TLS certificates configured")
	}

	if err := server.Start(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start SMTP server")
	}
}
