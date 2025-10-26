package config

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	// SMTP Configuration
	ListenAddr     string
	ListenAddrTLS  string
	ServerName     string
	MaxMessageSize int64
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration

	// TLS Configuration
	CertFile string
	KeyFile  string

	// Webhook Configuration
	WebhookURL  string
	WebhookUser string
	WebhookPass string

	// Webhook Retry Configuration
	WebhookMaxRetries      int
	WebhookRetryDelay      time.Duration
	WebhookMaxRetryDelay   time.Duration
	WebhookRetryMultiplier float64

	// Webhook Rate Limiting Configuration
	WebhookRateLimitPerSecond int
	WebhookRateLimitBurst     int

	// Authentication Configuration
	EnableSPF   bool
	EnableDKIM  bool
	EnableDMARC bool

	// Observability Configuration
	Verbose bool

	// Sentry Configuration
	EnableSentry  bool
	SentryDSN     string
	SentryEnv     string
	SentryRelease string

	// Metrics Configuration
	EnableMetrics   bool
	MetricsAddr     string
	MetricsAPIKey   string
	MetricsUsername string
	MetricsPassword string
}

// Default values
const (
	DefaultListenAddr     = "0.0.0.0:25"
	DefaultListenAddrTLS  = "0.0.0.0:587"
	DefaultServerName     = "mx.inboundparse.com"
	DefaultMaxMessageSize = 10 * 1024 * 1024 // 10MB
	DefaultReadTimeout    = 30 * time.Second
	DefaultWriteTimeout   = 30 * time.Second
	DefaultMetricsAddr    = "0.0.0.0:9090"
	DefaultSentryEnv      = "production"
)

// Option is a functional option for configuring the application
type Option func(*Config)

// WithListenAddr sets the SMTP listen address
func WithListenAddr(addr string) Option {
	return func(c *Config) {
		c.ListenAddr = addr
	}
}

// WithListenAddrTLS sets the TLS SMTP listen address
func WithListenAddrTLS(addr string) Option {
	return func(c *Config) {
		c.ListenAddrTLS = addr
	}
}

// WithWebhookURL sets the webhook URL
func WithWebhookURL(url string) Option {
	return func(c *Config) {
		c.WebhookURL = url
	}
}

// WithWebhookAuth sets webhook authentication
func WithWebhookAuth(user, pass string) Option {
	return func(c *Config) {
		c.WebhookUser = user
		c.WebhookPass = pass
	}
}

// WithTLS sets TLS certificate files
func WithTLS(certFile, keyFile string) Option {
	return func(c *Config) {
		c.CertFile = certFile
		c.KeyFile = keyFile
	}
}

// WithAuth enables authentication checks
func WithAuth(spf, dkim, dmarc bool) Option {
	return func(c *Config) {
		c.EnableSPF = spf
		c.EnableDKIM = dkim
		c.EnableDMARC = dmarc
	}
}

// WithSentry enables Sentry error tracking
func WithSentry(dsn, env, release string) Option {
	return func(c *Config) {
		c.EnableSentry = true
		c.SentryDSN = dsn
		c.SentryEnv = env
		c.SentryRelease = release
	}
}

// WithMetrics enables Prometheus metrics
func WithMetrics(addr, apiKey, username, password string) Option {
	return func(c *Config) {
		c.EnableMetrics = true
		c.MetricsAddr = addr
		c.MetricsAPIKey = apiKey
		c.MetricsUsername = username
		c.MetricsPassword = password
	}
}

// WithVerbose enables verbose logging
func WithVerbose(verbose bool) Option {
	return func(c *Config) {
		c.Verbose = verbose
	}
}

// New creates a new Config with default values
func New(options ...Option) *Config {
	config := &Config{
		ListenAddr:     DefaultListenAddr,
		ListenAddrTLS:  DefaultListenAddrTLS,
		ServerName:     DefaultServerName,
		MaxMessageSize: DefaultMaxMessageSize,
		ReadTimeout:    DefaultReadTimeout,
		WriteTimeout:   DefaultWriteTimeout,
		MetricsAddr:    DefaultMetricsAddr,
		SentryEnv:      DefaultSentryEnv,
		EnableSPF:      true,
		EnableDKIM:     true,
		EnableDMARC:    true,
	}

	for _, option := range options {
		option(config)
	}

	return config
}

// LoadFromFlags loads configuration from command line flags
func LoadFromFlags() (*Config, error) {
	// Define flags
	var (
		listenAddr    = flag.String("listen", DefaultListenAddr, "SMTP server listen address")
		listenAddrTLS = flag.String("listen-tls", DefaultListenAddrTLS, "SMTP server listen address for TLS")
		webhookURL    = flag.String("webhook", "", "Webhook URL to send email data to")
		webhookUser   = flag.String("webhook-user", "", "Basic auth username for webhook")
		webhookPass   = flag.String("webhook-pass", "", "Basic auth password for webhook")
		// Webhook retry flags
		webhookMaxRetries      = flag.Int("webhook-max-retries", 3, "Maximum number of webhook retry attempts")
		webhookRetryDelay      = flag.Int("webhook-retry-delay", 1, "Initial webhook retry delay in seconds")
		webhookMaxRetryDelay   = flag.Int("webhook-max-retry-delay", 30, "Maximum webhook retry delay in seconds")
		webhookRetryMultiplier = flag.Float64("webhook-retry-multiplier", 2.0, "Webhook retry delay multiplier")
		// Webhook rate limiting flags
		webhookRateLimitPerSecond = flag.Int("webhook-rate-limit", 10, "Webhook requests per second rate limit")
		webhookRateLimitBurst     = flag.Int("webhook-rate-burst", 20, "Webhook rate limit burst capacity")
		serverName                = flag.String("name", DefaultServerName, "SMTP server name")
		maxMessageSize            = flag.Int64("max-size", DefaultMaxMessageSize, "Maximum message size in bytes")
		readTimeout               = flag.Int("read-timeout", int(DefaultReadTimeout.Seconds()), "Read timeout in seconds")
		writeTimeout              = flag.Int("write-timeout", int(DefaultWriteTimeout.Seconds()), "Write timeout in seconds")
		enableSPF                 = flag.Bool("enable-spf", true, "Enable SPF validation")
		enableDKIM                = flag.Bool("enable-dkim", true, "Enable DKIM validation")
		enableDMARC               = flag.Bool("enable-dmarc", true, "Enable DMARC validation")
		certFile                  = flag.String("cert-file", "", "TLS certificate file")
		keyFile                   = flag.String("key-file", "", "TLS key file")
		verbose                   = flag.Bool("verbose", false, "Enable verbose logging")
		// Sentry flags
		enableSentry  = flag.Bool("enable-sentry", false, "Enable Sentry error tracking")
		sentryDSN     = flag.String("sentry-dsn", "", "Sentry DSN for error tracking")
		sentryEnv     = flag.String("sentry-env", DefaultSentryEnv, "Sentry environment")
		sentryRelease = flag.String("sentry-release", "", "Sentry release version")
		// Metrics flags
		enableMetrics   = flag.Bool("enable-metrics", false, "Enable Prometheus metrics")
		metricsAddr     = flag.String("metrics-addr", DefaultMetricsAddr, "Metrics server listen address")
		metricsAPIKey   = flag.String("metrics-api-key", "", "Metrics API key for Bearer token authentication")
		metricsUsername = flag.String("metrics-username", "", "Metrics username for Basic authentication")
		metricsPassword = flag.String("metrics-password", "", "Metrics password for Basic authentication")
	)

	// Load .env file if present
	if err := godotenv.Load(); err != nil {
		// Ignore error if .env file doesn't exist - this is expected behavior
		_ = err
	}

	// Parse flags
	flag.Parse()

	// Override with environment variables
	overrideFromEnv("LISTEN_ADDR", listenAddr)
	overrideFromEnv("LISTEN_ADDR_TLS", listenAddrTLS)
	overrideFromEnv("WEBHOOK_URL", webhookURL)
	overrideFromEnv("WEBHOOK_USER", webhookUser)
	overrideFromEnv("WEBHOOK_PASS", webhookPass)
	overrideIntFromEnv("WEBHOOK_MAX_RETRIES", webhookMaxRetries)
	overrideIntFromEnv("WEBHOOK_RETRY_DELAY", webhookRetryDelay)
	overrideIntFromEnv("WEBHOOK_MAX_RETRY_DELAY", webhookMaxRetryDelay)
	overrideFloat64FromEnv("WEBHOOK_RETRY_MULTIPLIER", webhookRetryMultiplier)
	overrideIntFromEnv("WEBHOOK_RATE_LIMIT", webhookRateLimitPerSecond)
	overrideIntFromEnv("WEBHOOK_RATE_BURST", webhookRateLimitBurst)
	overrideFromEnv("SERVER_NAME", serverName)
	overrideFromEnv("CERT_FILE", certFile)
	overrideFromEnv("KEY_FILE", keyFile)
	overrideFromEnv("SENTRY_DSN", sentryDSN)
	overrideFromEnv("SENTRY_ENV", sentryEnv)
	overrideFromEnv("SENTRY_RELEASE", sentryRelease)
	overrideFromEnv("METRICS_ADDR", metricsAddr)
	overrideFromEnv("METRICS_API_KEY", metricsAPIKey)
	overrideFromEnv("METRICS_USERNAME", metricsUsername)
	overrideFromEnv("METRICS_PASSWORD", metricsPassword)

	overrideBoolFromEnv("VERBOSE", verbose)
	overrideBoolFromEnv("ENABLE_SPF", enableSPF)
	overrideBoolFromEnv("ENABLE_DKIM", enableDKIM)
	overrideBoolFromEnv("ENABLE_DMARC", enableDMARC)
	overrideBoolFromEnv("ENABLE_SENTRY", enableSentry)
	overrideBoolFromEnv("ENABLE_METRICS", enableMetrics)

	// Validate required fields
	if *webhookURL == "" {
		return nil, fmt.Errorf("webhook URL is required. Use -webhook flag or WEBHOOK_URL environment variable")
	}

	// Build config
	config := New(
		WithListenAddr(*listenAddr),
		WithListenAddrTLS(*listenAddrTLS),
		WithWebhookURL(*webhookURL),
		WithWebhookAuth(*webhookUser, *webhookPass),
		WithTLS(*certFile, *keyFile),
		WithAuth(*enableSPF, *enableDKIM, *enableDMARC),
		WithVerbose(*verbose),
	)

	// Set webhook retry and rate limiting configuration
	config.WebhookMaxRetries = *webhookMaxRetries
	config.WebhookRetryDelay = time.Duration(*webhookRetryDelay) * time.Second
	config.WebhookMaxRetryDelay = time.Duration(*webhookMaxRetryDelay) * time.Second
	config.WebhookRetryMultiplier = *webhookRetryMultiplier
	config.WebhookRateLimitPerSecond = *webhookRateLimitPerSecond
	config.WebhookRateLimitBurst = *webhookRateLimitBurst

	// Set additional fields
	config.ServerName = *serverName
	config.MaxMessageSize = *maxMessageSize
	config.ReadTimeout = time.Duration(*readTimeout) * time.Second
	config.WriteTimeout = time.Duration(*writeTimeout) * time.Second

	// Sentry configuration
	if *enableSentry {
		config.EnableSentry = true
		config.SentryDSN = *sentryDSN
		config.SentryEnv = *sentryEnv
		config.SentryRelease = *sentryRelease
	}

	// Metrics configuration
	if *enableMetrics {
		config.EnableMetrics = true
		config.MetricsAddr = *metricsAddr
		config.MetricsAPIKey = *metricsAPIKey
		config.MetricsUsername = *metricsUsername
		config.MetricsPassword = *metricsPassword
	}

	return config, nil
}

// overrideFromEnv overrides a string flag from environment variable if present
func overrideFromEnv(envKey string, target *string) {
	if env := os.Getenv(envKey); env != "" {
		*target = env
	}
}

// overrideBoolFromEnv overrides a bool flag from environment variable if present
func overrideBoolFromEnv(envKey string, target *bool) {
	if env := os.Getenv(envKey); env != "" {
		*target = env == "true"
	}
	// If env var is empty or not set, keep the original value
}

// overrideIntFromEnv overrides an int flag from environment variable if present
func overrideIntFromEnv(envKey string, target *int) {
	if env := os.Getenv(envKey); env != "" {
		if val, err := fmt.Sscanf(env, "%d", target); err == nil && val == 1 {
			// Successfully parsed - no action needed as target is already updated
			return
		}
		// If parsing failed, keep the original value
	}
	// If env var is empty or not set, keep the original value
}

// overrideFloat64FromEnv overrides a float64 flag from environment variable if present
func overrideFloat64FromEnv(envKey string, target *float64) {
	if env := os.Getenv(envKey); env != "" {
		if val, err := fmt.Sscanf(env, "%f", target); err == nil && val == 1 {
			// Successfully parsed - no action needed as target is already updated
			return
		}
		// If parsing failed, keep the original value
	}
	// If env var is empty or not set, keep the original value
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.WebhookURL == "" {
		return fmt.Errorf("webhook URL is required")
	}

	if c.CertFile != "" && c.KeyFile == "" {
		return fmt.Errorf("TLS key file is required when certificate file is provided")
	}

	if c.KeyFile != "" && c.CertFile == "" {
		return fmt.Errorf("TLS certificate file is required when key file is provided")
	}

	if c.EnableSentry && c.SentryDSN == "" {
		return fmt.Errorf("sentry DSN is required when Sentry is enabled")
	}

	return nil
}
