package config

import (
	"flag"
	"fmt"
	"inboundparse/internal/utils"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	EnableDKIM2 bool
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

	// SMTP/Processing Configuration
	TrustedProxyCIDRs        []string
	MessageProcessingTimeout time.Duration
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

	// Webhook defaults
	DefaultWebhookMaxRetries         = 3
	DefaultWebhookRetryDelay         = 1 * time.Second
	DefaultWebhookMaxRetryDelay      = 30 * time.Second
	DefaultWebhookRetryMultiplier    = 2.0
	DefaultWebhookRateLimitPerSecond = 10
	DefaultWebhookRateLimitBurst     = 20

	// Processing defaults
	DefaultMessageProcessingTimeout = 5 * time.Minute
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
		EnableDKIM2:    true,
		EnableDMARC:    true,
		// Webhook defaults
		WebhookMaxRetries:         DefaultWebhookMaxRetries,
		WebhookRetryDelay:         DefaultWebhookRetryDelay,
		WebhookMaxRetryDelay:      DefaultWebhookMaxRetryDelay,
		WebhookRetryMultiplier:    DefaultWebhookRetryMultiplier,
		WebhookRateLimitPerSecond: DefaultWebhookRateLimitPerSecond,
		WebhookRateLimitBurst:     DefaultWebhookRateLimitBurst,
		// Processing defaults
		MessageProcessingTimeout: DefaultMessageProcessingTimeout,
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
		webhookMaxRetries      = flag.Int("webhook-max-retries", DefaultWebhookMaxRetries, "Maximum number of webhook retry attempts")
		webhookRetryDelay      = flag.Int("webhook-retry-delay", int(DefaultWebhookRetryDelay.Seconds()), "Initial webhook retry delay in seconds")
		webhookMaxRetryDelay   = flag.Int("webhook-max-retry-delay", int(DefaultWebhookMaxRetryDelay.Seconds()), "Maximum webhook retry delay in seconds")
		webhookRetryMultiplier = flag.Float64("webhook-retry-multiplier", DefaultWebhookRetryMultiplier, "Webhook retry delay multiplier")
		// Webhook rate limiting flags
		webhookRateLimitPerSecond = flag.Int("webhook-rate-limit", DefaultWebhookRateLimitPerSecond, "Webhook requests per second rate limit")
		webhookRateLimitBurst     = flag.Int("webhook-rate-burst", DefaultWebhookRateLimitBurst, "Webhook rate limit burst capacity")
		serverName                = flag.String("name", DefaultServerName, "SMTP server name")
		maxMessageSize            = flag.Int64("max-size", DefaultMaxMessageSize, "Maximum message size in bytes")
		readTimeout               = flag.Int("read-timeout", int(DefaultReadTimeout.Seconds()), "Read timeout in seconds")
		writeTimeout              = flag.Int("write-timeout", int(DefaultWriteTimeout.Seconds()), "Write timeout in seconds")
		enableSPF                 = flag.Bool("enable-spf", true, "Enable SPF validation")
		enableDKIM                = flag.Bool("enable-dkim", true, "Enable DKIM validation")
		enableDKIM2               = flag.Bool("enable-dkim2", true, "Enable DKIM2 verification")
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
		// Processing flags
		messageProcessingTimeout = flag.Int("message-processing-timeout", int(DefaultMessageProcessingTimeout.Seconds()), "Maximum time in seconds to process a single message (including auth checks and webhook delivery)")
	)

	// Load .env file if present
	utils.LoadEnv()

	// Parse flags
	flag.Parse()

	// Get values from flags or environment variables (env takes precedence)
	listenAddrVal := utils.GetEnv("LISTEN_ADDR", *listenAddr)
	listenAddrTLSVal := utils.GetEnv("LISTEN_ADDR_TLS", *listenAddrTLS)
	webhookURLVal := utils.GetEnv("WEBHOOK_URL", *webhookURL)
	webhookUserVal := utils.GetEnv("WEBHOOK_USER", *webhookUser)
	webhookPassVal := utils.GetEnv("WEBHOOK_PASS", *webhookPass)
	webhookMaxRetriesVal := utils.GetEnvInt("WEBHOOK_MAX_RETRIES", *webhookMaxRetries)
	webhookRetryDelayVal := utils.GetEnvInt("WEBHOOK_RETRY_DELAY", *webhookRetryDelay)
	webhookMaxRetryDelayVal := utils.GetEnvInt("WEBHOOK_MAX_RETRY_DELAY", *webhookMaxRetryDelay)
	webhookRetryMultiplierVal := utils.GetEnvFloat("WEBHOOK_RETRY_MULTIPLIER", *webhookRetryMultiplier)
	webhookRateLimitVal := utils.GetEnvInt("WEBHOOK_RATE_LIMIT", *webhookRateLimitPerSecond)
	webhookRateBurstVal := utils.GetEnvInt("WEBHOOK_RATE_BURST", *webhookRateLimitBurst)
	serverNameVal := utils.GetEnv("SERVER_NAME", *serverName)
	maxMessageSizeVal := *maxMessageSize
	if envVal := utils.GetEnv("MAX_SIZE", ""); envVal != "" {
		if parsed, err := strconv.ParseInt(envVal, 10, 64); err == nil {
			maxMessageSizeVal = parsed
		}
	}
	readTimeoutVal := utils.GetEnvInt("READ_TIMEOUT", *readTimeout)
	writeTimeoutVal := utils.GetEnvInt("WRITE_TIMEOUT", *writeTimeout)
	certFileVal := utils.GetEnv("CERT_FILE", *certFile)
	keyFileVal := utils.GetEnv("KEY_FILE", *keyFile)
	verboseVal := utils.GetEnvBool("VERBOSE", *verbose)
	enableSPFVal := utils.GetEnvBool("ENABLE_SPF", *enableSPF)
	enableDKIMVal := utils.GetEnvBool("ENABLE_DKIM", *enableDKIM)
	enableDKIM2Val := utils.GetEnvBool("ENABLE_DKIM2", *enableDKIM2)
	enableDMARCVal := utils.GetEnvBool("ENABLE_DMARC", *enableDMARC)
	enableSentryVal := utils.GetEnvBool("ENABLE_SENTRY", *enableSentry)
	sentryDSNVal := utils.GetEnv("SENTRY_DSN", *sentryDSN)
	sentryEnvVal := utils.GetEnv("SENTRY_ENV", *sentryEnv)
	sentryReleaseVal := utils.GetEnv("SENTRY_RELEASE", *sentryRelease)
	enableMetricsVal := utils.GetEnvBool("ENABLE_METRICS", *enableMetrics)
	metricsAddrVal := utils.GetEnv("METRICS_ADDR", *metricsAddr)
	metricsAPIKeyVal := utils.GetEnv("METRICS_API_KEY", *metricsAPIKey)
	metricsUsernameVal := utils.GetEnv("METRICS_USERNAME", *metricsUsername)
	metricsPasswordVal := utils.GetEnv("METRICS_PASSWORD", *metricsPassword)
	trustedProxyCIDRsVal := utils.GetEnvArray("TRUSTED_PROXY_CIDRS", []string{})
	messageProcessingTimeoutVal := utils.GetEnvInt("MESSAGE_PROCESSING_TIMEOUT", *messageProcessingTimeout)

	// Build config
	config := New(
		WithListenAddr(listenAddrVal),
		WithListenAddrTLS(listenAddrTLSVal),
		WithWebhookURL(webhookURLVal),
		WithWebhookAuth(webhookUserVal, webhookPassVal),
		WithTLS(certFileVal, keyFileVal),
		WithAuth(enableSPFVal, enableDKIMVal, enableDMARCVal),
		WithVerbose(verboseVal),
	)
	config.EnableDKIM2 = enableDKIM2Val

	// Set webhook retry and rate limiting configuration
	config.WebhookMaxRetries = webhookMaxRetriesVal
	config.WebhookRetryDelay = time.Duration(webhookRetryDelayVal) * time.Second
	config.WebhookMaxRetryDelay = time.Duration(webhookMaxRetryDelayVal) * time.Second
	config.WebhookRetryMultiplier = webhookRetryMultiplierVal
	config.WebhookRateLimitPerSecond = webhookRateLimitVal
	config.WebhookRateLimitBurst = webhookRateBurstVal

	// Set additional fields
	config.ServerName = serverNameVal
	config.MaxMessageSize = maxMessageSizeVal
	config.ReadTimeout = time.Duration(readTimeoutVal) * time.Second
	config.WriteTimeout = time.Duration(writeTimeoutVal) * time.Second

	// Sentry configuration
	if enableSentryVal {
		config.EnableSentry = true
		config.SentryDSN = sentryDSNVal
		config.SentryEnv = sentryEnvVal
		config.SentryRelease = sentryReleaseVal
	}

	// Metrics configuration
	if enableMetricsVal {
		config.EnableMetrics = true
		config.MetricsAddr = metricsAddrVal
		config.MetricsAPIKey = metricsAPIKeyVal
		config.MetricsUsername = metricsUsernameVal
		config.MetricsPassword = metricsPasswordVal
	}

	// Processing configuration
	config.TrustedProxyCIDRs = trustedProxyCIDRsVal
	config.MessageProcessingTimeout = time.Duration(messageProcessingTimeoutVal) * time.Second

	return config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.CertFile != "" && c.KeyFile == "" {
		return fmt.Errorf("TLS key file is required when certificate file is provided")
	}

	if c.KeyFile != "" && c.CertFile == "" {
		return fmt.Errorf("TLS certificate file is required when key file is provided")
	}

	if c.EnableSentry && c.SentryDSN == "" {
		return fmt.Errorf("sentry DSN is required when Sentry is enabled")
	}

	if c.WebhookRetryMultiplier <= 0 {
		return fmt.Errorf("webhook retry multiplier must be greater than 0, got %v", c.WebhookRetryMultiplier)
	}

	if c.WebhookURL != "" {
		u, err := url.Parse(c.WebhookURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("webhook URL must be a valid http or https URL, got %q", c.WebhookURL)
		}
	}

	if c.EnableMetrics {
		if err := validateMetricsAuth(c.MetricsAddr, c.MetricsAPIKey, c.MetricsUsername, c.MetricsPassword); err != nil {
			return err
		}
	}

	return nil
}

// metricsBindHostAllowsUnauthenticated returns true only for loopback binds
// where exposing /metrics without credentials is acceptable (local dev/tests).
func metricsBindHostAllowsUnauthenticated(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func validateMetricsAuth(addr, apiKey, username, password string) error {
	if addr == "" {
		return fmt.Errorf("metrics address is required when metrics are enabled")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid metrics address %q: %w", addr, err)
	}
	// Empty host (e.g. ":9090") means all interfaces — never allow open /metrics.
	if host == "" {
		host = "0.0.0.0"
	}

	userOrPass := (username != "") != (password != "")
	if userOrPass {
		return fmt.Errorf("metrics: both username and password must be set for basic authentication")
	}

	hasAuth := apiKey != "" || (username != "" && password != "")
	if hasAuth {
		return nil
	}
	if metricsBindHostAllowsUnauthenticated(host) {
		return nil
	}
	return fmt.Errorf("metrics: set METRICS_API_KEY or METRICS_USERNAME and METRICS_PASSWORD when binding to %q (unauthenticated /metrics is only allowed on loopback)", addr)
}
