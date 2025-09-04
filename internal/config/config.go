package config

import (
	"flag"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// Config represents the application configuration
type Config struct {
	Server  ServerConfig  `json:"server"`
	Webhook WebhookConfig `json:"webhook"`
	Auth    AuthConfig    `json:"auth"`
	Metrics MetricsConfig `json:"metrics"`
	Sentry  SentryConfig  `json:"sentry"`
	Logging LoggingConfig `json:"logging"`
}

// ServerConfig contains SMTP server configuration
type ServerConfig struct {
	ListenAddr     string        `json:"listen_addr" default:"0.0.0.0:25"`
	ListenAddrTLS  string        `json:"listen_addr_tls" default:"0.0.0.0:587"`
	ServerName     string        `json:"server_name" default:"mx.inboundparse.com"`
	MaxMessageSize int64         `json:"max_message_size" default:"10485760"` // 10MB
	ReadTimeout    time.Duration `json:"read_timeout" default:"30s"`
	WriteTimeout   time.Duration `json:"write_timeout" default:"30s"`
	CertFile       string        `json:"cert_file"`
	KeyFile        string        `json:"key_file"`
	Verbose        bool          `json:"verbose" default:"false"`
}

// WebhookConfig contains webhook configuration
type WebhookConfig struct {
	URL      string `json:"url" default:"http://localhost:8080/webhook"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	EnableSPF   bool `json:"enable_spf" default:"true"`
	EnableDKIM  bool `json:"enable_dkim" default:"true"`
	EnableDMARC bool `json:"enable_dmarc" default:"true"`
}

// MetricsConfig contains metrics configuration
type MetricsConfig struct {
	Enabled  bool   `json:"enabled" default:"false"`
	Addr     string `json:"addr" default:"0.0.0.0:9090"`
	APIKey   string `json:"api_key"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// SentryConfig contains Sentry configuration
type SentryConfig struct {
	Enabled bool   `json:"enabled" default:"false"`
	DSN     string `json:"dsn"`
	Env     string `json:"env" default:"production"`
	Release string `json:"release"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `json:"level" default:"info"`
	Format string `json:"format" default:"json"`
	Output string `json:"output" default:"stdout"`
}

// Load loads configuration from environment variables and command line flags
func Load() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load() // .env file is optional, so we ignore the error

	config := &Config{
		Server: ServerConfig{
			ListenAddr:     getEnvWithDefault("LISTEN_ADDR", "0.0.0.0:25"),
			ListenAddrTLS:  getEnvWithDefault("LISTEN_ADDR_TLS", "0.0.0.0:587"),
			ServerName:     getEnvWithDefault("SERVER_NAME", "mx.inboundparse.com"),
			MaxMessageSize: 10 * 1024 * 1024, // 10MB
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   30 * time.Second,
			CertFile:       os.Getenv("CERT_FILE"),
			KeyFile:        os.Getenv("KEY_FILE"),
			Verbose:        getEnvBoolWithDefault("VERBOSE", false),
		},
		Webhook: WebhookConfig{
			URL:      getEnvWithDefault("WEBHOOK_URL", "http://localhost:8080/webhook"),
			Username: os.Getenv("WEBHOOK_USER"),
			Password: os.Getenv("WEBHOOK_PASS"),
		},
		Auth: AuthConfig{
			EnableSPF:   getEnvBoolWithDefault("ENABLE_SPF", true),
			EnableDKIM:  getEnvBoolWithDefault("ENABLE_DKIM", true),
			EnableDMARC: getEnvBoolWithDefault("ENABLE_DMARC", true),
		},
		Metrics: MetricsConfig{
			Enabled:  getEnvBoolWithDefault("ENABLE_METRICS", false),
			Addr:     getEnvWithDefault("METRICS_ADDR", "0.0.0.0:9090"),
			APIKey:   os.Getenv("METRICS_API_KEY"),
			Username: os.Getenv("METRICS_USERNAME"),
			Password: os.Getenv("METRICS_PASSWORD"),
		},
		Sentry: SentryConfig{
			Enabled: getEnvBoolWithDefault("ENABLE_SENTRY", false),
			DSN:     os.Getenv("SENTRY_DSN"),
			Env:     getEnvWithDefault("SENTRY_ENV", "production"),
			Release: os.Getenv("SENTRY_RELEASE"),
		},
		Logging: LoggingConfig{
			Level:  getEnvWithDefault("LOG_LEVEL", "info"),
			Format: getEnvWithDefault("LOG_FORMAT", "json"),
			Output: getEnvWithDefault("LOG_OUTPUT", "stdout"),
		},
	}

	// Override with command line flags if provided
	loadFromFlags(config)

	return config, nil
}

// loadFromFlags loads configuration from command line flags
func loadFromFlags(config *Config) {
	// Server flags
	flag.StringVar(&config.Server.ListenAddr, "listen", config.Server.ListenAddr, "SMTP server listen address")
	flag.StringVar(&config.Server.ListenAddrTLS, "listen-tls", config.Server.ListenAddrTLS, "SMTP server listen address for TLS")
	flag.StringVar(&config.Server.ServerName, "name", config.Server.ServerName, "SMTP server name")
	flag.Int64Var(&config.Server.MaxMessageSize, "max-size", config.Server.MaxMessageSize, "Maximum message size in bytes")
	readTimeoutSeconds := int(config.Server.ReadTimeout.Seconds())
	writeTimeoutSeconds := int(config.Server.WriteTimeout.Seconds())
	flag.IntVar(&readTimeoutSeconds, "read-timeout", readTimeoutSeconds, "Read timeout in seconds")
	flag.IntVar(&writeTimeoutSeconds, "write-timeout", writeTimeoutSeconds, "Write timeout in seconds")
	config.Server.ReadTimeout = time.Duration(readTimeoutSeconds) * time.Second
	config.Server.WriteTimeout = time.Duration(writeTimeoutSeconds) * time.Second
	flag.StringVar(&config.Server.CertFile, "cert-file", config.Server.CertFile, "TLS certificate file")
	flag.StringVar(&config.Server.KeyFile, "key-file", config.Server.KeyFile, "TLS key file")
	flag.BoolVar(&config.Server.Verbose, "verbose", config.Server.Verbose, "Enable verbose logging")

	// Webhook flags
	flag.StringVar(&config.Webhook.URL, "webhook", config.Webhook.URL, "Webhook URL to send email data to")
	flag.StringVar(&config.Webhook.Username, "webhook-user", config.Webhook.Username, "Basic auth username for webhook")
	flag.StringVar(&config.Webhook.Password, "webhook-pass", config.Webhook.Password, "Basic auth password for webhook")

	// Auth flags
	flag.BoolVar(&config.Auth.EnableSPF, "enable-spf", config.Auth.EnableSPF, "Enable SPF validation")
	flag.BoolVar(&config.Auth.EnableDKIM, "enable-dkim", config.Auth.EnableDKIM, "Enable DKIM validation")
	flag.BoolVar(&config.Auth.EnableDMARC, "enable-dmarc", config.Auth.EnableDMARC, "Enable DMARC validation")

	// Metrics flags
	flag.BoolVar(&config.Metrics.Enabled, "enable-metrics", config.Metrics.Enabled, "Enable Prometheus metrics collection")
	flag.StringVar(&config.Metrics.Addr, "metrics-addr", config.Metrics.Addr, "Metrics server listen address")
	flag.StringVar(&config.Metrics.APIKey, "metrics-api-key", config.Metrics.APIKey, "Metrics API key")
	flag.StringVar(&config.Metrics.Username, "metrics-username", config.Metrics.Username, "Metrics username")
	flag.StringVar(&config.Metrics.Password, "metrics-password", config.Metrics.Password, "Metrics password")

	// Sentry flags
	flag.BoolVar(&config.Sentry.Enabled, "enable-sentry", config.Sentry.Enabled, "Enable Sentry error tracking")
	flag.StringVar(&config.Sentry.DSN, "sentry-dsn", config.Sentry.DSN, "Sentry DSN for error tracking")
	flag.StringVar(&config.Sentry.Env, "sentry-env", config.Sentry.Env, "Sentry environment (production, staging, development)")
	flag.StringVar(&config.Sentry.Release, "sentry-release", config.Sentry.Release, "Sentry release version")

	flag.Parse()
}

// getEnvWithDefault returns the value of an environment variable or a default value
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBoolWithDefault returns the boolean value of an environment variable or a default value
func getEnvBoolWithDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}
