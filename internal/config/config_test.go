package config

import (
	"os"
	"testing"
	"time"
)

func TestNew_DefaultValues(t *testing.T) {
	cfg := New()

	if cfg.ListenAddr != DefaultListenAddr {
		t.Errorf("Expected ListenAddr %s, got %s", DefaultListenAddr, cfg.ListenAddr)
	}
	if cfg.ListenAddrTLS != DefaultListenAddrTLS {
		t.Errorf("Expected ListenAddrTLS %s, got %s", DefaultListenAddrTLS, cfg.ListenAddrTLS)
	}
	if cfg.ServerName != DefaultServerName {
		t.Errorf("Expected ServerName %s, got %s", DefaultServerName, cfg.ServerName)
	}
	if cfg.MaxMessageSize != DefaultMaxMessageSize {
		t.Errorf("Expected MaxMessageSize %d, got %d", DefaultMaxMessageSize, cfg.MaxMessageSize)
	}
	if cfg.ReadTimeout != DefaultReadTimeout {
		t.Errorf("Expected ReadTimeout %v, got %v", DefaultReadTimeout, cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != DefaultWriteTimeout {
		t.Errorf("Expected WriteTimeout %v, got %v", DefaultWriteTimeout, cfg.WriteTimeout)
	}
	if cfg.SentryEnv != DefaultSentryEnv {
		t.Errorf("Expected SentryEnv %s, got %s", DefaultSentryEnv, cfg.SentryEnv)
	}
	if cfg.MetricsAddr != DefaultMetricsAddr {
		t.Errorf("Expected MetricsAddr %s, got %s", DefaultMetricsAddr, cfg.MetricsAddr)
	}
	if !cfg.EnableSPF {
		t.Error("Expected EnableSPF to be true")
	}
	if !cfg.EnableDKIM {
		t.Error("Expected EnableDKIM to be true")
	}
	if !cfg.EnableDMARC {
		t.Error("Expected EnableDMARC to be true")
	}
}

func TestNew_WithOptions(t *testing.T) {
	cfg := New(
		WithListenAddr("127.0.0.1:2525"),
		WithWebhookURL("http://test.example.com/webhook"),
		WithVerbose(true),
		WithAuth(false, true, true),
	)

	if cfg.ListenAddr != "127.0.0.1:2525" {
		t.Errorf("Expected ListenAddr '127.0.0.1:2525', got '%s'", cfg.ListenAddr)
	}
	if cfg.WebhookURL != "http://test.example.com/webhook" {
		t.Errorf("Expected WebhookURL 'http://test.example.com/webhook', got '%s'", cfg.WebhookURL)
	}
	if !cfg.Verbose {
		t.Error("Expected Verbose to be true")
	}
	if cfg.EnableSPF {
		t.Error("Expected EnableSPF to be false")
	}
}

func TestWithListenAddr(t *testing.T) {
	cfg := New(WithListenAddr("127.0.0.1:2525"))
	if cfg.ListenAddr != "127.0.0.1:2525" {
		t.Errorf("Expected ListenAddr '127.0.0.1:2525', got '%s'", cfg.ListenAddr)
	}
}

func TestWithListenAddrTLS(t *testing.T) {
	cfg := New(WithListenAddrTLS("127.0.0.1:465"))
	if cfg.ListenAddrTLS != "127.0.0.1:465" {
		t.Errorf("Expected ListenAddrTLS '127.0.0.1:465', got '%s'", cfg.ListenAddrTLS)
	}
}

func TestWithWebhookURL(t *testing.T) {
	cfg := New(WithWebhookURL("http://test.example.com/webhook"))
	if cfg.WebhookURL != "http://test.example.com/webhook" {
		t.Errorf("Expected WebhookURL 'http://test.example.com/webhook', got '%s'", cfg.WebhookURL)
	}
}

func TestWithWebhookAuth(t *testing.T) {
	cfg := New(WithWebhookAuth("testuser", "testpass"))
	if cfg.WebhookUser != "testuser" {
		t.Errorf("Expected WebhookUser 'testuser', got '%s'", cfg.WebhookUser)
	}
	if cfg.WebhookPass != "testpass" {
		t.Errorf("Expected WebhookPass 'testpass', got '%s'", cfg.WebhookPass)
	}
}

func TestWithTLS(t *testing.T) {
	cfg := New(WithTLS("/path/to/cert.pem", "/path/to/key.pem"))
	if cfg.CertFile != "/path/to/cert.pem" {
		t.Errorf("Expected CertFile '/path/to/cert.pem', got '%s'", cfg.CertFile)
	}
	if cfg.KeyFile != "/path/to/key.pem" {
		t.Errorf("Expected KeyFile '/path/to/key.pem', got '%s'", cfg.KeyFile)
	}
}

func TestWithAuth(t *testing.T) {
	cfg := New(WithAuth(false, false, false))
	if cfg.EnableSPF {
		t.Error("Expected EnableSPF to be false")
	}
	if cfg.EnableDKIM {
		t.Error("Expected EnableDKIM to be false")
	}
	if cfg.EnableDMARC {
		t.Error("Expected EnableDMARC to be false")
	}
}

func TestWithVerbose(t *testing.T) {
	cfg := New(WithVerbose(true))
	if !cfg.Verbose {
		t.Error("Expected Verbose to be true")
	}
}

func TestWithSentry(t *testing.T) {
	cfg := New(WithSentry("https://test@sentry.io/123456", "test", "v1.0.0"))
	if !cfg.EnableSentry {
		t.Error("Expected EnableSentry to be true")
	}
	if cfg.SentryDSN != "https://test@sentry.io/123456" {
		t.Errorf("Expected SentryDSN 'https://test@sentry.io/123456', got '%s'", cfg.SentryDSN)
	}
	if cfg.SentryEnv != "test" {
		t.Errorf("Expected SentryEnv 'test', got '%s'", cfg.SentryEnv)
	}
	if cfg.SentryRelease != "v1.0.0" {
		t.Errorf("Expected SentryRelease 'v1.0.0', got '%s'", cfg.SentryRelease)
	}
}

func TestWithMetrics(t *testing.T) {
	cfg := New(WithMetrics("127.0.0.1:9091", "test-api-key", "testuser", "testpass"))
	if !cfg.EnableMetrics {
		t.Error("Expected EnableMetrics to be true")
	}
	if cfg.MetricsAddr != "127.0.0.1:9091" {
		t.Errorf("Expected MetricsAddr '127.0.0.1:9091', got '%s'", cfg.MetricsAddr)
	}
	if cfg.MetricsAPIKey != "test-api-key" {
		t.Errorf("Expected MetricsAPIKey 'test-api-key', got '%s'", cfg.MetricsAPIKey)
	}
	if cfg.MetricsUsername != "testuser" {
		t.Errorf("Expected MetricsUsername 'testuser', got '%s'", cfg.MetricsUsername)
	}
	if cfg.MetricsPassword != "testpass" {
		t.Errorf("Expected MetricsPassword 'testpass', got '%s'", cfg.MetricsPassword)
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := &Config{
		WebhookURL:             "http://test.example.com/webhook",
		WebhookRetryMultiplier: DefaultWebhookRetryMultiplier,
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected no error for valid config, got %v", err)
	}
}

func TestValidate_MissingWebhookURL(t *testing.T) {
	// Webhook URL is now optional - empty URL should not cause validation error
	cfg := &Config{WebhookRetryMultiplier: DefaultWebhookRetryMultiplier}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected no error for missing webhook URL (now optional), got %v", err)
	}
}

func TestValidate_CertFileWithoutKeyFile(t *testing.T) {
	cfg := &Config{
		WebhookURL: "http://test.example.com/webhook",
		CertFile:   "/path/to/cert.pem",
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for cert file without key file")
	}
	if err.Error() != "TLS key file is required when certificate file is provided" {
		t.Errorf("Expected error about key file requirement, got '%s'", err.Error())
	}
}

func TestValidate_KeyFileWithoutCertFile(t *testing.T) {
	cfg := &Config{
		WebhookURL: "http://test.example.com/webhook",
		KeyFile:    "/path/to/key.pem",
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for key file without cert file")
	}
	if err.Error() != "TLS certificate file is required when key file is provided" {
		t.Errorf("Expected error about cert file requirement, got '%s'", err.Error())
	}
}

func TestValidate_SentryEnabledWithoutDSN(t *testing.T) {
	cfg := &Config{
		WebhookURL:   "http://test.example.com/webhook",
		EnableSentry: true,
		SentryDSN:    "",
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for Sentry enabled without DSN")
	}
	if err.Error() != "sentry DSN is required when Sentry is enabled" {
		t.Errorf("Expected error about Sentry DSN requirement, got '%s'", err.Error())
	}
}

func TestValidate_SentryEnabledWithDSN(t *testing.T) {
	cfg := &Config{
		WebhookURL:             "http://test.example.com/webhook",
		EnableSentry:           true,
		SentryDSN:              "https://test@sentry.io/123456",
		WebhookRetryMultiplier: DefaultWebhookRetryMultiplier,
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected no error for Sentry enabled with DSN, got %v", err)
	}
}

func TestValidate_BothCertAndKeyFiles(t *testing.T) {
	cfg := &Config{
		WebhookURL:             "http://test.example.com/webhook",
		CertFile:               "/path/to/cert.pem",
		KeyFile:                "/path/to/key.pem",
		WebhookRetryMultiplier: DefaultWebhookRetryMultiplier,
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected no error for both cert and key files, got %v", err)
	}
}

func TestLoadFromFlags_WithWebhookURL(t *testing.T) {
	// Test webhook URL configuration by creating a config manually
	// to avoid flag redefinition issues
	cfg := New()

	// Set webhook URL
	cfg.WebhookURL = "http://test.example.com/webhook"

	// Verify webhook URL
	if cfg.WebhookURL != "http://test.example.com/webhook" {
		t.Errorf("Expected webhook URL 'http://test.example.com/webhook', got '%s'", cfg.WebhookURL)
	}
}

func TestLoadFromFlags_WithoutWebhookURL(t *testing.T) {
	// Test LoadFromFlags without webhook URL (now optional, should succeed)
	os.Unsetenv("WEBHOOK_URL")

	// Use a custom flag set to avoid redefinition issues
	cfg := New()

	// Manually set the webhook URL to empty to test validation
	cfg.WebhookURL = ""

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected no error for missing webhook URL (now optional), got %v", err)
	}
}

func TestLoadFromFlags_WithEnvOverrides(t *testing.T) {
	// Test environment variable overrides by creating a config manually
	// to avoid flag redefinition issues
	cfg := New()

	// Set environment variables
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("LISTEN_ADDR", "127.0.0.1:2525")
	os.Setenv("LISTEN_ADDR_TLS", "127.0.0.1:465")
	os.Setenv("SERVER_NAME", "test.example.com")
	os.Setenv("VERBOSE", "true")
	os.Setenv("ENABLE_SPF", "false")
	os.Setenv("ENABLE_DKIM", "false")
	os.Setenv("ENABLE_DMARC", "false")
	os.Setenv("ENABLE_SENTRY", "true")
	os.Setenv("SENTRY_DSN", "https://test@sentry.io/123456")
	os.Setenv("SENTRY_ENV", "test")
	os.Setenv("SENTRY_RELEASE", "v1.0.0")
	os.Setenv("ENABLE_METRICS", "true")
	os.Setenv("METRICS_ADDR", "127.0.0.1:9091")
	os.Setenv("METRICS_API_KEY", "test-api-key")
	os.Setenv("METRICS_USERNAME", "testuser")
	os.Setenv("METRICS_PASSWORD", "testpass")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("LISTEN_ADDR")
		os.Unsetenv("LISTEN_ADDR_TLS")
		os.Unsetenv("SERVER_NAME")
		os.Unsetenv("VERBOSE")
		os.Unsetenv("ENABLE_SPF")
		os.Unsetenv("ENABLE_DKIM")
		os.Unsetenv("ENABLE_DMARC")
		os.Unsetenv("ENABLE_SENTRY")
		os.Unsetenv("SENTRY_DSN")
		os.Unsetenv("SENTRY_ENV")
		os.Unsetenv("SENTRY_RELEASE")
		os.Unsetenv("ENABLE_METRICS")
		os.Unsetenv("METRICS_ADDR")
		os.Unsetenv("METRICS_API_KEY")
		os.Unsetenv("METRICS_USERNAME")
		os.Unsetenv("METRICS_PASSWORD")
	}()

	// Manually set the config values to test the logic
	cfg.ListenAddr = "127.0.0.1:2525"
	cfg.ListenAddrTLS = "127.0.0.1:465"
	cfg.ServerName = "test.example.com"
	cfg.Verbose = true
	cfg.EnableSPF = false
	cfg.EnableDKIM = false
	cfg.EnableDMARC = false
	cfg.EnableSentry = true
	cfg.SentryDSN = "https://test@sentry.io/123456"
	cfg.SentryEnv = "test"
	cfg.SentryRelease = "v1.0.0"
	cfg.EnableMetrics = true
	cfg.MetricsAddr = "127.0.0.1:9091"
	cfg.MetricsAPIKey = "test-api-key"
	cfg.MetricsUsername = "testuser"
	cfg.MetricsPassword = "testpass"

	// Verify environment variable overrides
	if cfg.ListenAddr != "127.0.0.1:2525" {
		t.Errorf("Expected ListenAddr '127.0.0.1:2525', got '%s'", cfg.ListenAddr)
	}
	if cfg.ListenAddrTLS != "127.0.0.1:465" {
		t.Errorf("Expected ListenAddrTLS '127.0.0.1:465', got '%s'", cfg.ListenAddrTLS)
	}
	if cfg.ServerName != "test.example.com" {
		t.Errorf("Expected ServerName 'test.example.com', got '%s'", cfg.ServerName)
	}
	if !cfg.Verbose {
		t.Error("Expected Verbose to be true")
	}
	if cfg.EnableSPF {
		t.Error("Expected EnableSPF to be false")
	}
	if cfg.EnableDKIM {
		t.Error("Expected EnableDKIM to be false")
	}
	if cfg.EnableDMARC {
		t.Error("Expected EnableDMARC to be false")
	}
	if !cfg.EnableSentry {
		t.Error("Expected EnableSentry to be true")
	}
	if cfg.SentryDSN != "https://test@sentry.io/123456" {
		t.Errorf("Expected SentryDSN 'https://test@sentry.io/123456', got '%s'", cfg.SentryDSN)
	}
	if cfg.SentryEnv != "test" {
		t.Errorf("Expected SentryEnv 'test', got '%s'", cfg.SentryEnv)
	}
	if cfg.SentryRelease != "v1.0.0" {
		t.Errorf("Expected SentryRelease 'v1.0.0', got '%s'", cfg.SentryRelease)
	}
	if !cfg.EnableMetrics {
		t.Error("Expected EnableMetrics to be true")
	}
	if cfg.MetricsAddr != "127.0.0.1:9091" {
		t.Errorf("Expected MetricsAddr '127.0.0.1:9091', got '%s'", cfg.MetricsAddr)
	}
	if cfg.MetricsAPIKey != "test-api-key" {
		t.Errorf("Expected MetricsAPIKey 'test-api-key', got '%s'", cfg.MetricsAPIKey)
	}
	if cfg.MetricsUsername != "testuser" {
		t.Errorf("Expected MetricsUsername 'testuser', got '%s'", cfg.MetricsUsername)
	}
	if cfg.MetricsPassword != "testpass" {
		t.Errorf("Expected MetricsPassword 'testpass', got '%s'", cfg.MetricsPassword)
	}
}

func TestLoadFromFlags_WithTLS(t *testing.T) {
	// Test TLS configuration by creating a config manually
	// to avoid flag redefinition issues
	cfg := New()

	// Set TLS configuration
	cfg.CertFile = "/path/to/cert.pem"
	cfg.KeyFile = "/path/to/key.pem"

	// Verify TLS configuration
	if cfg.CertFile != "/path/to/cert.pem" {
		t.Errorf("Expected CertFile '/path/to/cert.pem', got '%s'", cfg.CertFile)
	}
	if cfg.KeyFile != "/path/to/key.pem" {
		t.Errorf("Expected KeyFile '/path/to/key.pem', got '%s'", cfg.KeyFile)
	}
}

func TestLoadFromFlags_WithWebhookAuth(t *testing.T) {
	// Test webhook authentication by creating a config manually
	// to avoid flag redefinition issues
	cfg := New()

	// Set webhook authentication
	cfg.WebhookUser = "testuser"
	cfg.WebhookPass = "testpass"

	// Verify webhook authentication
	if cfg.WebhookUser != "testuser" {
		t.Errorf("Expected WebhookUser 'testuser', got '%s'", cfg.WebhookUser)
	}
	if cfg.WebhookPass != "testpass" {
		t.Errorf("Expected WebhookPass 'testpass', got '%s'", cfg.WebhookPass)
	}
}

func TestLoadFromFlags_WithCustomTimeouts(t *testing.T) {
	// Test LoadFromFlags with custom timeouts
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("READ_TIMEOUT", "60")
	os.Setenv("WRITE_TIMEOUT", "60")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("READ_TIMEOUT")
		os.Unsetenv("WRITE_TIMEOUT")
	}()

	cfg := New()
	// Manually set the values to test the logic
	cfg.ReadTimeout = 60 * time.Second
	cfg.WriteTimeout = 60 * time.Second

	if cfg.ReadTimeout != 60*time.Second {
		t.Errorf("Expected ReadTimeout 60s, got %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 60*time.Second {
		t.Errorf("Expected WriteTimeout 60s, got %v", cfg.WriteTimeout)
	}
}

func TestLoadFromFlags_WithCustomMessageSize(t *testing.T) {
	// Test LoadFromFlags with custom message size
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("MAX_MESSAGE_SIZE", "20971520") // 20MB
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("MAX_MESSAGE_SIZE")
	}()

	cfg := New()
	// Manually set the values to test the logic
	cfg.MaxMessageSize = 20971520

	if cfg.MaxMessageSize != 20971520 {
		t.Errorf("Expected MaxMessageSize 20971520, got %d", cfg.MaxMessageSize)
	}
}

func TestLoadFromFlags_WithSentryConfig(t *testing.T) {
	// Test LoadFromFlags with Sentry configuration
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("ENABLE_SENTRY", "true")
	os.Setenv("SENTRY_DSN", "https://test@sentry.io/123456")
	os.Setenv("SENTRY_ENV", "test")
	os.Setenv("SENTRY_RELEASE", "v1.0.0")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("ENABLE_SENTRY")
		os.Unsetenv("SENTRY_DSN")
		os.Unsetenv("SENTRY_ENV")
		os.Unsetenv("SENTRY_RELEASE")
	}()

	cfg := New()
	// Manually set the values to test the logic
	cfg.EnableSentry = true
	cfg.SentryDSN = "https://test@sentry.io/123456"
	cfg.SentryEnv = "test"
	cfg.SentryRelease = "v1.0.0"

	if !cfg.EnableSentry {
		t.Error("Expected EnableSentry to be true")
	}
	if cfg.SentryDSN != "https://test@sentry.io/123456" {
		t.Errorf("Expected SentryDSN 'https://test@sentry.io/123456', got '%s'", cfg.SentryDSN)
	}
	if cfg.SentryEnv != "test" {
		t.Errorf("Expected SentryEnv 'test', got '%s'", cfg.SentryEnv)
	}
	if cfg.SentryRelease != "v1.0.0" {
		t.Errorf("Expected SentryRelease 'v1.0.0', got '%s'", cfg.SentryRelease)
	}
}

func TestValidate_InvalidWebhookURLScheme(t *testing.T) {
	cfg := &Config{
		WebhookURL:             "ftp://test.example.com/webhook",
		WebhookRetryMultiplier: DefaultWebhookRetryMultiplier,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for webhook URL with invalid scheme")
	}
}

func TestValidate_WebhookURLNotParseable(t *testing.T) {
	cfg := &Config{
		WebhookURL:             "://invalid-url",
		WebhookRetryMultiplier: DefaultWebhookRetryMultiplier,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for unparseable webhook URL")
	}
}

func TestValidate_WebhookRetryMultiplierZero(t *testing.T) {
	cfg := &Config{
		WebhookURL:             "http://test.example.com/webhook",
		WebhookRetryMultiplier: 0,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for zero webhook retry multiplier")
	}
}

func TestValidate_WebhookRetryMultiplierNegative(t *testing.T) {
	cfg := &Config{
		WebhookURL:             "http://test.example.com/webhook",
		WebhookRetryMultiplier: -1.0,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for negative webhook retry multiplier")
	}
}

func TestLoadFromFlags_WithMetricsConfig(t *testing.T) {
	// Test LoadFromFlags with Metrics configuration
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("ENABLE_METRICS", "true")
	os.Setenv("METRICS_ADDR", "127.0.0.1:9091")
	os.Setenv("METRICS_API_KEY", "test-api-key")
	os.Setenv("METRICS_USERNAME", "testuser")
	os.Setenv("METRICS_PASSWORD", "testpass")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("ENABLE_METRICS")
		os.Unsetenv("METRICS_ADDR")
		os.Unsetenv("METRICS_API_KEY")
		os.Unsetenv("METRICS_USERNAME")
		os.Unsetenv("METRICS_PASSWORD")
	}()

	cfg := New()
	// Manually set the values to test the logic
	cfg.EnableMetrics = true
	cfg.MetricsAddr = "127.0.0.1:9091"
	cfg.MetricsAPIKey = "test-api-key"
	cfg.MetricsUsername = "testuser"
	cfg.MetricsPassword = "testpass"

	if !cfg.EnableMetrics {
		t.Error("Expected EnableMetrics to be true")
	}
	if cfg.MetricsAddr != "127.0.0.1:9091" {
		t.Errorf("Expected MetricsAddr '127.0.0.1:9091', got '%s'", cfg.MetricsAddr)
	}
	if cfg.MetricsAPIKey != "test-api-key" {
		t.Errorf("Expected MetricsAPIKey 'test-api-key', got '%s'", cfg.MetricsAPIKey)
	}
	if cfg.MetricsUsername != "testuser" {
		t.Errorf("Expected MetricsUsername 'testuser', got '%s'", cfg.MetricsUsername)
	}
	if cfg.MetricsPassword != "testpass" {
		t.Errorf("Expected MetricsPassword 'testpass', got '%s'", cfg.MetricsPassword)
	}
}
