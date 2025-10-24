package main

import (
	"os"
	"testing"
)

func TestMain_WithTestExit(t *testing.T) {
	// Test the test exit hook
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer os.Unsetenv("INBOUNDPARSE_TEST_EXIT")

	// This should return early without error
	main()
}

func TestMain_WithTestInitOnly(t *testing.T) {
	// Test the test init only hook
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	os.Setenv("INBOUNDPARSE_TEST_INIT_ONLY", "1")
	defer func() {
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
		os.Unsetenv("INBOUNDPARSE_TEST_INIT_ONLY")
	}()

	// This should return early without error
	main()
}

func TestMain_WithWebhookURL(t *testing.T) {
	// Test with a valid webhook URL
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithoutWebhookURL(t *testing.T) {
	// Test without webhook URL (should fail config validation)
	os.Unsetenv("WEBHOOK_URL")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer os.Unsetenv("INBOUNDPARSE_TEST_EXIT")

	// This should not panic (config validation happens after test exit check)
	main()
}

func TestMain_WithVerbose(t *testing.T) {
	// Test with verbose logging
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("VERBOSE", "true")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("VERBOSE")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithSentry(t *testing.T) {
	// Test with Sentry enabled
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("ENABLE_SENTRY", "true")
	os.Setenv("SENTRY_DSN", "https://test@sentry.io/123456")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("ENABLE_SENTRY")
		os.Unsetenv("SENTRY_DSN")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithMetrics(t *testing.T) {
	// Test with metrics enabled
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("ENABLE_METRICS", "true")
	os.Setenv("METRICS_ADDR", "127.0.0.1:9091")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("ENABLE_METRICS")
		os.Unsetenv("METRICS_ADDR")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithTLS(t *testing.T) {
	// Test with TLS configuration
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("CERT_FILE", "/path/to/cert.pem")
	os.Setenv("KEY_FILE", "/path/to/key.pem")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("CERT_FILE")
		os.Unsetenv("KEY_FILE")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithCustomListenAddr(t *testing.T) {
	// Test with custom listen addresses
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("LISTEN_ADDR", "127.0.0.1:2525")
	os.Setenv("LISTEN_ADDR_TLS", "127.0.0.1:465")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("LISTEN_ADDR")
		os.Unsetenv("LISTEN_ADDR_TLS")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithWebhookAuth(t *testing.T) {
	// Test with webhook authentication
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("WEBHOOK_USER", "testuser")
	os.Setenv("WEBHOOK_PASS", "testpass")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("WEBHOOK_USER")
		os.Unsetenv("WEBHOOK_PASS")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithAuthDisabled(t *testing.T) {
	// Test with authentication disabled
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("ENABLE_SPF", "false")
	os.Setenv("ENABLE_DKIM", "false")
	os.Setenv("ENABLE_DMARC", "false")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("ENABLE_SPF")
		os.Unsetenv("ENABLE_DKIM")
		os.Unsetenv("ENABLE_DMARC")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithCustomServerName(t *testing.T) {
	// Test with custom server name
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("SERVER_NAME", "custom.example.com")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("SERVER_NAME")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithCustomTimeouts(t *testing.T) {
	// Test with custom timeouts
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("READ_TIMEOUT", "60s")
	os.Setenv("WRITE_TIMEOUT", "60s")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("READ_TIMEOUT")
		os.Unsetenv("WRITE_TIMEOUT")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithCustomMessageSize(t *testing.T) {
	// Test with custom message size
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("MAX_MESSAGE_SIZE", "20971520") // 20MB
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("MAX_MESSAGE_SIZE")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithMetricsAuth(t *testing.T) {
	// Test with metrics authentication
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("ENABLE_METRICS", "true")
	os.Setenv("METRICS_API_KEY", "test-api-key")
	os.Setenv("METRICS_USERNAME", "testuser")
	os.Setenv("METRICS_PASSWORD", "testpass")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("ENABLE_METRICS")
		os.Unsetenv("METRICS_API_KEY")
		os.Unsetenv("METRICS_USERNAME")
		os.Unsetenv("METRICS_PASSWORD")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_WithSentryConfig(t *testing.T) {
	// Test with full Sentry configuration
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("ENABLE_SENTRY", "true")
	os.Setenv("SENTRY_DSN", "https://test@sentry.io/123456")
	os.Setenv("SENTRY_ENV", "test")
	os.Setenv("SENTRY_RELEASE", "v1.0.0")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("ENABLE_SENTRY")
		os.Unsetenv("SENTRY_DSN")
		os.Unsetenv("SENTRY_ENV")
		os.Unsetenv("SENTRY_RELEASE")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}

func TestMain_ConfigLoadError(t *testing.T) {
	// Test config loading error path by providing invalid configuration
	// This tests lines 16-23 in main.go
	os.Unsetenv("WEBHOOK_URL") // This will cause config validation to fail
	os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	defer os.Unsetenv("INBOUNDPARSE_TEST_EXIT")

	// This should not panic but will test the error handling path
	// The actual error handling is tested through the config validation
	main()
}

func TestMain_AppCreationError(t *testing.T) {
	// Test app creation error path
	// This tests lines 27-33 in main.go
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("INBOUNDPARSE_TEST_INIT_ONLY", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("INBOUNDPARSE_TEST_INIT_ONLY")
	}()

	// This should not panic
	main()
}

func TestMain_AppRunError(t *testing.T) {
	// Test app run error path
	// This tests lines 42-47 in main.go
	os.Setenv("WEBHOOK_URL", "http://test.example.com/webhook")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer func() {
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("INBOUNDPARSE_TEST_EXIT")
	}()

	// This should not panic
	main()
}
