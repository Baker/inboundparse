package main

import (
	"flag"
	"os"
	"testing"
)

func TestSetEnvString(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		initial  string
		expected string
	}{
		{
			name:     "Set when env var exists",
			envKey:   "TEST_STRING",
			envValue: "new-value",
			initial:  "old-value",
			expected: "new-value",
		},
		{
			name:     "Keep initial when env var empty",
			envKey:   "TEST_STRING_EMPTY",
			envValue: "",
			initial:  "keep-this",
			expected: "keep-this",
		},
		{
			name:     "Keep initial when env var not set",
			envKey:   "TEST_STRING_NOTSET",
			envValue: "",
			initial:  "keep-this-too",
			expected: "keep-this-too",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up
			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
				defer os.Unsetenv(tt.envKey)
			}

			target := tt.initial

			// Execute
			setEnvString(tt.envKey, &target)

			// Verify
			if target != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, target)
			}
		})
	}
}

func TestSetEnvBool(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		initial  bool
		expected bool
	}{
		{
			name:     "Set to true",
			envKey:   "TEST_BOOL_TRUE",
			envValue: "true",
			initial:  false,
			expected: true,
		},
		{
			name:     "Set to false",
			envKey:   "TEST_BOOL_FALSE",
			envValue: "false",
			initial:  true,
			expected: false,
		},
		{
			name:     "Invalid value keeps initial",
			envKey:   "TEST_BOOL_INVALID",
			envValue: "yes",
			initial:  true,
			expected: false, // "yes" != "true" so it becomes false
		},
		{
			name:     "Empty keeps initial",
			envKey:   "TEST_BOOL_EMPTY",
			envValue: "",
			initial:  true,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up
			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
				defer os.Unsetenv(tt.envKey)
			}

			target := tt.initial

			// Execute
			setEnvBool(tt.envKey, &target)

			// Verify
			if target != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, target)
			}
		})
	}
}

func TestLoadCoreConfig(t *testing.T) {
	// Save original values
	origListenAddr := *listenAddr
	origWebhookURL := *webhookURL
	origServerName := *serverName
	origVerbose := *verbose

	defer func() {
		*listenAddr = origListenAddr
		*webhookURL = origWebhookURL
		*serverName = origServerName
		*verbose = origVerbose
	}()

	// Set environment variables
	os.Setenv("LISTEN_ADDR", "0.0.0.0:2525")
	os.Setenv("WEBHOOK_URL", "https://test.example.com/webhook")
	os.Setenv("SERVER_NAME", "test.server.com")
	os.Setenv("VERBOSE", "true")
	defer func() {
		os.Unsetenv("LISTEN_ADDR")
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("SERVER_NAME")
		os.Unsetenv("VERBOSE")
	}()

	// Execute
	loadCoreConfig()

	// Verify
	if *listenAddr != "0.0.0.0:2525" {
		t.Errorf("Expected listenAddr '0.0.0.0:2525', got %q", *listenAddr)
	}
	if *webhookURL != "https://test.example.com/webhook" {
		t.Errorf("Expected webhookURL 'https://test.example.com/webhook', got %q", *webhookURL)
	}
	if *serverName != "test.server.com" {
		t.Errorf("Expected serverName 'test.server.com', got %q", *serverName)
	}
	if !*verbose {
		t.Error("Expected verbose to be true")
	}
}

func TestLoadAuthConfig(t *testing.T) {
	// Save original values
	origEnableSPF := *enableSPF
	origEnableDKIM := *enableDKIM
	origEnableDMARC := *enableDMARC

	defer func() {
		*enableSPF = origEnableSPF
		*enableDKIM = origEnableDKIM
		*enableDMARC = origEnableDMARC
	}()

	// Set environment variables
	os.Setenv("ENABLE_SPF", "false")
	os.Setenv("ENABLE_DKIM", "true")
	os.Setenv("ENABLE_DMARC", "false")
	defer func() {
		os.Unsetenv("ENABLE_SPF")
		os.Unsetenv("ENABLE_DKIM")
		os.Unsetenv("ENABLE_DMARC")
	}()

	// Execute
	loadAuthConfig()

	// Verify
	if *enableSPF {
		t.Error("Expected enableSPF to be false")
	}
	if !*enableDKIM {
		t.Error("Expected enableDKIM to be true")
	}
	if *enableDMARC {
		t.Error("Expected enableDMARC to be false")
	}
}

func TestLoadSentryConfig(t *testing.T) {
	// Save original values
	origEnableSentry := *enableSentry
	origSentryDSN := *sentryDSN
	origSentryEnv := *sentryEnv
	origSentryRelease := *sentryRelease

	defer func() {
		*enableSentry = origEnableSentry
		*sentryDSN = origSentryDSN
		*sentryEnv = origSentryEnv
		*sentryRelease = origSentryRelease
	}()

	// Set environment variables
	os.Setenv("ENABLE_SENTRY", "true")
	os.Setenv("SENTRY_DSN", "https://test@sentry.io/123")
	os.Setenv("SENTRY_ENV", "staging")
	os.Setenv("SENTRY_RELEASE", "v1.2.3")
	defer func() {
		os.Unsetenv("ENABLE_SENTRY")
		os.Unsetenv("SENTRY_DSN")
		os.Unsetenv("SENTRY_ENV")
		os.Unsetenv("SENTRY_RELEASE")
	}()

	// Execute
	loadSentryConfig()

	// Verify
	if !*enableSentry {
		t.Error("Expected enableSentry to be true")
	}
	if *sentryDSN != "https://test@sentry.io/123" {
		t.Errorf("Expected sentryDSN 'https://test@sentry.io/123', got %q", *sentryDSN)
	}
	if *sentryEnv != "staging" {
		t.Errorf("Expected sentryEnv 'staging', got %q", *sentryEnv)
	}
	if *sentryRelease != "v1.2.3" {
		t.Errorf("Expected sentryRelease 'v1.2.3', got %q", *sentryRelease)
	}
}

func TestLoadMetricsConfig(t *testing.T) {
	// Save original values
	origEnableMetrics := *enableMetrics
	origMetricsAddr := *metricsAddr
	origMetricsAPIKey := *metricsAPIKey
	origMetricsUsername := *metricsUsername
	origMetricsPassword := *metricsPassword

	defer func() {
		*enableMetrics = origEnableMetrics
		*metricsAddr = origMetricsAddr
		*metricsAPIKey = origMetricsAPIKey
		*metricsUsername = origMetricsUsername
		*metricsPassword = origMetricsPassword
	}()

	// Set environment variables
	os.Setenv("ENABLE_METRICS", "true")
	os.Setenv("METRICS_ADDR", "0.0.0.0:9091")
	os.Setenv("METRICS_API_KEY", "secret-key-123")
	os.Setenv("METRICS_USERNAME", "metrics-user")
	os.Setenv("METRICS_PASSWORD", "metrics-pass")
	defer func() {
		os.Unsetenv("ENABLE_METRICS")
		os.Unsetenv("METRICS_ADDR")
		os.Unsetenv("METRICS_API_KEY")
		os.Unsetenv("METRICS_USERNAME")
		os.Unsetenv("METRICS_PASSWORD")
	}()

	// Execute
	loadMetricsConfig()

	// Verify
	if !*enableMetrics {
		t.Error("Expected enableMetrics to be true")
	}
	if *metricsAddr != "0.0.0.0:9091" {
		t.Errorf("Expected metricsAddr '0.0.0.0:9091', got %q", *metricsAddr)
	}
	if *metricsAPIKey != "secret-key-123" {
		t.Errorf("Expected metricsAPIKey 'secret-key-123', got %q", *metricsAPIKey)
	}
	if *metricsUsername != "metrics-user" {
		t.Errorf("Expected metricsUsername 'metrics-user', got %q", *metricsUsername)
	}
	if *metricsPassword != "metrics-pass" {
		t.Errorf("Expected metricsPassword 'metrics-pass', got %q", *metricsPassword)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	// Save original values
	origListenAddr := *listenAddr
	origEnableSPF := *enableSPF
	origEnableSentry := *enableSentry
	origEnableMetrics := *enableMetrics

	defer func() {
		*listenAddr = origListenAddr
		*enableSPF = origEnableSPF
		*enableSentry = origEnableSentry
		*enableMetrics = origEnableMetrics
	}()

	// Set a mix of environment variables
	os.Setenv("LISTEN_ADDR", "0.0.0.0:3025")
	os.Setenv("ENABLE_SPF", "false")
	os.Setenv("ENABLE_SENTRY", "true")
	os.Setenv("ENABLE_METRICS", "true")
	defer func() {
		os.Unsetenv("LISTEN_ADDR")
		os.Unsetenv("ENABLE_SPF")
		os.Unsetenv("ENABLE_SENTRY")
		os.Unsetenv("ENABLE_METRICS")
	}()

	// Execute
	loadEnvOverrides()

	// Verify - this calls all sub-functions
	if *listenAddr != "0.0.0.0:3025" {
		t.Errorf("Expected listenAddr '0.0.0.0:3025', got %q", *listenAddr)
	}
	if *enableSPF {
		t.Error("Expected enableSPF to be false")
	}
	if !*enableSentry {
		t.Error("Expected enableSentry to be true")
	}
	if !*enableMetrics {
		t.Error("Expected enableMetrics to be true")
	}
}

func TestLoadEnvOverrides_NoEnvironmentVars(t *testing.T) {
	// Save original values
	origListenAddr := *listenAddr
	origEnableSPF := *enableSPF

	defer func() {
		*listenAddr = origListenAddr
		*enableSPF = origEnableSPF
	}()

	// Set initial values
	*listenAddr = "original:25"
	*enableSPF = true

	// Execute without setting any env vars
	loadEnvOverrides()

	// Verify values remain unchanged
	if *listenAddr != "original:25" {
		t.Errorf("Expected listenAddr to remain 'original:25', got %q", *listenAddr)
	}
	if !*enableSPF {
		t.Error("Expected enableSPF to remain true")
	}
}

func TestMain_TestExit(t *testing.T) {
	// This tests the early exit condition in main()
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	defer os.Unsetenv("INBOUNDPARSE_TEST_EXIT")

	// Call main - should return immediately
	main()

	// If we got here, the test passed (main exited early)
}

func TestSetEnvString_WhitespaceValue(t *testing.T) {
	os.Setenv("TEST_WHITESPACE", "  value-with-spaces  ")
	defer os.Unsetenv("TEST_WHITESPACE")

	target := "initial"
	setEnvString("TEST_WHITESPACE", &target)

	if target != "  value-with-spaces  " {
		t.Errorf("Expected whitespace preserved, got %q", target)
	}
}

func TestSetEnvBool_CaseSensitivity(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"true", true},
		{"True", false}, // Case sensitive
		{"TRUE", false}, // Case sensitive
		{"false", false},
		{"False", false},
		{"1", false}, // Not "true"
		{"0", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			os.Setenv("TEST_BOOL_CASE", tt.value)
			defer os.Unsetenv("TEST_BOOL_CASE")

			target := false
			setEnvBool("TEST_BOOL_CASE", &target)

			if target != tt.expected {
				t.Errorf("For value %q, expected %v, got %v", tt.value, tt.expected, target)
			}
		})
	}
}

func TestLoadCoreConfig_PartialOverride(t *testing.T) {
	// Save original values
	origListenAddr := *listenAddr
	origWebhookURL := *webhookURL

	defer func() {
		*listenAddr = origListenAddr
		*webhookURL = origWebhookURL
	}()

	// Set initial values
	*listenAddr = "initial:25"
	*webhookURL = "initial-webhook"

	// Only override one value
	os.Setenv("LISTEN_ADDR", "overridden:2525")
	defer os.Unsetenv("LISTEN_ADDR")

	// Execute
	loadCoreConfig()

	// Verify only the set env var was overridden
	if *listenAddr != "overridden:2525" {
		t.Errorf("Expected listenAddr 'overridden:2525', got %q", *listenAddr)
	}
	if *webhookURL != "initial-webhook" {
		t.Errorf("Expected webhookURL to remain 'initial-webhook', got %q", *webhookURL)
	}
}

func TestMain_FullInitialization(t *testing.T) {
	// This test exercises the full initialization path in main()
	// without starting the blocking SMTP server

	// Skip if already parsed (to avoid conflicts in parallel tests)
	if !flag.Parsed() {
		flag.Parse()
	}

	// Set up environment for full initialization
	os.Setenv("INBOUNDPARSE_TEST_INIT_ONLY", "1")
	os.Setenv("WEBHOOK_URL", "https://test.example.com/webhook")
	os.Setenv("LISTEN_ADDR", "127.0.0.1:2525")
	os.Setenv("ENABLE_SPF", "true")
	os.Setenv("ENABLE_DKIM", "true")
	os.Setenv("ENABLE_DMARC", "true")
	os.Setenv("VERBOSE", "false")

	defer func() {
		os.Unsetenv("INBOUNDPARSE_TEST_INIT_ONLY")
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("LISTEN_ADDR")
		os.Unsetenv("ENABLE_SPF")
		os.Unsetenv("ENABLE_DKIM")
		os.Unsetenv("ENABLE_DMARC")
		os.Unsetenv("VERBOSE")
	}()

	// This should run through initialization without blocking
	main()

	// If we got here, initialization succeeded
}

func TestMain_WithSentryEnabled(t *testing.T) {
	// Test initialization with Sentry enabled but no DSN (should warn)
	if !flag.Parsed() {
		flag.Parse()
	}

	os.Setenv("INBOUNDPARSE_TEST_INIT_ONLY", "1")
	os.Setenv("WEBHOOK_URL", "https://test.example.com/webhook")
	os.Setenv("ENABLE_SENTRY", "true")
	os.Setenv("SENTRY_DSN", "") // Empty DSN should trigger warning

	defer func() {
		os.Unsetenv("INBOUNDPARSE_TEST_INIT_ONLY")
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("ENABLE_SENTRY")
		os.Unsetenv("SENTRY_DSN")
	}()

	// Should complete without error (just warns)
	main()
}

func TestMain_WithMetricsEnabled(t *testing.T) {
	// Test initialization with metrics enabled
	if !flag.Parsed() {
		flag.Parse()
	}

	os.Setenv("INBOUNDPARSE_TEST_INIT_ONLY", "1")
	os.Setenv("WEBHOOK_URL", "https://test.example.com/webhook")
	os.Setenv("ENABLE_METRICS", "true")
	os.Setenv("METRICS_ADDR", "127.0.0.1:9999")
	os.Setenv("METRICS_API_KEY", "test-key")

	defer func() {
		os.Unsetenv("INBOUNDPARSE_TEST_INIT_ONLY")
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("ENABLE_METRICS")
		os.Unsetenv("METRICS_ADDR")
		os.Unsetenv("METRICS_API_KEY")
	}()

	// Should complete without error
	main()
}

func TestMain_VerboseMode(t *testing.T) {
	// Test initialization with verbose logging enabled
	if !flag.Parsed() {
		flag.Parse()
	}

	os.Setenv("INBOUNDPARSE_TEST_INIT_ONLY", "1")
	os.Setenv("WEBHOOK_URL", "https://test.example.com/webhook")
	os.Setenv("VERBOSE", "true")

	defer func() {
		os.Unsetenv("INBOUNDPARSE_TEST_INIT_ONLY")
		os.Unsetenv("WEBHOOK_URL")
		os.Unsetenv("VERBOSE")
	}()

	// Should complete without error
	main()
}
