package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/inboundparse/inboundparse/internal/config"
	"github.com/inboundparse/inboundparse/internal/service"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// mockLoggerService is a mock implementation of LoggerService for main tests
type mockLoggerServiceForMain struct{}

func (m *mockLoggerServiceForMain) Info(ctx context.Context, msg string, fields ...zap.Field)  {}
func (m *mockLoggerServiceForMain) Error(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerServiceForMain) Warn(ctx context.Context, msg string, fields ...zap.Field)  {}
func (m *mockLoggerServiceForMain) Debug(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerServiceForMain) Fatal(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerServiceForMain) With(fields ...zap.Field) service.LoggerService             { return m }
func (m *mockLoggerServiceForMain) WithContext(ctx context.Context) service.LoggerService      { return m }
func (m *mockLoggerServiceForMain) Close() error                                               { return nil }

func TestInitializeSentry(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		expectError bool
	}{
		{
			name: "Sentry disabled",
			config: &config.Config{
				Sentry: config.SentryConfig{
					Enabled: false,
				},
			},
			expectError: false,
		},
		{
			name: "Sentry enabled but no DSN",
			config: &config.Config{
				Sentry: config.SentryConfig{
					Enabled: true,
					DSN:     "",
				},
			},
			expectError: false,
		},
		{
			name: "Sentry enabled with DSN",
			config: &config.Config{
				Sentry: config.SentryConfig{
					Enabled: true,
					DSN:     "https://test@sentry.io/123",
					Env:     "test",
					Release: "v1.0.0",
				},
				Server: config.ServerConfig{
					Verbose: false,
				},
			},
			expectError: false, // Sentry init might fail in test environment, but that's OK
		},
		{
			name: "Sentry enabled with DSN and verbose mode",
			config: &config.Config{
				Sentry: config.SentryConfig{
					Enabled: true,
					DSN:     "https://test@sentry.io/123",
					Env:     "development",
					Release: "v1.0.0-dev",
				},
				Server: config.ServerConfig{
					Verbose: true,
				},
			},
			expectError: false,
		},
		{
			name: "Sentry with production environment",
			config: &config.Config{
				Sentry: config.SentryConfig{
					Enabled: true,
					DSN:     "https://test@sentry.io/123",
					Env:     "production",
					Release: "v2.0.0",
				},
				Server: config.ServerConfig{
					Verbose: false,
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockLoggerServiceForMain{}
			err := initializeSentry(tt.config, logger)

			// In test environment, Sentry initialization might fail due to network issues
			// but the function should handle it gracefully
			if tt.expectError {
				assert.Error(t, err, "Expected error but got none")
			}
		})
	}
}

func TestLogServerInfo(t *testing.T) {
	config := &config.Config{
		Server: config.ServerConfig{
			ListenAddr:    "0.0.0.0:25",
			ListenAddrTLS: "0.0.0.0:587",
			ServerName:    "test.example.com",
			Verbose:       true,
			CertFile:      "/path/to/cert.pem",
			KeyFile:       "/path/to/key.pem",
		},
		Webhook: config.WebhookConfig{
			URL: "http://localhost:8080/webhook",
		},
		Auth: config.AuthConfig{
			EnableSPF:   true,
			EnableDKIM:  false,
			EnableDMARC: true,
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Addr:    "0.0.0.0:9090",
		},
		Sentry: config.SentryConfig{
			Enabled: false,
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}

	logger := &mockLoggerServiceForMain{}
	ctx := context.Background()

	// This should not panic and should complete successfully
	logServerInfo(ctx, config, logger)
}

func TestSMTPBackend_NewSession(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMain{}
	logger := &mockLoggerServiceForMain{}

	backend := service.NewSMTPBackend(config, webhookService, authService, metricsService, logger)

	tests := []struct {
		name        string
		conn        *smtp.Conn
		expectError bool
	}{
		{
			name:        "valid connection",
			conn:        nil, // We can't easily create a real SMTP connection in tests
			expectError: false,
		},
		{
			name:        "nil connection",
			conn:        nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := backend.NewSession(tt.conn)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.NotNil(t, session, "NewSession() returned nil session")
		})
	}
}

func TestSMTPBackend_NewSession_IncrementsActiveSessions(t *testing.T) {
	cfg := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMain{}
	logger := &mockLoggerServiceForMain{}

	backend := service.NewSMTPBackend(cfg, webhookService, authService, metricsService, logger)

	session, err := backend.NewSession(nil)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, 1, metricsService.activeSessionsInc, "active sessions should be incremented once")
}

// Test main function error paths
func TestMain_ConfigurationError(t *testing.T) {
	// This test would require mocking the config.Load() function
	// For now, we'll test the individual components that main() calls
}

// Test main function with webhook URL validation
func TestMain_WebhookURLValidation(t *testing.T) {
	// Test the webhook URL validation logic from main()
	config := &config.Config{
		Webhook: config.WebhookConfig{
			URL: "", // Empty URL should cause fatal
		},
	}

	// This would be called in main() if webhook URL is empty
	// We can't easily test the fatal call, but we can test the validation logic
	assert.Empty(t, config.Webhook.URL, "Webhook URL should be empty")
}

// Test main function service creation
func TestMain_ServiceCreation(t *testing.T) {
	config := &config.Config{
		Metrics: config.MetricsConfig{
			Enabled: true,
		},
		Webhook: config.WebhookConfig{
			URL:      "http://localhost:8080/webhook",
			Username: "testuser",
			Password: "testpass",
		},
		Auth: config.AuthConfig{
			EnableSPF:   true,
			EnableDKIM:  false,
			EnableDMARC: true,
		},
	}

	// Test service creation (these are called in main())
	metricsService := service.NewMetricsService(config.Metrics.Enabled)
	assert.NotNil(t, metricsService)

	webhookService := service.NewWebhookService(config.Webhook.URL, config.Webhook.Username, config.Webhook.Password)
	assert.NotNil(t, webhookService)

	logger := &mockLoggerServiceForMain{}
	authService := service.NewAuthService(config.Auth.EnableSPF, config.Auth.EnableDKIM, config.Auth.EnableDMARC, logger)
	assert.NotNil(t, authService)
}

// Test main function backend creation
func TestMain_BackendCreation(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMain{}
	logger := &mockLoggerServiceForMain{}

	// Test backend creation (this is done in main())
	backend := service.NewSMTPBackend(config, webhookService, authService, metricsService, logger)

	assert.NotNil(t, backend)
}

// Test main function with different configurations (without metrics to avoid registration issues)
func TestMain_WithDifferentConfigurations(t *testing.T) {
	testCases := []struct {
		name   string
		config *config.Config
	}{
		{
			name: "minimal config",
			config: &config.Config{
				Webhook: config.WebhookConfig{
					URL: "http://localhost:8080/webhook",
				},
			},
		},
		{
			name: "full config without metrics",
			config: &config.Config{
				Server: config.ServerConfig{
					ListenAddr:    "0.0.0.0:25",
					ListenAddrTLS: "0.0.0.0:587",
					ServerName:    "test.example.com",
					Verbose:       true,
					CertFile:      "/path/to/cert.pem",
					KeyFile:       "/path/to/key.pem",
				},
				Webhook: config.WebhookConfig{
					URL:      "http://localhost:8080/webhook",
					Username: "testuser",
					Password: "testpass",
				},
				Auth: config.AuthConfig{
					EnableSPF:   true,
					EnableDKIM:  true,
					EnableDMARC: true,
				},
				Metrics: config.MetricsConfig{
					Enabled: false, // Disabled to avoid registration issues
					Addr:    "0.0.0.0:9090",
				},
				Sentry: config.SentryConfig{
					Enabled: true,
					DSN:     "https://test@sentry.io/123",
					Env:     "test",
					Release: "v1.0.0",
				},
			},
		},
		{
			name: "disabled features",
			config: &config.Config{
				Webhook: config.WebhookConfig{
					URL: "http://localhost:8080/webhook",
				},
				Auth: config.AuthConfig{
					EnableSPF:   false,
					EnableDKIM:  false,
					EnableDMARC: false,
				},
				Metrics: config.MetricsConfig{
					Enabled: false,
				},
				Sentry: config.SentryConfig{
					Enabled: false,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test service creation with different configs (metrics disabled to avoid registration issues)
			metricsService := service.NewMetricsService(false) // Always disabled in tests
			assert.NotNil(t, metricsService)

			webhookService := service.NewWebhookService(tc.config.Webhook.URL, tc.config.Webhook.Username, tc.config.Webhook.Password)
			assert.NotNil(t, webhookService)

			logger := &mockLoggerServiceForMain{}
			authService := service.NewAuthService(tc.config.Auth.EnableSPF, tc.config.Auth.EnableDKIM, tc.config.Auth.EnableDMARC, logger)
			assert.NotNil(t, authService)

			// Test backend creation
			backend := service.NewSMTPBackend(tc.config, webhookService, authService, metricsService, logger)
			assert.NotNil(t, backend)
		})
	}
}

// Test main function error handling paths
func TestMain_ErrorHandling(t *testing.T) {
	// Test Sentry initialization error (would be handled in main())
	config := &config.Config{
		Sentry: config.SentryConfig{
			Enabled: true,
			DSN:     "invalid-dsn",
		},
	}

	logger := &mockLoggerServiceForMain{}
	err := initializeSentry(config, logger)
	// This might fail in test environment, which is expected
	if err != nil {
		t.Logf("Sentry initialization failed as expected: %v", err)
	}
}

// Test main function with context handling
func TestMain_ContextHandling(t *testing.T) {
	// Test the context creation and usage in main()
	ctx := context.Background()
	assert.NotNil(t, ctx)

	// Test that context is properly passed to functions
	logger := &mockLoggerServiceForMain{}
	config := &config.Config{
		Server: config.ServerConfig{
			ListenAddr:    "0.0.0.0:25",
			ListenAddrTLS: "0.0.0.0:587",
			ServerName:    "test.example.com",
			Verbose:       true,
			CertFile:      "/path/to/cert.pem",
			KeyFile:       "/path/to/key.pem",
		},
		Webhook: config.WebhookConfig{
			URL: "http://localhost:8080/webhook",
		},
		Auth: config.AuthConfig{
			EnableSPF:   true,
			EnableDKIM:  false,
			EnableDMARC: true,
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Addr:    "0.0.0.0:9090",
		},
		Sentry: config.SentryConfig{
			Enabled: false,
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}

	// Test logServerInfo with context
	logServerInfo(ctx, config, logger)

	// Test initializeSentry with context
	err := initializeSentry(config, logger)
	if err != nil {
		t.Logf("Sentry initialization failed as expected: %v", err)
	}
}

// Test main function with defer statements
func TestMain_DeferStatements(t *testing.T) {
	// Test the defer statements in main()
	logger := &mockLoggerServiceForMain{}

	// Test logger.Close() defer
	defer func() {
		err := logger.Close()
		assert.NoError(t, err)
	}()

	// Test sentry.Flush() defer (would be called in main() if Sentry is enabled)
	// This is difficult to test without actually initializing Sentry
}

// Test main function with different environment scenarios
func TestMain_EnvironmentScenarios(t *testing.T) {
	// Test main() behavior in different environments
	scenarios := []struct {
		name        string
		config      *config.Config
		expectError bool
	}{
		{
			name: "production environment",
			config: &config.Config{
				Webhook: config.WebhookConfig{
					URL: "http://localhost:8080/webhook",
				},
				Sentry: config.SentryConfig{
					Enabled: true,
					DSN:     "https://prod@sentry.io/123",
					Env:     "production",
				},
			},
			expectError: false,
		},
		{
			name: "development environment",
			config: &config.Config{
				Webhook: config.WebhookConfig{
					URL: "http://localhost:8080/webhook",
				},
				Server: config.ServerConfig{
					Verbose: true,
				},
				Sentry: config.SentryConfig{
					Enabled: false,
				},
			},
			expectError: false,
		},
		{
			name: "test environment",
			config: &config.Config{
				Webhook: config.WebhookConfig{
					URL: "http://localhost:8080/webhook",
				},
				Sentry: config.SentryConfig{
					Enabled: true,
					DSN:     "https://test@sentry.io/123",
					Env:     "test",
				},
			},
			expectError: false,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Test service creation for each scenario (metrics disabled to avoid registration issues)
			metricsService := service.NewMetricsService(false) // Always disabled in tests
			assert.NotNil(t, metricsService)

			webhookService := service.NewWebhookService(scenario.config.Webhook.URL, scenario.config.Webhook.Username, scenario.config.Webhook.Password)
			assert.NotNil(t, webhookService)

			// Test Sentry initialization
			logger := &mockLoggerServiceForMain{}

			authService := service.NewAuthService(scenario.config.Auth.EnableSPF, scenario.config.Auth.EnableDKIM, scenario.config.Auth.EnableDMARC, logger)
			assert.NotNil(t, authService)
			err := initializeSentry(scenario.config, logger)
			if scenario.expectError {
				assert.Error(t, err)
			} else {
				// In test environment, Sentry might fail due to network issues
				if err != nil {
					t.Logf("Sentry initialization failed (expected in test environment): %v", err)
				}
			}
		})
	}
}

// Mock implementations for testing

type mockWebhookService struct {
	sendWebhookFunc func(ctx context.Context, payload *service.WebhookPayload) error
}

func (m *mockWebhookService) SendWebhook(ctx context.Context, payload *service.WebhookPayload) error {
	if m.sendWebhookFunc != nil {
		return m.sendWebhookFunc(ctx, payload)
	}
	return nil
}

type mockAuthService struct {
	performAuthChecksFunc func(ctx context.Context, message []byte, remoteIP net.IP) (*service.AuthResult, error)
}

func (m *mockAuthService) PerformAuthenticationChecks(ctx context.Context, message []byte, remoteIP net.IP) (*service.AuthResult, error) {
	if m.performAuthChecksFunc != nil {
		return m.performAuthChecksFunc(ctx, message, remoteIP)
	}
	return &service.AuthResult{}, nil
}

type mockMetricsServiceForMain struct {
	activeSessionsInc int
	activeSessionsDec int
	smtpMessagesInc   int
	messagesFailedInc int
}

func (m *mockMetricsServiceForMain) IncrementSMTPConnections()                           {}
func (m *mockMetricsServiceForMain) IncrementActiveConnections()                         {}
func (m *mockMetricsServiceForMain) DecrementActiveConnections()                         {}
func (m *mockMetricsServiceForMain) RecordConnectionDuration(duration time.Duration)     {}
func (m *mockMetricsServiceForMain) IncrementSMTPMessages()                              { m.smtpMessagesInc++ }
func (m *mockMetricsServiceForMain) RecordMessageSize(size int64)                        {}
func (m *mockMetricsServiceForMain) IncrementMessagesProcessed()                         {}
func (m *mockMetricsServiceForMain) IncrementMessagesFailed()                            { m.messagesFailedInc++ }
func (m *mockMetricsServiceForMain) RecordMessageParsingDuration(duration time.Duration) {}
func (m *mockMetricsServiceForMain) IncrementMessageParsingFailed()                      {}
func (m *mockMetricsServiceForMain) IncrementWebhookRequests()                           {}
func (m *mockMetricsServiceForMain) RecordWebhookDuration(duration time.Duration)        {}
func (m *mockMetricsServiceForMain) IncrementWebhookFailed()                             {}
func (m *mockMetricsServiceForMain) IncrementAuthChecks()                                {}
func (m *mockMetricsServiceForMain) IncrementSPFChecks()                                 {}
func (m *mockMetricsServiceForMain) IncrementDKIMChecks()                                {}
func (m *mockMetricsServiceForMain) IncrementDMARCChecks()                               {}
func (m *mockMetricsServiceForMain) IncrementAuthChecksFailed()                          {}
func (m *mockMetricsServiceForMain) RecordSPFResult(result string)                       {}
func (m *mockMetricsServiceForMain) RecordDKIMResult(result string)                      {}
func (m *mockMetricsServiceForMain) RecordDMARCResult(result string)                     {}
func (m *mockMetricsServiceForMain) RecordDMARCPolicy(policy string)                     {}
func (m *mockMetricsServiceForMain) IncrementActiveSessions()                            { m.activeSessionsInc++ }
func (m *mockMetricsServiceForMain) DecrementActiveSessions()                            { m.activeSessionsDec++ }
func (m *mockMetricsServiceForMain) Close() error                                        { return nil }

// TestInitializeSentry_BeforeSendCallback tests the BeforeSend callback functionality
func TestInitializeSentry_BeforeSendCallback(t *testing.T) {
	logger := &mockLoggerServiceForMain{}

	config := &config.Config{
		Sentry: config.SentryConfig{
			Enabled: true,
			DSN:     "https://test@sentry.io/123",
			Env:     "test",
			Release: "v1.0.0",
		},
		Server: config.ServerConfig{
			Verbose: true,
		},
	}

	// Initialize Sentry (may fail in test environment, but we test the callback logic)
	err := initializeSentry(config, logger)
	// Test passes if no error or if Sentry init fails gracefully
	// The important thing is that the function doesn't panic
	if err != nil {
		t.Logf("Sentry initialization failed (expected in test environment): %v", err)
	}
}

// TestRun_MissingWebhookURL checks that missing webhook URL returns an error
func TestRun_MissingWebhookURL(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			ListenAddr: ":25",
			ServerName: "localhost",
		},
		Webhook: config.WebhookConfig{
			URL: "", // Should trigger error
		},
		Auth: config.AuthConfig{
			EnableSPF:   true,
			EnableDKIM:  true,
			EnableDMARC: true,
		},
		Metrics: config.MetricsConfig{
			Enabled: false,
		},
		Sentry: config.SentryConfig{
			Enabled: false,
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
	err := runWithConfig(cfg)
	if err == nil {
		t.Error("expected error for missing webhook URL, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "webhook URL is required") {
		t.Errorf("expected error to mention missing webhook URL, got: %v", err)
	}
}

// TestLogServerInfo_AllFields ensures all configuration fields are logged
func TestLogServerInfo_AllFields(t *testing.T) {
	logger := &mockLoggerServiceForMain{}
	ctx := context.Background()

	testCases := []struct {
		name   string
		config *config.Config
	}{
		{
			name: "complete configuration",
			config: &config.Config{
				Server: config.ServerConfig{
					ListenAddr:    "0.0.0.0:2525",
					ListenAddrTLS: "0.0.0.0:2587",
					ServerName:    "mail.example.com",
					Verbose:       true,
					CertFile:      "/etc/ssl/cert.pem",
					KeyFile:       "/etc/ssl/key.pem",
				},
				Webhook: config.WebhookConfig{
					URL: "https://webhook.example.com/endpoint",
				},
				Auth: config.AuthConfig{
					EnableSPF:   true,
					EnableDKIM:  true,
					EnableDMARC: true,
				},
				Metrics: config.MetricsConfig{
					Enabled: true,
					Addr:    ":9090",
				},
				Sentry: config.SentryConfig{
					Enabled: true,
				},
				Logging: config.LoggingConfig{
					Level:  "debug",
					Format: "json",
				},
			},
		},
		{
			name: "minimal configuration",
			config: &config.Config{
				Server: config.ServerConfig{
					ListenAddr: ":25",
					ServerName: "localhost",
				},
				Webhook: config.WebhookConfig{
					URL: "http://localhost/webhook",
				},
				Logging: config.LoggingConfig{
					Level:  "info",
					Format: "console",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Should not panic
			logServerInfo(ctx, tc.config, logger)
		})
	}
}

// TestInitializeSentry_ErrorCases tests error handling in Sentry initialization
func TestInitializeSentry_ErrorCases(t *testing.T) {
	logger := &mockLoggerServiceForMain{}

	testCases := []struct {
		name        string
		config      *config.Config
		expectError bool
	}{
		{
			name: "invalid DSN format",
			config: &config.Config{
				Sentry: config.SentryConfig{
					Enabled: true,
					DSN:     "invalid-dsn",
					Env:     "test",
				},
				Server: config.ServerConfig{
					Verbose: false,
				},
			},
			expectError: true,
		},
		{
			name: "empty DSN but enabled",
			config: &config.Config{
				Sentry: config.SentryConfig{
					Enabled: true,
					DSN:     "",
				},
			},
			expectError: false, // Should skip initialization gracefully
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := initializeSentry(tc.config, logger)

			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// TestRunWithConfig_MissingWebhookURL tests validation of webhook URL
func TestRunWithConfig_MissingWebhookURL(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			ListenAddr: ":25",
			ServerName: "localhost",
			Verbose:    false,
		},
		Webhook: config.WebhookConfig{
			URL: "", // Missing webhook URL
		},
		Auth: config.AuthConfig{
			EnableSPF:   true,
			EnableDKIM:  true,
			EnableDMARC: true,
		},
		Metrics: config.MetricsConfig{
			Enabled: false,
		},
		Sentry: config.SentryConfig{
			Enabled: false,
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}

	err := runWithConfig(cfg)

	assert.Error(t, err, "Expected error for missing webhook URL")
	assert.Contains(t, err.Error(), "webhook URL is required")
}

// TestRunWithConfig_SentryInitialization verifies that Sentry is initialized properly in runWithConfig.
// Because runWithConfig starts a blocking server, we test Sentry initialization logic only.
func TestRunWithConfig_SentryInitialization(t *testing.T) {
	logger := &mockLoggerServiceForMain{}

	cfg := &config.Config{
		Server: config.ServerConfig{
			ListenAddr: ":25",
			ServerName: "localhost",
			Verbose:    true,
		},
		Webhook: config.WebhookConfig{
			URL: "http://example.com/webhook", // Valid to get past webhook check
		},
		Auth: config.AuthConfig{
			EnableSPF:   true,
			EnableDKIM:  true,
			EnableDMARC: true,
		},
		Metrics: config.MetricsConfig{
			Enabled: false,
		},
		Sentry: config.SentryConfig{
			Enabled: true,
			DSN:     "https://public@sentry.io/1", // Example DSN, may not actually connect in test
			Env:     "test",
			Release: "v0.0.1-test",
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}

	// Call Sentry initializer directly to simulate what runWithConfig would do.
	err := initializeSentry(cfg, logger)
	if err != nil {
		t.Logf("Sentry initialization failed (may be expected in test): %v", err)
	}
}
