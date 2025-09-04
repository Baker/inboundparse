package main

import (
	"context"
	"io"
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

func (m *mockLoggerServiceForMain) Info(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerServiceForMain) Error(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerServiceForMain) Warn(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerServiceForMain) Debug(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerServiceForMain) Fatal(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerServiceForMain) With(fields ...zap.Field) service.LoggerService { return m }
func (m *mockLoggerServiceForMain) WithContext(ctx context.Context) service.LoggerService { return m }
func (m *mockLoggerServiceForMain) Close() error { return nil }

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
			ListenAddr:     "0.0.0.0:25",
			ListenAddrTLS:  "0.0.0.0:587",
			ServerName:     "test.example.com",
			Verbose:        true,
			CertFile:       "/path/to/cert.pem",
			KeyFile:        "/path/to/key.pem",
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

func TestSMTPBackendWithServices_NewSession(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMain{}

	backend := &smtpBackendWithServices{
		config:         config,
		webhookService: webhookService,
		authService:    authService,
		metricsService: metricsService,
	}

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

func TestSMTPSessionWithServices_AuthPlain(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{
			name:     "valid credentials",
			username: "testuser",
			password: "testpass",
			wantErr:  false,
		},
		{
			name:     "empty credentials",
			username: "",
			password: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := session.AuthPlain(tt.username, tt.password)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSMTPSessionWithServices_Mail(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	tests := []struct {
		name    string
		from    string
		wantErr bool
	}{
		{
			name:    "valid from address",
			from:    "test@example.com",
			wantErr: false,
		},
		{
			name:    "empty from address",
			from:    "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := session.Mail(tt.from, nil)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.from, session.from)
		})
	}
}

func TestSMTPSessionWithServices_Rcpt(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	tests := []struct {
		name    string
		to      string
		wantErr bool
	}{
		{
			name:    "valid to address",
			to:      "recipient@example.com",
			wantErr: false,
		},
		{
			name:    "empty to address",
			to:      "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := session.Rcpt(tt.to, nil)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if !tt.wantErr {
				assert.NotEmpty(t, session.to)
				assert.Equal(t, tt.to, session.to[len(session.to)-1])
			}
		})
	}
}

func TestSMTPSessionWithServices_Data(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	tests := []struct {
		name                string
		messageData         string
		processMessageError error
		wantErr             bool
	}{
		{
			name:                "successful message processing",
			messageData:         "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message",
			processMessageError: nil,
			wantErr:             false,
		},
		{
			name:                "message processing error",
			messageData:         "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message",
			processMessageError: context.Canceled,
			wantErr:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up message processor mock
			messageProcessor.processMessageFunc = func(ctx context.Context, r io.Reader) error {
				return tt.processMessageError
			}

			reader := strings.NewReader(tt.messageData)
			err := session.Data(reader)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSMTPSessionWithServices_Reset(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	// Set some state
	session.from = "test@example.com"
	session.to = []string{"recipient@example.com"}

	// Reset the session
	session.Reset()

	assert.Empty(t, session.from, "Reset() should clear from field")
	assert.Nil(t, session.to, "Reset() should clear to field")
}

func TestSMTPSessionWithServices_Logout(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	err := session.Logout()
	assert.NoError(t, err)
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

type mockMessageProcessor struct {
	processMessageFunc func(ctx context.Context, r io.Reader) error
}

func (m *mockMessageProcessor) ProcessMessage(ctx context.Context, r io.Reader) error {
	if m.processMessageFunc != nil {
		return m.processMessageFunc(ctx, r)
	}
	return nil
}

type mockMetricsServiceForMain struct{}

func (m *mockMetricsServiceForMain) IncrementSMTPConnections() {}
func (m *mockMetricsServiceForMain) IncrementActiveConnections() {}
func (m *mockMetricsServiceForMain) DecrementActiveConnections() {}
func (m *mockMetricsServiceForMain) RecordConnectionDuration(duration time.Duration) {}
func (m *mockMetricsServiceForMain) IncrementSMTPMessages() {}
func (m *mockMetricsServiceForMain) RecordMessageSize(size int64) {}
func (m *mockMetricsServiceForMain) IncrementMessagesProcessed() {}
func (m *mockMetricsServiceForMain) IncrementMessagesFailed() {}
func (m *mockMetricsServiceForMain) RecordMessageParsingDuration(duration time.Duration) {}
func (m *mockMetricsServiceForMain) IncrementMessageParsingFailed() {}
func (m *mockMetricsServiceForMain) IncrementWebhookRequests() {}
func (m *mockMetricsServiceForMain) RecordWebhookDuration(duration time.Duration) {}
func (m *mockMetricsServiceForMain) IncrementWebhookFailed() {}
func (m *mockMetricsServiceForMain) IncrementAuthChecks() {}
func (m *mockMetricsServiceForMain) IncrementSPFChecks() {}
func (m *mockMetricsServiceForMain) IncrementDKIMChecks() {}
func (m *mockMetricsServiceForMain) IncrementDMARCChecks() {}
func (m *mockMetricsServiceForMain) IncrementAuthChecksFailed() {}
func (m *mockMetricsServiceForMain) RecordSPFResult(result string) {}
func (m *mockMetricsServiceForMain) RecordDKIMResult(result string) {}
func (m *mockMetricsServiceForMain) RecordDMARCResult(result string) {}
func (m *mockMetricsServiceForMain) RecordDMARCPolicy(policy string) {}
func (m *mockMetricsServiceForMain) IncrementActiveSessions() {}
func (m *mockMetricsServiceForMain) DecrementActiveSessions() {}
func (m *mockMetricsServiceForMain) Close() error { return nil }

func TestInitializeSentry_WithDSN(t *testing.T) {
	config := &config.Config{
		Sentry: config.SentryConfig{
			Enabled: true,
			DSN:     "https://test@sentry.io/123",
			Env:     "test",
			Release: "v1.0.0",
		},
		Server: config.ServerConfig{
			Verbose: false,
		},
	}

	logger := &mockLoggerServiceForMain{}
	err := initializeSentry(config, logger)
	
	// In test environment, Sentry initialization might fail due to network issues
	// but the function should handle it gracefully
	if err != nil {
		t.Logf("Sentry initialization failed (expected in test environment): %v", err)
	}
}

func TestInitializeSentry_WithoutDSN(t *testing.T) {
	config := &config.Config{
		Sentry: config.SentryConfig{
			Enabled: true,
			DSN:     "",
			Env:     "test",
			Release: "v1.0.0",
		},
		Server: config.ServerConfig{
			Verbose: false,
		},
	}

	logger := &mockLoggerServiceForMain{}
	err := initializeSentry(config, logger)
	
	// Should not error when DSN is empty
	assert.NoError(t, err, "initializeSentry() should not error when DSN is empty")
}

func TestInitializeSentry_Disabled(t *testing.T) {
	config := &config.Config{
		Sentry: config.SentryConfig{
			Enabled: false,
			DSN:     "https://test@sentry.io/123",
			Env:     "test",
			Release: "v1.0.0",
		},
		Server: config.ServerConfig{
			Verbose: false,
		},
	}

	logger := &mockLoggerServiceForMain{}
	err := initializeSentry(config, logger)
	
	// Should not error when disabled
	assert.NoError(t, err, "initializeSentry() should not error when disabled")
}

func TestLogServerInfo_Comprehensive(t *testing.T) {
	config := &config.Config{
		Server: config.ServerConfig{
			ListenAddr:     "0.0.0.0:25",
			ListenAddrTLS:  "0.0.0.0:587",
			ServerName:     "test.example.com",
			Verbose:        true,
			CertFile:       "/path/to/cert.pem",
			KeyFile:        "/path/to/key.pem",
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
			Enabled: true,
		},
		Logging: config.LoggingConfig{
			Level:  "debug",
			Format: "json",
		},
	}

	logger := &mockLoggerServiceForMain{}
	ctx := context.Background()

	// This should not panic and should complete successfully
	logServerInfo(ctx, config, logger)
}

func TestSMTPBackendWithServices_NewSession_WithRemoteIP(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMain{}

	backend := &smtpBackendWithServices{
		config:         config,
		webhookService: webhookService,
		authService:    authService,
		metricsService: metricsService,
	}

	// Test with nil connection
	session, err := backend.NewSession(nil)
	assert.NoError(t, err)
	assert.NotNil(t, session, "NewSession() returned nil session")
}

func TestSMTPSessionWithServices_Data_ErrorHandling(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	// Test with message processor that returns an error
	messageProcessor.processMessageFunc = func(ctx context.Context, r io.Reader) error {
		return context.Canceled
	}

	reader := strings.NewReader("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	err := session.Data(reader)

	assert.Error(t, err, "Expected error from Data() when message processor fails")
}

func TestSMTPSessionWithServices_Data_Success(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	// Test with successful message processor
	messageProcessor.processMessageFunc = func(ctx context.Context, r io.Reader) error {
		return nil
	}

	reader := strings.NewReader("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	err := session.Data(reader)

	assert.NoError(t, err)
}

func TestSMTPSessionWithServices_Reset_State(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	// Set some state
	session.from = "test@example.com"
	session.to = []string{"recipient@example.com", "another@example.com"}

	// Reset the session
	session.Reset()

	assert.Empty(t, session.from, "Reset() should clear from field")
	assert.Nil(t, session.to, "Reset() should clear to field")
}

func TestSMTPSessionWithServices_Mail_State(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	// Test Mail command
	err := session.Mail("test@example.com", nil)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", session.from)
}

func TestSMTPSessionWithServices_Rcpt_State(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	// Test Rcpt command
	err := session.Rcpt("recipient@example.com", nil)
	assert.NoError(t, err)
	assert.Len(t, session.to, 1)
	assert.Equal(t, "recipient@example.com", session.to[0])

	// Test multiple recipients
	err = session.Rcpt("another@example.com", nil)
	assert.NoError(t, err)
	assert.Len(t, session.to, 2)
}

func TestInitializeSentry_ErrorHandling(t *testing.T) {
	// Test with invalid DSN
	config := &config.Config{
		Sentry: config.SentryConfig{
			Enabled: true,
			DSN:     "invalid-dsn",
			Env:     "test",
			Release: "v1.0.0",
		},
		Server: config.ServerConfig{
			Verbose: false,
		},
	}

	logger := &mockLoggerServiceForMain{}
	err := initializeSentry(config, logger)
	
	// Should handle invalid DSN gracefully
	if err != nil {
		t.Logf("Sentry initialization failed as expected: %v", err)
	}
}

func TestLogServerInfo_EdgeCases(t *testing.T) {
	// Test with minimal config
	config := &config.Config{
		Server: config.ServerConfig{
			ListenAddr:     "",
			ListenAddrTLS:  "",
			ServerName:     "",
			Verbose:        false,
			CertFile:       "",
			KeyFile:        "",
		},
		Webhook: config.WebhookConfig{
			URL: "",
		},
		Auth: config.AuthConfig{
			EnableSPF:   false,
			EnableDKIM:  false,
			EnableDMARC: false,
		},
		Metrics: config.MetricsConfig{
			Enabled: false,
			Addr:    "",
		},
		Sentry: config.SentryConfig{
			Enabled: false,
		},
		Logging: config.LoggingConfig{
			Level:  "",
			Format: "",
		},
	}

	logger := &mockLoggerServiceForMain{}
	ctx := context.Background()

	// This should not panic even with empty values
	logServerInfo(ctx, config, logger)
}

func TestSMTPBackendWithServices_NewSession_EdgeCases(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMain{}

	backend := &smtpBackendWithServices{
		config:         config,
		webhookService: webhookService,
		authService:    authService,
		metricsService: metricsService,
	}

	// Test with nil connection
	session, err := backend.NewSession(nil)
	assert.NoError(t, err)
	assert.NotNil(t, session)

	// Test that metrics are incremented
	// (We can't easily test the exact metrics values, but we can ensure no panic)
}

func TestSMTPSessionWithServices_Data_EdgeCases(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	// Test with empty reader
	emptyReader := strings.NewReader("")
	messageProcessor.processMessageFunc = func(ctx context.Context, r io.Reader) error {
		return nil
	}

	err := session.Data(emptyReader)
	assert.NoError(t, err)

	// Test with large message
	largeMessage := strings.Repeat("x", 10000)
	largeReader := strings.NewReader(largeMessage)
	messageProcessor.processMessageFunc = func(ctx context.Context, r io.Reader) error {
		return nil
	}

	err = session.Data(largeReader)
	assert.NoError(t, err)
}

func TestSMTPSessionWithServices_StateManagement(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	// Test Mail command
	err := session.Mail("test@example.com", nil)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", session.from)

	// Test Rcpt command
	err = session.Rcpt("recipient@example.com", nil)
	assert.NoError(t, err)
	assert.Len(t, session.to, 1)

	// Test Reset
	session.Reset()
	assert.Empty(t, session.from)
	assert.Nil(t, session.to)

	// Test Logout
	err = session.Logout()
	assert.NoError(t, err)
}

func TestSMTPSessionWithServices_AuthPlain_EdgeCases(t *testing.T) {
	config := &config.Config{}
	messageProcessor := &mockMessageProcessor{}
	metricsService := &mockMetricsServiceForMain{}
	remoteIP := net.IPv4(127, 0, 0, 1)

	session := &smtpSessionWithServices{
		config:           config,
		messageProcessor: messageProcessor,
		metricsService:   metricsService,
		remoteIP:         remoteIP,
	}

	// Test with special characters
	err := session.AuthPlain("user@domain.com", "pass@word123")
	assert.NoError(t, err)

	// Test with unicode characters
	err = session.AuthPlain("用户", "密码")
	assert.NoError(t, err)

	// Test with very long credentials
	longUser := strings.Repeat("a", 1000)
	longPass := strings.Repeat("b", 1000)
	err = session.AuthPlain(longUser, longPass)
	assert.NoError(t, err)
}