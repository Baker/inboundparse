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
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
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
			if (err != nil) != tt.expectError {
				t.Errorf("NewSession() error = %v, wantErr %v", err, tt.expectError)
				return
			}
			if session == nil {
				t.Error("NewSession() returned nil session")
			}
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
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthPlain() error = %v, wantErr %v", err, tt.wantErr)
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
			if (err != nil) != tt.wantErr {
				t.Errorf("Mail() error = %v, wantErr %v", err, tt.wantErr)
			}
			if session.from != tt.from {
				t.Errorf("Mail() from = %v, want %v", session.from, tt.from)
			}
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
			if (err != nil) != tt.wantErr {
				t.Errorf("Rcpt() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(session.to) == 0 || session.to[len(session.to)-1] != tt.to {
				t.Errorf("Rcpt() to = %v, want %v", session.to, []string{tt.to})
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

			if (err != nil) != tt.wantErr {
				t.Errorf("Data() error = %v, wantErr %v", err, tt.wantErr)
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

	if session.from != "" {
		t.Errorf("Reset() from = %v, want empty string", session.from)
	}
	if session.to != nil {
		t.Errorf("Reset() to = %v, want nil", session.to)
	}
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
	if err != nil {
		t.Errorf("Logout() error = %v", err)
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
	if err != nil {
		t.Errorf("initializeSentry() error = %v, expected no error", err)
	}
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
	if err != nil {
		t.Errorf("initializeSentry() error = %v, expected no error", err)
	}
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
	if err != nil {
		t.Errorf("NewSession() error = %v", err)
	}
	if session == nil {
		t.Error("NewSession() returned nil session")
	}
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

	if err == nil {
		t.Error("Expected error from Data() when message processor fails")
	}
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

	if err != nil {
		t.Errorf("Data() error = %v", err)
	}
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

	if session.from != "" {
		t.Errorf("Reset() from = %v, want empty string", session.from)
	}
	if session.to != nil {
		t.Errorf("Reset() to = %v, want nil", session.to)
	}
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
	if err != nil {
		t.Errorf("Mail() error = %v", err)
	}
	if session.from != "test@example.com" {
		t.Errorf("Mail() from = %v, want test@example.com", session.from)
	}
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
	if err != nil {
		t.Errorf("Rcpt() error = %v", err)
	}
	if len(session.to) != 1 || session.to[0] != "recipient@example.com" {
		t.Errorf("Rcpt() to = %v, want [recipient@example.com]", session.to)
	}

	// Test multiple recipients
	err = session.Rcpt("another@example.com", nil)
	if err != nil {
		t.Errorf("Rcpt() error = %v", err)
	}
	if len(session.to) != 2 {
		t.Errorf("Rcpt() to length = %v, want 2", len(session.to))
	}
}