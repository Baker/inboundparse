package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/inboundparse/inboundparse/internal/config"
)

// mockMetricsService is a mock implementation of MetricsService
type mockMetricsService struct {
	incrementActiveSessionsCalled bool
	decrementActiveSessionsCalled bool
	incrementSMTPMessagesCalled   bool
	incrementMessagesFailedCalled bool
}

func (m *mockMetricsService) IncrementSMTPConnections()                       {}
func (m *mockMetricsService) IncrementActiveConnections()                     {}
func (m *mockMetricsService) DecrementActiveConnections()                     {}
func (m *mockMetricsService) RecordConnectionDuration(duration time.Duration) {}
func (m *mockMetricsService) IncrementSMTPMessages() {
	m.incrementSMTPMessagesCalled = true
}
func (m *mockMetricsService) RecordMessageSize(size int64) {}
func (m *mockMetricsService) IncrementMessagesProcessed()  {}
func (m *mockMetricsService) IncrementMessagesFailed() {
	m.incrementMessagesFailedCalled = true
}
func (m *mockMetricsService) RecordMessageParsingDuration(duration time.Duration) {}
func (m *mockMetricsService) IncrementMessageParsingFailed()                      {}
func (m *mockMetricsService) IncrementWebhookRequests()                           {}
func (m *mockMetricsService) RecordWebhookDuration(duration time.Duration)        {}
func (m *mockMetricsService) IncrementWebhookFailed()                             {}
func (m *mockMetricsService) IncrementAuthChecks()                                {}
func (m *mockMetricsService) IncrementSPFChecks()                                 {}
func (m *mockMetricsService) IncrementDKIMChecks()                                {}
func (m *mockMetricsService) IncrementDMARCChecks()                               {}
func (m *mockMetricsService) IncrementAuthChecksFailed()                          {}
func (m *mockMetricsService) RecordSPFResult(result string)                       {}
func (m *mockMetricsService) RecordDKIMResult(result string)                      {}
func (m *mockMetricsService) RecordDMARCResult(result string)                     {}
func (m *mockMetricsService) RecordDMARCPolicy(policy string)                     {}
func (m *mockMetricsService) IncrementActiveSessions() {
	m.incrementActiveSessionsCalled = true
}

func (m *mockMetricsService) DecrementActiveSessions() {
	m.decrementActiveSessionsCalled = true
}
func (m *mockMetricsService) Close() error { return nil }

func TestNewSMTPBackend(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsService{}

	backend := NewSMTPBackend(config, webhookService, authService, metricsService)
	if backend == nil {
		t.Error("NewSMTPBackend() returned nil")
	}
}

func TestSMTPBackend_NewSession(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsService{}

	backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)

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

func TestSMTPBackend_NewSession_IncrementsMetrics(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsService{}

	backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)

	_, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	if !metricsService.incrementActiveSessionsCalled {
		t.Error("Expected IncrementActiveSessions to be called")
	}
}

func TestSMTPSession_AuthPlain(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsService{}

	backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	smtpSession := session.(*smtpSession)

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
			err := smtpSession.AuthPlain(tt.username, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthPlain() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSMTPSession_Mail(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsService{}

	backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	smtpSession := session.(*smtpSession)

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
			err := smtpSession.Mail(tt.from, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Mail() error = %v, wantErr %v", err, tt.wantErr)
			}
			if smtpSession.from != tt.from {
				t.Errorf("Mail() from = %v, want %v", smtpSession.from, tt.from)
			}
		})
	}
}

func TestSMTPSession_Rcpt(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsService{}

	backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	smtpSession := session.(*smtpSession)

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
			err := smtpSession.Rcpt(tt.to, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Rcpt() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(smtpSession.to) == 0 || smtpSession.to[len(smtpSession.to)-1] != tt.to {
				t.Errorf("Rcpt() to = %v, want %v", smtpSession.to, []string{tt.to})
			}
		})
	}
}

func TestSMTPSession_Data(t *testing.T) {
	tests := []struct {
		name              string
		messageData       string
		webhookError      error
		wantErr           bool
		expectMetricsCall bool
	}{
		{
			name:              "successful message processing",
			messageData:       "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message",
			webhookError:      nil,
			wantErr:           false,
			expectMetricsCall: true,
		},
		{
			name:              "message processing error",
			messageData:       "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message",
			webhookError:      context.Canceled,
			wantErr:           true,
			expectMetricsCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &config.Config{}
			webhookService := &mockWebhookService{
				sendWebhookFunc: func(ctx context.Context, payload *WebhookPayload) error {
					return tt.webhookError
				},
			}
			authService := &mockAuthService{}
			metricsService := &mockMetricsService{}

			backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)
			session, err := backend.NewSession(nil)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}

			smtpSession := session.(*smtpSession)

			reader := strings.NewReader(tt.messageData)
			err = smtpSession.Data(reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("Data() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.expectMetricsCall && !metricsService.incrementSMTPMessagesCalled {
				t.Error("Expected IncrementSMTPMessages to be called")
			}

			if !tt.expectMetricsCall && tt.webhookError != nil && !metricsService.incrementMessagesFailedCalled {
				t.Error("Expected IncrementMessagesFailed to be called")
			}
		})
	}
}

func TestSMTPSession_Reset(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsService{}

	backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	smtpSession := session.(*smtpSession)

	// Set some state
	smtpSession.from = "test@example.com"
	smtpSession.to = []string{"recipient@example.com"}

	// Reset the session
	smtpSession.Reset()

	if smtpSession.from != "" {
		t.Errorf("Reset() from = %v, want empty string", smtpSession.from)
	}
	if smtpSession.to != nil {
		t.Errorf("Reset() to = %v, want nil", smtpSession.to)
	}
}

func TestSMTPSession_Logout(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsService{}

	backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	smtpSession := session.(*smtpSession)

	err = smtpSession.Logout()
	if err != nil {
		t.Errorf("Logout() error = %v", err)
	}

	if !metricsService.decrementActiveSessionsCalled {
		t.Error("Expected DecrementActiveSessions to be called")
	}
}

func TestSMTPBackend_NewSession_WithConnection(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsService{}

	backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)

	// Test with a mock connection that has a remote address
	tests := []struct {
		name        string
		conn        *smtp.Conn
		expectError bool
	}{
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

func TestSMTPSession_Data_WithMetrics(t *testing.T) {
	tests := []struct {
		name                 string
		messageData          string
		webhookError         error
		wantErr              bool
		expectSuccessMetrics bool
		expectFailureMetrics bool
	}{
		{
			name:                 "successful message processing",
			messageData:          "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message",
			webhookError:         nil,
			wantErr:              false,
			expectSuccessMetrics: true,
			expectFailureMetrics: false,
		},
		{
			name:                 "message processing error",
			messageData:          "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message",
			webhookError:         context.Canceled,
			wantErr:              true,
			expectSuccessMetrics: false,
			expectFailureMetrics: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &config.Config{}
			webhookService := &mockWebhookService{
				sendWebhookFunc: func(ctx context.Context, payload *WebhookPayload) error {
					return tt.webhookError
				},
			}
			authService := &mockAuthService{}
			metricsService := &mockMetricsService{
				incrementSMTPMessagesCalled:   false,
				incrementMessagesFailedCalled: false,
			}

			backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)
			session, err := backend.NewSession(nil)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}

			smtpSession := session.(*smtpSession)

			reader := strings.NewReader(tt.messageData)
			err = smtpSession.Data(reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("Data() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.expectSuccessMetrics && !metricsService.incrementSMTPMessagesCalled {
				t.Error("Expected IncrementSMTPMessages to be called")
			}

			if tt.expectFailureMetrics && !metricsService.incrementMessagesFailedCalled {
				t.Error("Expected IncrementMessagesFailed to be called")
			}
		})
	}
}

func TestSMTPSession_Logout_WithMetrics(t *testing.T) {
	config := &config.Config{}
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsService{
		decrementActiveSessionsCalled: false,
	}

	backend := NewSMTPBackend(config, webhookService, authService, metricsService).(*smtpBackend)
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	smtpSession := session.(*smtpSession)

	err = smtpSession.Logout()
	if err != nil {
		t.Errorf("Logout() error = %v", err)
	}

	if !metricsService.decrementActiveSessionsCalled {
		t.Error("Expected DecrementActiveSessions to be called")
	}
}
