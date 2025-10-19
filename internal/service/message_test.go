package service

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockMetricsServiceForMessage is a mock implementation of MetricsService for message processor tests
type mockMetricsServiceForMessage struct {
	recordMessageSizeCalled             bool
	incrementMessageParsingFailedCalled bool
	recordMessageParsingDurationCalled  bool
	incrementWebhookFailedCalled        bool
	incrementWebhookRequestsCalled      bool
	recordWebhookDurationCalled         bool
	incrementMessagesProcessedCalled    bool
}

func (m *mockMetricsServiceForMessage) IncrementSMTPConnections()                       {}
func (m *mockMetricsServiceForMessage) IncrementActiveConnections()                     {}
func (m *mockMetricsServiceForMessage) DecrementActiveConnections()                     {}
func (m *mockMetricsServiceForMessage) RecordConnectionDuration(duration time.Duration) {}
func (m *mockMetricsServiceForMessage) IncrementSMTPMessages()                          {}
func (m *mockMetricsServiceForMessage) RecordMessageSize(size int64) {
	m.recordMessageSizeCalled = true
}

func (m *mockMetricsServiceForMessage) IncrementMessagesProcessed() {
	m.incrementMessagesProcessedCalled = true
}
func (m *mockMetricsServiceForMessage) IncrementMessagesFailed() {}
func (m *mockMetricsServiceForMessage) RecordMessageParsingDuration(duration time.Duration) {
	m.recordMessageParsingDurationCalled = true
}

func (m *mockMetricsServiceForMessage) IncrementMessageParsingFailed() {
	m.incrementMessageParsingFailedCalled = true
}

func (m *mockMetricsServiceForMessage) IncrementWebhookRequests() {
	m.incrementWebhookRequestsCalled = true
}

func (m *mockMetricsServiceForMessage) RecordWebhookDuration(duration time.Duration) {
	m.recordWebhookDurationCalled = true
}

func (m *mockMetricsServiceForMessage) IncrementWebhookFailed() {
	m.incrementWebhookFailedCalled = true
}
func (m *mockMetricsServiceForMessage) IncrementAuthChecks()            {}
func (m *mockMetricsServiceForMessage) IncrementSPFChecks()             {}
func (m *mockMetricsServiceForMessage) IncrementDKIMChecks()            {}
func (m *mockMetricsServiceForMessage) IncrementDMARCChecks()           {}
func (m *mockMetricsServiceForMessage) IncrementAuthChecksFailed()      {}
func (m *mockMetricsServiceForMessage) RecordSPFResult(result string)   {}
func (m *mockMetricsServiceForMessage) RecordDKIMResult(result string)  {}
func (m *mockMetricsServiceForMessage) RecordDMARCResult(result string) {}
func (m *mockMetricsServiceForMessage) RecordDMARCPolicy(policy string) {}
func (m *mockMetricsServiceForMessage) IncrementActiveSessions()        {}
func (m *mockMetricsServiceForMessage) DecrementActiveSessions()        {}
func (m *mockMetricsServiceForMessage) Close() error                    { return nil }

func TestNewMessageProcessor(t *testing.T) {
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger)
	if processor == nil {
		t.Error("NewMessageProcessor() returned nil")
	}
}

func TestMessageProcessor_ProcessMessage_Success(t *testing.T) {
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger).(*messageProcessor)

	// Valid email message
	messageData := `From: test@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <test@example.com>

This is a test email body.`

	reader := strings.NewReader(messageData)
	err := processor.ProcessMessage(context.Background(), reader)
	if err != nil {
		t.Errorf("ProcessMessage() error = %v", err)
	}

	// Check that metrics were recorded
	if !metricsService.recordMessageSizeCalled {
		t.Error("Expected RecordMessageSize to be called")
	}
	if !metricsService.recordMessageParsingDurationCalled {
		t.Error("Expected RecordMessageParsingDuration to be called")
	}
	if !metricsService.incrementWebhookRequestsCalled {
		t.Error("Expected IncrementWebhookRequests to be called")
	}
	if !metricsService.recordWebhookDurationCalled {
		t.Error("Expected RecordWebhookDuration to be called")
	}
	if !metricsService.incrementMessagesProcessedCalled {
		t.Error("Expected IncrementMessagesProcessed to be called")
	}
}

func TestMessageProcessor_ProcessMessage_ReadError(t *testing.T) {
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger).(*messageProcessor)

	// Create a reader that will return an error
	errorReader := &errorReader{err: errors.New("read error")}

	err := processor.ProcessMessage(context.Background(), errorReader)

	if err == nil {
		t.Error("Expected ProcessMessage to return an error")
	}

	if !metricsService.incrementMessageParsingFailedCalled {
		t.Error("Expected IncrementMessageParsingFailed to be called")
	}
}

func TestMessageProcessor_ProcessMessage_ParseError(t *testing.T) {
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger).(*messageProcessor)

	// Invalid email message
	messageData := `This is not a valid email message`

	reader := strings.NewReader(messageData)
	err := processor.ProcessMessage(context.Background(), reader)

	if err == nil {
		t.Error("Expected ProcessMessage to return an error")
	}

	if !metricsService.incrementMessageParsingFailedCalled {
		t.Error("Expected IncrementMessageParsingFailed to be called")
	}
}

func TestMessageProcessor_ProcessMessage_AuthError(t *testing.T) {
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{
		performAuthChecksFunc: func(ctx context.Context, message []byte, remoteIP net.IP) (*AuthResult, error) {
			return nil, errors.New("auth error")
		},
	}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger).(*messageProcessor)

	// Valid email message
	messageData := `From: test@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <test@example.com>

This is a test email body.`

	reader := strings.NewReader(messageData)
	err := processor.ProcessMessage(context.Background(), reader)
	// Auth errors should not cause the message processing to fail
	if err != nil {
		t.Errorf("ProcessMessage() error = %v, expected no error for auth failure", err)
	}
}

func TestMessageProcessor_ProcessMessage_WebhookError(t *testing.T) {
	webhookService := &mockWebhookService{
		sendWebhookFunc: func(ctx context.Context, payload *WebhookPayload) error {
			return errors.New("webhook error")
		},
	}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger).(*messageProcessor)

	// Valid email message
	messageData := `From: test@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <test@example.com>

This is a test email body.`

	reader := strings.NewReader(messageData)
	err := processor.ProcessMessage(context.Background(), reader)

	if err == nil {
		t.Error("Expected ProcessMessage to return an error")
	}

	if !metricsService.incrementWebhookFailedCalled {
		t.Error("Expected IncrementWebhookFailed to be called")
	}
}

func TestMessageProcessor_ProcessMessage_NoServices(t *testing.T) {
	// Test with nil services
	processor := NewMessageProcessor(nil, nil, nil, net.IPv4(127, 0, 0, 1), nil).(*messageProcessor)

	// Valid email message
	messageData := `From: test@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <test@example.com>

This is a test email body.`

	reader := strings.NewReader(messageData)
	err := processor.ProcessMessage(context.Background(), reader)
	// Should still work without services
	if err != nil {
		t.Errorf("ProcessMessage() error = %v", err)
	}
}

func TestMessageProcessor_ExtractHeaders(t *testing.T) {
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger).(*messageProcessor)

	// Test with email that has various headers
	messageData := `From: test@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <test@example.com>
Reply-To: noreply@example.com

This is a test email body.`

	reader := strings.NewReader(messageData)
	err := processor.ProcessMessage(context.Background(), reader)
	if err != nil {
		t.Errorf("ProcessMessage() error = %v", err)
	}
}

// errorReader is a helper for testing read errors
type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func TestMessageProcessor_ProcessMessage_WithAttachments(t *testing.T) {
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger).(*messageProcessor)

	// Set up webhook service to capture payload
	var capturedPayload *WebhookPayload
	webhookService.sendWebhookFunc = func(ctx context.Context, payload *WebhookPayload) error {
		capturedPayload = payload
		return nil
	}

	// Create message with attachments
	messageData := `From: test@example.com
To: recipient@example.com
Subject: Test with attachments
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

This is the message body.

--boundary123
Content-Type: text/plain
Content-Disposition: attachment; filename="test.txt"

This is an attachment.

--boundary123--
`
	reader := strings.NewReader(messageData)

	ctx := context.Background()
	err := processor.ProcessMessage(ctx, reader)

	assert.NoError(t, err)
	assert.NotNil(t, capturedPayload)
	assert.Equal(t, "test@example.com", capturedPayload.From[0].Address)
	assert.Equal(t, "recipient@example.com", capturedPayload.To[0].Address)
	assert.Equal(t, "Test with attachments", capturedPayload.Subject)
}

func TestMessageProcessor_ProcessMessage_WithHTMLContent(t *testing.T) {
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger).(*messageProcessor)

	// Set up webhook service to capture payload
	var capturedPayload *WebhookPayload
	webhookService.sendWebhookFunc = func(ctx context.Context, payload *WebhookPayload) error {
		capturedPayload = payload
		return nil
	}

	// Create HTML message
	messageData := `From: test@example.com
To: recipient@example.com
Subject: HTML Test
Content-Type: text/html

<html>
<body>
<h1>Hello World</h1>
<p>This is an HTML email.</p>
</body>
</html>
`
	reader := strings.NewReader(messageData)

	ctx := context.Background()
	err := processor.ProcessMessage(ctx, reader)

	assert.NoError(t, err)
	assert.NotNil(t, capturedPayload)
	assert.Equal(t, "test@example.com", capturedPayload.From[0].Address)
	assert.Equal(t, "recipient@example.com", capturedPayload.To[0].Address)
	assert.Equal(t, "HTML Test", capturedPayload.Subject)
}

func TestMessageProcessor_ProcessMessage_WithEmptyMessage(t *testing.T) {
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger).(*messageProcessor)

	// Create empty message
	messageData := ""
	reader := strings.NewReader(messageData)

	ctx := context.Background()
	err := processor.ProcessMessage(ctx, reader)

	// Should return an error for empty message
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse email")
}

func TestMessageProcessor_ProcessMessage_WithInvalidMessage(t *testing.T) {
	webhookService := &mockWebhookService{}
	authService := &mockAuthService{}
	metricsService := &mockMetricsServiceForMessage{}
	remoteIP := net.IPv4(127, 0, 0, 1)
	logger := &mockLoggerService{}

	processor := NewMessageProcessor(webhookService, authService, metricsService, remoteIP, logger).(*messageProcessor)

	// Create invalid message
	messageData := "This is not a valid email message"
	reader := strings.NewReader(messageData)

	ctx := context.Background()
	err := processor.ProcessMessage(ctx, reader)

	// Should return an error for invalid message
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse email")
}
