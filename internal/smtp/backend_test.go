package smtp

import (
	"context"
	"fmt"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"inboundparse/internal/processor"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/getsentry/sentry-go"
	"github.com/mnako/letters"
	"github.com/rs/zerolog"
)

// Helper function to create a mock message processor
func createMockMessageProcessor() *processor.MessageProcessor {
	// Create a real MessageProcessor with mock dependencies
	config := processor.ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	return processor.NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)
}

// Mock implementations for testing
type mockAuthChecker struct{}

func (m *mockAuthChecker) CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.SPFResult, error) {
	return nil, nil
}

func (m *mockAuthChecker) CheckDKIM(ctx context.Context, rawMessage string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DKIMResult, error) {
	return nil, nil
}

func (m *mockAuthChecker) CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DMARCResult, error) {
	return nil, nil
}

type mockWebhookSender struct {
	shouldError bool
}

func (m *mockWebhookSender) SendWebhook(ctx context.Context, payload interface{}) error {
	if m.shouldError {
		return fmt.Errorf("mock webhook error")
	}
	return nil
}

type mockSentryClient struct{}

func (m *mockSentryClient) Init(config observability.SentryConfig) error        { return nil }
func (m *mockSentryClient) CaptureError(err error, tags map[string]interface{}) {}
func (m *mockSentryClient) CaptureMessage(message string, level sentry.Level, tags map[string]interface{}) {
}
func (m *mockSentryClient) Flush()             {}
func (m *mockSentryClient) RecoverWithSentry() {}

type mockMetricsCollector struct{}

func (m *mockMetricsCollector) TrackConnection() func()                                    { return func() {} }
func (m *mockMetricsCollector) TrackSession() func()                                       { return func() {} }
func (m *mockMetricsCollector) TrackMessage(size int64, success bool)                      {}
func (m *mockMetricsCollector) TrackSPFResult(result string)                               {}
func (m *mockMetricsCollector) TrackDKIMResult(valid bool)                                 {}
func (m *mockMetricsCollector) TrackDMARCResult(result, policy string)                     {}
func (m *mockMetricsCollector) TrackWebhookRequest(statusCode int, duration time.Duration) {}
func (m *mockMetricsCollector) TrackWebhookRequestSize(requestSize, responseSize int64)    {}
func (m *mockMetricsCollector) TrackWebhookRetry(success bool)                             {}
func (m *mockMetricsCollector) TrackWebhookError(errorType string)                         {}
func (m *mockMetricsCollector) TrackSPFDuration(duration time.Duration)                    {}
func (m *mockMetricsCollector) TrackDKIMDuration(duration time.Duration)                   {}
func (m *mockMetricsCollector) TrackDMARCDuration(duration time.Duration)                  {}
func (m *mockMetricsCollector) TrackSPFResultByDomain(domain, result string)               {}
func (m *mockMetricsCollector) TrackDKIMResultByDomain(domain, result string)              {}
func (m *mockMetricsCollector) TrackDMARCResultByDomain(domain, result string)             {}
func (m *mockMetricsCollector) TrackAuthError(checkType, errorType string)                 {}

type mockLogger struct{}

func (m *mockLogger) Debug() *zerolog.Event { return nil }
func (m *mockLogger) Info() *zerolog.Event  { return nil }
func (m *mockLogger) Warn() *zerolog.Event  { return nil }
func (m *mockLogger) Error() *zerolog.Event { return nil }
func (m *mockLogger) Fatal() *zerolog.Event { return nil }
func (m *mockLogger) With() zerolog.Context { return zerolog.New(nil).With() }

type mockMessageProcessor struct {
	shouldError bool
}

func (m *mockMessageProcessor) ProcessMessage(ctx context.Context, r io.Reader, from string, to []string, sessionID string, remoteIP net.IP) error {
	if m.shouldError {
		return fmt.Errorf("mock processing error")
	}
	return nil
}

func TestNewBackend(t *testing.T) {
	config := BackendConfig{
		MaxRecipients: 100,
	}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)

	if backend == nil {
		t.Fatal("Expected non-nil backend")
	}
	if backend.config != config {
		t.Error("Expected config to be set")
	}
	if backend.messageProcessor != messageProcessor {
		t.Error("Expected messageProcessor to be set")
	}
	if backend.metrics != metrics {
		t.Error("Expected metrics to be set")
	}
	if backend.logger != logger {
		t.Error("Expected logger to be set")
	}
}

func TestBackend_NewSession(t *testing.T) {
	config := BackendConfig{
		MaxRecipients: 100,
	}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)

	// Test with nil connection
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if session == nil {
		t.Fatal("Expected non-nil session")
	}

	// Verify it's the correct type
	_, ok := session.(*Session)
	if !ok {
		t.Error("Expected session to be of type *Session")
	}
}

func TestBackend_NewSession_WithConnection(t *testing.T) {
	config := BackendConfig{
		MaxRecipients: 100,
	}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)

	// Create a mock connection
	smtpConn := &smtp.Conn{}

	session, err := backend.NewSession(smtpConn)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if session == nil {
		t.Fatal("Expected non-nil session")
	}
}

func TestBackendConfig_DefaultValues(t *testing.T) {
	config := BackendConfig{}

	if config.MaxRecipients != 0 {
		t.Errorf("Expected MaxRecipients 0, got %d", config.MaxRecipients)
	}
}

func TestBackendConfig_WithValues(t *testing.T) {
	config := BackendConfig{
		MaxRecipients: 50,
	}

	if config.MaxRecipients != 50 {
		t.Errorf("Expected MaxRecipients 50, got %d", config.MaxRecipients)
	}
}

// Mock connection for testing
type mockConn struct{}

func (m *mockConn) RemoteAddr() net.Addr {
	return &mockAddr{}
}

func (m *mockConn) LocalAddr() net.Addr {
	return &mockAddr{}
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type mockAddr struct{}

func (m *mockAddr) Network() string {
	return "tcp"
}

func (m *mockAddr) String() string {
	return "127.0.0.1:12345"
}

func TestSession_AuthPlain(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)

	// Test AUTH PLAIN
	sessionImpl := session.(*Session)
	err := sessionImpl.AuthPlain("user", "pass")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_Mail(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)

	// Test MAIL command
	sessionImpl := session.(*Session)
	err := sessionImpl.Mail("test@example.com", &smtp.MailOptions{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_Rcpt(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)

	// Test RCPT command
	sessionImpl := session.(*Session)
	err := sessionImpl.Rcpt("recipient@example.com", &smtp.RcptOptions{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_Rcpt_MaxRecipients(t *testing.T) {
	config := BackendConfig{MaxRecipients: 2}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Add recipients up to the limit
	err := sessionImpl.Rcpt("recipient1@example.com", &smtp.RcptOptions{})
	if err != nil {
		t.Errorf("Expected no error for first recipient, got %v", err)
	}

	err = sessionImpl.Rcpt("recipient2@example.com", &smtp.RcptOptions{})
	if err != nil {
		t.Errorf("Expected no error for second recipient, got %v", err)
	}

	// This should fail
	err = sessionImpl.Rcpt("recipient3@example.com", &smtp.RcptOptions{})
	if err == nil {
		t.Error("Expected error for exceeding max recipients")
	}
}

func TestSession_Data(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Set up session state
	sessionImpl.Mail("test@example.com", &smtp.MailOptions{})
	sessionImpl.Rcpt("recipient@example.com", &smtp.RcptOptions{})

	// Test DATA command
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)

	err := sessionImpl.Data(reader)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_Data_NoRecipients(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Set up session state without recipients
	sessionImpl.Mail("test@example.com", &smtp.MailOptions{})

	// Test DATA command without recipients
	message := "From: test@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)

	err := sessionImpl.Data(reader)
	if err == nil {
		t.Error("Expected error for no recipients")
	}
}

func TestSession_Reset(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Set up session state
	sessionImpl.Mail("test@example.com", &smtp.MailOptions{})
	sessionImpl.Rcpt("recipient@example.com", &smtp.RcptOptions{})

	// Reset session
	sessionImpl.Reset()

	// Verify state is reset
	if sessionImpl.from != "" {
		t.Error("Expected from to be empty after reset")
	}
	if sessionImpl.to != nil {
		t.Error("Expected to to be nil after reset")
	}
}

func TestSession_Logout(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Test LOGOUT command
	err := sessionImpl.Logout()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_ProcessMessage_Error(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	// Create a real message processor with a mock that returns an error
	processorConfig := processor.ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{}
	webhookSender := &mockWebhookSender{shouldError: true}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	messageProcessor := processor.NewMessageProcessor(processorConfig, authChecker, webhookSender, metrics, sentry, logger)

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Set up session state
	sessionImpl.Mail("test@example.com", &smtp.MailOptions{})
	sessionImpl.Rcpt("recipient@example.com", &smtp.RcptOptions{})

	// Test DATA command with processing error
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)

	err := sessionImpl.Data(reader)
	if err == nil {
		t.Error("Expected error from message processing")
	}
}

func TestBackend_NewSession_WithRemoteAddress(t *testing.T) {
	config := BackendConfig{
		MaxRecipients: 100,
	}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)

	// Create a mock connection with remote address
	smtpConn := &smtp.Conn{}

	session, err := backend.NewSession(smtpConn)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if session == nil {
		t.Fatal("Expected non-nil session")
	}

	// Verify it's the correct type
	_, ok := session.(*Session)
	if !ok {
		t.Error("Expected session to be of type *Session")
	}
}

func TestBackend_NewSession_WithUnknownRemoteAddress(t *testing.T) {
	config := BackendConfig{
		MaxRecipients: 100,
	}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)

	// Create a mock connection with unknown remote address
	smtpConn := &smtp.Conn{}

	session, err := backend.NewSession(smtpConn)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if session == nil {
		t.Fatal("Expected non-nil session")
	}

	// Verify it's the correct type
	_, ok := session.(*Session)
	if !ok {
		t.Error("Expected session to be of type *Session")
	}
}

func TestSession_WithConnection(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)

	// Create a mock connection
	smtpConn := &smtp.Conn{}

	session, err := backend.NewSession(smtpConn)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if session == nil {
		t.Fatal("Expected non-nil session")
	}

	// Test session methods with connection
	sessionImpl := session.(*Session)

	// Test AUTH PLAIN
	err = sessionImpl.AuthPlain("user", "pass")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test MAIL command
	err = sessionImpl.Mail("test@example.com", &smtp.MailOptions{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test RCPT command
	err = sessionImpl.Rcpt("recipient@example.com", &smtp.RcptOptions{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test DATA command
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	err = sessionImpl.Data(reader)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test RESET command
	sessionImpl.Reset()

	// Test LOGOUT command
	err = sessionImpl.Logout()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_WithNilConnection(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)

	// Test with nil connection
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if session == nil {
		t.Fatal("Expected non-nil session")
	}

	// Test session methods with nil connection
	sessionImpl := session.(*Session)

	// Test AUTH PLAIN
	err = sessionImpl.AuthPlain("user", "pass")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test MAIL command
	err = sessionImpl.Mail("test@example.com", &smtp.MailOptions{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test RCPT command
	err = sessionImpl.Rcpt("recipient@example.com", &smtp.RcptOptions{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test DATA command
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	err = sessionImpl.Data(reader)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test RESET command
	sessionImpl.Reset()

	// Test LOGOUT command
	err = sessionImpl.Logout()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_WithEmptyFrom(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Test MAIL command with empty from
	err := sessionImpl.Mail("", &smtp.MailOptions{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_WithEmptyTo(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Test RCPT command with empty to
	err := sessionImpl.Rcpt("", &smtp.RcptOptions{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_WithEmptyMessage(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Set up session state
	sessionImpl.Mail("test@example.com", &smtp.MailOptions{})
	sessionImpl.Rcpt("recipient@example.com", &smtp.RcptOptions{})

	// Test DATA command with empty message
	message := ""
	reader := strings.NewReader(message)

	err := sessionImpl.Data(reader)
	// Empty messages should fail to parse
	if err == nil {
		t.Error("Expected error for empty message")
	}
}

func TestSession_WithInvalidMessage(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Set up session state
	sessionImpl.Mail("test@example.com", &smtp.MailOptions{})
	sessionImpl.Rcpt("recipient@example.com", &smtp.RcptOptions{})

	// Test DATA command with invalid message
	message := "invalid message content"
	reader := strings.NewReader(message)

	err := sessionImpl.Data(reader)
	// Invalid messages should fail to parse
	if err == nil {
		t.Error("Expected error for invalid message")
	}
}

func TestSession_WithLargeMessage(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Set up session state
	sessionImpl.Mail("test@example.com", &smtp.MailOptions{})
	sessionImpl.Rcpt("recipient@example.com", &smtp.RcptOptions{})

	// Test DATA command with large message
	largeContent := strings.Repeat("x", 10000)
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\n" + largeContent
	reader := strings.NewReader(message)

	err := sessionImpl.Data(reader)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_WithMultipleRecipients(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Set up session state
	sessionImpl.Mail("test@example.com", &smtp.MailOptions{})
	sessionImpl.Rcpt("recipient1@example.com", &smtp.RcptOptions{})
	sessionImpl.Rcpt("recipient2@example.com", &smtp.RcptOptions{})
	sessionImpl.Rcpt("recipient3@example.com", &smtp.RcptOptions{})

	// Test DATA command with multiple recipients
	message := "From: test@example.com\r\nTo: recipient1@example.com, recipient2@example.com, recipient3@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)

	err := sessionImpl.Data(reader)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSession_WithSpecialCharacters(t *testing.T) {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	backend := NewBackend(config, messageProcessor, metrics, logger)
	session, _ := backend.NewSession(nil)
	sessionImpl := session.(*Session)

	// Set up session state with special characters
	sessionImpl.Mail("test+tag@example.com", &smtp.MailOptions{})
	sessionImpl.Rcpt("recipient+tag@example.com", &smtp.RcptOptions{})

	// Test DATA command with special characters
	message := "From: test+tag@example.com\r\nTo: recipient+tag@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)

	err := sessionImpl.Data(reader)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// Mock connection with unknown remote address
type mockConnWithUnknownAddr struct{}

func (m *mockConnWithUnknownAddr) RemoteAddr() net.Addr {
	return &mockUnknownAddr{}
}

func (m *mockConnWithUnknownAddr) LocalAddr() net.Addr {
	return &mockAddr{}
}

func (m *mockConnWithUnknownAddr) Close() error {
	return nil
}

func (m *mockConnWithUnknownAddr) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (m *mockConnWithUnknownAddr) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConnWithUnknownAddr) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConnWithUnknownAddr) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConnWithUnknownAddr) SetWriteDeadline(t time.Time) error {
	return nil
}

type mockUnknownAddr struct{}

func (m *mockUnknownAddr) Network() string {
	return "unknown"
}

func (m *mockUnknownAddr) String() string {
	return "unknown"
}
