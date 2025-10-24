package processor

import (
	"context"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/mnako/letters"
	"github.com/rs/zerolog"
)

// Mock implementations for testing
type mockAuthChecker struct {
	spfResult   *domain.SPFResult
	dkimResult  *domain.DKIMResult
	dmarcResult *domain.DMARCResult
	spfErr      error
	dkimErr     error
	dmarcErr    error
}

func (m *mockAuthChecker) CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string) (*domain.SPFResult, error) {
	return m.spfResult, m.spfErr
}

func (m *mockAuthChecker) CheckDKIM(ctx context.Context, rawMessage string) (*domain.DKIMResult, error) {
	return m.dkimResult, m.dkimErr
}

func (m *mockAuthChecker) CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult) (*domain.DMARCResult, error) {
	return m.dmarcResult, m.dmarcErr
}

type mockWebhookSender struct {
	err error
}

func (m *mockWebhookSender) SendWebhook(ctx context.Context, payload interface{}) error {
	return m.err
}

type mockMetricsCollector struct{}

func (m *mockMetricsCollector) TrackConnection() func()                                    { return func() {} }
func (m *mockMetricsCollector) TrackSession() func()                                       { return func() {} }
func (m *mockMetricsCollector) TrackMessage(size int64, success bool)                      {}
func (m *mockMetricsCollector) TrackSPFResult(result string)                               {}
func (m *mockMetricsCollector) TrackDKIMResult(valid bool)                                 {}
func (m *mockMetricsCollector) TrackDMARCResult(result, policy string)                     {}
func (m *mockMetricsCollector) TrackWebhookRequest(statusCode int, duration time.Duration) {}

type mockSentryClient struct{}

func (m *mockSentryClient) Init(config observability.SentryConfig) error           { return nil }
func (m *mockSentryClient) CaptureError(err error, context map[string]interface{}) {}
func (m *mockSentryClient) CaptureMessage(message string, level sentry.Level, context map[string]interface{}) {
}
func (m *mockSentryClient) Flush()             {}
func (m *mockSentryClient) RecoverWithSentry() {}

type mockLogger struct{}

func (m *mockLogger) Debug() *zerolog.Event { return nil }
func (m *mockLogger) Info() *zerolog.Event  { return nil }
func (m *mockLogger) Warn() *zerolog.Event  { return nil }
func (m *mockLogger) Error() *zerolog.Event { return nil }
func (m *mockLogger) Fatal() *zerolog.Event { return nil }
func (m *mockLogger) With() zerolog.Context { return zerolog.New(nil).With() }

func TestNewMessageProcessor(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	if processor == nil {
		t.Fatal("Expected non-nil processor")
	}
}

func TestMessageProcessor_ProcessMessage_Success(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		spfResult:   &domain.SPFResult{Result: "pass"},
		dkimResult:  &domain.DKIMResult{Valid: true},
		dmarcResult: &domain.DMARCResult{Result: "pass"},
	}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_WebhookError(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		spfResult:   &domain.SPFResult{Result: "pass"},
		dkimResult:  &domain.DKIMResult{Valid: true},
		dmarcResult: &domain.DMARCResult{Result: "pass"},
	}
	webhookSender := &mockWebhookSender{err: io.ErrUnexpectedEOF}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err == nil {
		t.Error("Expected error from webhook sender")
	}
}

func TestMessageProcessor_ProcessMessage_AuthDisabled(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   false,
		EnableDKIM:  false,
		EnableDMARC: false,
	}

	authChecker := &mockAuthChecker{}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_EmptyMessage(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	reader := strings.NewReader("")
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err == nil {
		t.Error("Expected error for empty message")
	}
}

func TestMessageProcessor_ProcessMessage_InvalidMessage(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	// Invalid message format
	reader := strings.NewReader("invalid message content")
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err == nil {
		t.Error("Expected error for invalid message")
	}
}

func TestProcessorConfig_DefaultValues(t *testing.T) {
	config := ProcessorConfig{}

	if config.EnableSPF {
		t.Error("Expected EnableSPF to be false by default")
	}
	if config.EnableDKIM {
		t.Error("Expected EnableDKIM to be false by default")
	}
	if config.EnableDMARC {
		t.Error("Expected EnableDMARC to be false by default")
	}
}

func TestProcessorConfig_WithValues(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	if !config.EnableSPF {
		t.Error("Expected EnableSPF to be true")
	}
	if !config.EnableDKIM {
		t.Error("Expected EnableDKIM to be true")
	}
	if !config.EnableDMARC {
		t.Error("Expected EnableDMARC to be true")
	}
}

func TestMessageProcessor_ProcessMessage_ContextCancellation(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	// The processor doesn't check context during processing, so it should succeed
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_LargeMessage(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		spfResult:   &domain.SPFResult{Result: "pass"},
		dkimResult:  &domain.DKIMResult{Valid: true},
		dmarcResult: &domain.DMARCResult{Result: "pass"},
	}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	// Create a large message
	largeContent := strings.Repeat("x", 10000)
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\n" + largeContent
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err != nil {
		t.Errorf("Expected no error for large message, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_ReadError(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	// Create a reader that will fail to read
	reader := &failingReader{}
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err == nil {
		t.Error("Expected error from failing reader")
	}
}

func TestMessageProcessor_ProcessMessage_SPFError(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		spfErr: io.ErrUnexpectedEOF,
	}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	// The processor logs SPF errors but doesn't return them, so we expect no error
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_DKIMError(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		dkimErr: io.ErrUnexpectedEOF,
	}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	// The processor logs DKIM errors but doesn't return them, so we expect no error
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_DMARCError(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		dmarcErr: io.ErrUnexpectedEOF,
	}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	// The processor logs DMARC errors but doesn't return them, so we expect no error
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_AllAuthErrors(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		spfErr:   io.ErrUnexpectedEOF,
		dkimErr:  io.ErrUnexpectedEOF,
		dmarcErr: io.ErrUnexpectedEOF,
	}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	// The processor logs auth errors but doesn't return them, so we expect no error
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_WithNilRemoteIP(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		spfResult:   &domain.SPFResult{Result: "pass"},
		dkimResult:  &domain.DKIMResult{Valid: true},
		dmarcResult: &domain.DMARCResult{Result: "pass"},
	}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	var remoteIP net.IP = nil

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err != nil {
		t.Errorf("Expected no error with nil remote IP, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_WithEmptyFrom(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		spfResult:   &domain.SPFResult{Result: "pass"},
		dkimResult:  &domain.DKIMResult{Valid: true},
		dmarcResult: &domain.DMARCResult{Result: "pass"},
	}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := ""
	to := []string{"recipient@example.com"}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err != nil {
		t.Errorf("Expected no error with empty from, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_WithEmptyTo(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		spfResult:   &domain.SPFResult{Result: "pass"},
		dkimResult:  &domain.DKIMResult{Valid: true},
		dmarcResult: &domain.DMARCResult{Result: "pass"},
	}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{}
	sessionID := "test-session"
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err != nil {
		t.Errorf("Expected no error with empty to, got %v", err)
	}
}

func TestMessageProcessor_ProcessMessage_WithEmptySessionID(t *testing.T) {
	config := ProcessorConfig{
		EnableSPF:   true,
		EnableDKIM:  true,
		EnableDMARC: true,
	}

	authChecker := &mockAuthChecker{
		spfResult:   &domain.SPFResult{Result: "pass"},
		dkimResult:  &domain.DKIMResult{Valid: true},
		dmarcResult: &domain.DMARCResult{Result: "pass"},
	}
	webhookSender := &mockWebhookSender{}
	metrics := &mockMetricsCollector{}
	sentry := &mockSentryClient{}
	logger := &mockLogger{}

	processor := NewMessageProcessor(config, authChecker, webhookSender, metrics, sentry, logger)

	ctx := context.Background()
	message := "From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	reader := strings.NewReader(message)
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := ""
	remoteIP := net.ParseIP("192.168.1.1")

	err := processor.ProcessMessage(ctx, reader, from, to, sessionID, remoteIP)
	if err != nil {
		t.Errorf("Expected no error with empty session ID, got %v", err)
	}
}

// Helper type for testing read errors
type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}
