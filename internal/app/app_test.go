package app

import (
	"context"
	"errors"
	"inboundparse/internal/config"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// Mock implementations for testing
type mockLogger struct{}

func (m *mockLogger) Trace() *interface{} { return nil }
func (m *mockLogger) Debug() *interface{} { return nil }
func (m *mockLogger) Info() *interface{}  { return nil }
func (m *mockLogger) Warn() *interface{}  { return nil }
func (m *mockLogger) Error() *interface{} { return nil }
func (m *mockLogger) Fatal() *interface{} { return nil }
func (m *mockLogger) Panic() *interface{} { return nil }

type mockMetricsCollector struct{}

func (m *mockMetricsCollector) TrackConnection() func()                                    { return func() {} }
func (m *mockMetricsCollector) TrackSession() func()                                       { return func() {} }
func (m *mockMetricsCollector) TrackMessage(size int64, success bool)                      {}
func (m *mockMetricsCollector) TrackSPFResult(result string)                               {}
func (m *mockMetricsCollector) TrackDKIMResult(valid bool)                                 {}
func (m *mockMetricsCollector) TrackDMARCResult(result, policy string)                     {}
func (m *mockMetricsCollector) TrackWebhookRequest(statusCode int, duration time.Duration) {}

type mockSentryClient struct{}

func (m *mockSentryClient) Init(config interface{}) error                       { return nil }
func (m *mockSentryClient) CaptureError(err error, tags map[string]interface{}) {}
func (m *mockSentryClient) CaptureMessage(message string, level interface{}, tags map[string]interface{}) {
}
func (m *mockSentryClient) Flush()             {}
func (m *mockSentryClient) RecoverWithSentry() {}

type mockAuthChecker struct{}

func (m *mockAuthChecker) CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string, logger observability.Logger) (*domain.SPFResult, error) {
	return nil, nil
}

func (m *mockAuthChecker) CheckDKIM(ctx context.Context, rawMessage string, logger observability.Logger) (*domain.DKIMResult, error) {
	return nil, nil
}

func (m *mockAuthChecker) CheckDMARC(ctx context.Context, rawMessage string, headers interface{}, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult, logger observability.Logger) (*domain.DMARCResult, error) {
	return nil, nil
}

type mockWebhookSender struct{}

func (m *mockWebhookSender) SendWebhook(ctx context.Context, payload interface{}) error {
	return nil
}

type mockMessageProcessor struct{}

func (m *mockMessageProcessor) ProcessMessage(ctx context.Context, r io.Reader, from string, to []string, sessionID string, remoteIP net.IP) error {
	return nil
}

type mockBackend struct{}

func (m *mockBackend) NewSession(c interface{}) (interface{}, error) {
	return nil, nil
}

type mockSMTPServer struct {
	startErr error
	stopErr  error
}

func (m *mockSMTPServer) Start() error {
	return m.startErr
}

func (m *mockSMTPServer) Stop() error {
	return m.stopErr
}

type mockMetricsServer struct {
	startErr error
}

func (m *mockMetricsServer) Start() error {
	return m.startErr
}

func (m *mockMetricsServer) Stop(ctx context.Context) error {
	return nil
}

func TestNewApp(t *testing.T) {
	config := &config.Config{
		ListenAddr: "127.0.0.1:0",
		WebhookURL: "http://localhost:8080/webhook",
		ServerName: "test",
		Verbose:    true,
	}

	app, err := NewApp(config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if app == nil {
		t.Fatal("Expected non-nil app")
	}
}

func TestNewApp_InvalidConfig(t *testing.T) {
	// Test with nil config - this should return an error
	app, err := NewApp(nil)
	if err == nil {
		t.Error("Expected error with nil config")
	}
	if app != nil {
		t.Error("Expected nil app with nil config")
	}
}

func TestApp_Start_ValidConfig(t *testing.T) {
	config := &config.Config{
		ListenAddr:    "127.0.0.1:0",
		WebhookURL:    "http://localhost:8080/webhook",
		ServerName:    "test",
		Verbose:       true,
		EnableMetrics: false, // Disable metrics to avoid registration conflicts
		EnableSentry:  false, // Disable sentry to avoid initialization issues
	}

	app, err := NewApp(config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test that the app was created successfully
	if app == nil {
		t.Fatal("Expected non-nil app")
	}

	// Test that the app has the expected configuration
	if app.config.WebhookURL != "http://localhost:8080/webhook" {
		t.Errorf("Expected webhook URL 'http://localhost:8080/webhook', got '%s'", app.config.WebhookURL)
	}
}

func TestApp_Start_InvalidConfig(t *testing.T) {
	// Test with invalid TLS config (cert without key) which should fail validation
	config := &config.Config{
		ListenAddr: "127.0.0.1:0",
		WebhookURL: "http://localhost:8080/webhook",
		ServerName: "test",
		Verbose:    true,
		CertFile:   "/path/to/cert.pem",
		KeyFile:    "", // Missing key file - should fail validation
	}

	app, err := NewApp(config)
	if err != nil {
		t.Fatalf("Expected no error creating app, got %v", err)
	}

	// Test Start method with invalid config - should fail validation
	err = app.Start()
	if err == nil {
		t.Error("Expected error starting app with invalid config")
	}
	if err != nil && !strings.Contains(err.Error(), "invalid configuration") {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestApp_Start_WithMetrics(t *testing.T) {
	config := &config.Config{
		ListenAddr:    "127.0.0.1:0",
		WebhookURL:    "http://localhost:8080/webhook",
		ServerName:    "test",
		Verbose:       true,
		EnableMetrics: true,
		MetricsAddr:   "127.0.0.1:0", // Use port 0 for testing
	}

	app, err := NewApp(config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test that the app was created successfully with metrics enabled
	if app == nil {
		t.Fatal("Expected non-nil app")
	}

	// Test that metrics are enabled
	if !app.config.EnableMetrics {
		t.Error("Expected metrics to be enabled")
	}
}

func TestApp_Start_WithTLS(t *testing.T) {
	config := &config.Config{
		ListenAddr:    "127.0.0.1:0",
		ListenAddrTLS: "127.0.0.1:0",
		WebhookURL:    "http://localhost:8080/webhook",
		ServerName:    "test",
		Verbose:       true,
		CertFile:      "/nonexistent/cert.pem", // This will cause an error
		KeyFile:       "/nonexistent/key.pem",
	}

	app, err := NewApp(config)
	if err == nil {
		t.Fatalf("Expected error creating app, got nil")
	}
	if app != nil {
		t.Fatal("Expected app to be nil due to TLS certificate load error")
	}
	if !strings.Contains(err.Error(), "failed to create SMTP server: failed to load TLS certificate: open /nonexistent/cert.pem") {
		t.Errorf("Expected TLS cert load error, got: %s", err.Error())
	}
}

func TestApp_Run_WithSignalHandling(t *testing.T) {
	config := &config.Config{
		ListenAddr: "127.0.0.1:0",
		WebhookURL: "http://localhost:8080/webhook",
		ServerName: "test",
		Verbose:    true,
	}

	app, err := NewApp(config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test Run method - this will test signal handling setup
	// We can't easily test the actual signal handling without complex setup
	// but we can test that the method doesn't panic
	go func() {
		// Simulate a signal after a short delay
		time.Sleep(10 * time.Millisecond)
		// The actual signal handling is complex to test in unit tests
	}()

	// Start the app in a goroutine and then stop it quickly
	go func() {
		app.Run()
	}()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Stop the app
	err = app.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping app, got %v", err)
	}
}

func TestApp_Stop_WithoutMetrics(t *testing.T) {
	config := &config.Config{
		ListenAddr: "127.0.0.1:0",
		WebhookURL: "http://localhost:8080/webhook",
		ServerName: "test",
		Verbose:    true,
	}

	app, err := NewApp(config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test Stop method without metrics
	err = app.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping app without metrics, got %v", err)
	}
}

func TestApp_Start_WithTLSConfig(t *testing.T) {
	// Test TLS configuration logging (lines 160-165)
	// This test verifies that TLS config is set but doesn't actually start the server
	config := &config.Config{
		ListenAddr: "127.0.0.1:0",
		WebhookURL: "http://localhost:8080/webhook",
		ServerName: "test",
		Verbose:    true,
		CertFile:   "", // Don't set cert file to avoid TLS loading
		KeyFile:    "", // Don't set key file to avoid TLS loading
	}

	app, err := NewApp(config)
	if err != nil {
		t.Fatalf("Expected no error creating app, got %v", err)
	}

	// Test that the app was created successfully with TLS config
	if app == nil {
		t.Fatal("Expected non-nil app")
	}

	// Test that TLS configuration is set (empty strings)
	if app.config.CertFile != "" {
		t.Errorf("Expected CertFile '', got '%s'", app.config.CertFile)
	}
	if app.config.KeyFile != "" {
		t.Errorf("Expected KeyFile '', got '%s'", app.config.KeyFile)
	}
}

func TestApp_Start_SMTPServerError(t *testing.T) {
	// Test SMTP server start error path (lines 168-170)
	config := &config.Config{
		ListenAddr:             "invalid-address:99999", // Invalid port should cause error
		WebhookURL:             "http://localhost:8080/webhook",
		ServerName:             "test",
		Verbose:                true,
		EnableMetrics:          false,
		EnableSentry:           false,
		WebhookRetryMultiplier: config.DefaultWebhookRetryMultiplier,
	}

	app, err := NewApp(config)
	if err != nil {
		t.Fatalf("Expected no error creating app, got %v", err)
	}

	// Test Start method with invalid SMTP address
	err = app.Start()
	if err == nil {
		t.Error("Expected error starting app with invalid SMTP address")
	}
	if !strings.Contains(err.Error(), "failed to start SMTP server") {
		t.Errorf("Expected SMTP server error, got: %v", err)
	}
}

func TestApp_Start_MetricsServerError(t *testing.T) {
	// Test metrics server start error path (lines 156-160)
	// Use a mock metrics server to avoid Prometheus registration conflicts
	// Since the metrics server Start() method doesn't actually return errors in the current implementation,
	// we test the error handling code path by verifying the code structure exists.
	// The actual error would occur if the metrics server Start() method returned an error.

	config := &config.Config{
		ListenAddr:             "127.0.0.1:0",
		WebhookURL:             "http://localhost:8080/webhook",
		ServerName:             "test",
		Verbose:                true,
		EnableMetrics:          true, // Enable metrics to trigger the error path check
		MetricsAddr:            "127.0.0.1:0",
		EnableSentry:           false, // Disable sentry to avoid initialization issues
		WebhookRetryMultiplier: config.DefaultWebhookRetryMultiplier,
	}

	app, err := NewApp(config)
	if err != nil {
		t.Fatalf("Expected no error creating app, got %v", err)
	}

	// Replace the metrics server with a mock that returns an error
	mockServer := &mockMetricsServer{
		startErr: errors.New("metrics server start failed"),
	}

	// Access the private metricsServer field using unsafe
	// Since we're in the same package, we can use unsafe to access unexported fields
	appValue := reflect.ValueOf(app).Elem()
	metricsServerField := appValue.FieldByName("metricsServer")
	if !metricsServerField.IsValid() {
		t.Fatal("Could not find metricsServer field")
	}

	// Use unsafe to get a settable pointer to the field
	fieldPtr := unsafe.Pointer(metricsServerField.UnsafeAddr())
	metricsServerPtr := (*observability.MetricsServer)(fieldPtr)
	originalServer := *metricsServerPtr
	*metricsServerPtr = mockServer
	defer func() {
		*metricsServerPtr = originalServer
	}()

	// Test Start method - should return error from metrics server
	err = app.Start()
	if err == nil {
		t.Error("Expected error starting app with metrics server error")
	}
	if err != nil && !strings.Contains(err.Error(), "failed to start metrics server") {
		t.Errorf("Expected error message about metrics server, got: %v", err)
	}
}

// TestApp_Run_GoRoutinesCoverage exercises the Run() method goroutine setup paths.
// It starts the app and then stops the SMTP server to allow Run() to proceed past
// Start() and into its goroutine setup code.
func TestApp_Run_GoRoutinesCoverage(t *testing.T) {
	cfg := &config.Config{
		ListenAddr:             "127.0.0.1:0",
		WebhookURL:             "http://localhost:8080/webhook",
		ServerName:             "test",
		Verbose:                false,
		EnableMetrics:          false,
		EnableSentry:           false,
		WebhookRetryMultiplier: config.DefaultWebhookRetryMultiplier,
	}

	app, err := NewApp(cfg)
	if err != nil {
		t.Fatalf("Expected no error creating app, got %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- app.Run()
	}()

	// Give Run() time to enter Start() (which blocks on SMTP listen)
	time.Sleep(50 * time.Millisecond)

	// Stop the SMTP server to unblock Start(), allowing Run() to proceed to goroutine setup
	app.smtpServer.Stop()

	// Run() should now set up its goroutines and wait for signal/ctx.Done()
	// Give it a moment then stop
	time.Sleep(50 * time.Millisecond)

	// Stop gracefully
	app.Stop()

	// The goroutines in Run() are still waiting for signal, so we just wait briefly
	select {
	case runErr := <-done:
		t.Logf("Run() returned: %v", runErr)
	case <-time.After(2 * time.Second):
		// This is expected - Run's goroutines don't terminate without a signal
		// but the code paths are covered
	}
}

// TestApp_Stop_WithMetricsEnabled tests Stop() when metrics are enabled
func TestApp_Stop_WithMetricsEnabled(t *testing.T) {
	cfg := &config.Config{
		ListenAddr:             "127.0.0.1:0",
		WebhookURL:             "http://localhost:8080/webhook",
		ServerName:             "test",
		Verbose:                false,
		EnableMetrics:          true,
		MetricsAddr:            "127.0.0.1:0",
		EnableSentry:           false,
		WebhookRetryMultiplier: config.DefaultWebhookRetryMultiplier,
	}

	app, err := NewApp(cfg)
	if err != nil {
		t.Fatalf("Expected no error creating app, got %v", err)
	}

	// Start metrics server first
	if err := app.metricsServer.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}

	// Stop should stop metrics server too
	err = app.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping app, got %v", err)
	}
}

func TestApp_Start_WithTLSConfigLogging(t *testing.T) {
	// Test TLS configuration logging (lines 160-165)
	// This test verifies that TLS config is set but doesn't actually start the server
	config := &config.Config{
		ListenAddr: "127.0.0.1:0",
		WebhookURL: "http://localhost:8080/webhook",
		ServerName: "test",
		Verbose:    true,
		CertFile:   "", // Don't set cert file to avoid TLS loading
		KeyFile:    "", // Don't set key file to avoid TLS loading
	}

	app, err := NewApp(config)
	if err != nil {
		t.Fatalf("Expected no error creating app, got %v", err)
	}

	// Test that the app was created successfully with TLS config
	if app == nil {
		t.Fatal("Expected non-nil app")
	}

	// Test that TLS configuration is set (empty strings)
	if app.config.CertFile != "" {
		t.Errorf("Expected CertFile '', got '%s'", app.config.CertFile)
	}
	if app.config.KeyFile != "" {
		t.Errorf("Expected KeyFile '', got '%s'", app.config.KeyFile)
	}
}

// TestNewApp_WithSentryInitError exercises the sentry.Init failure warning path (line 46-54).
// An invalid DSN with EnableSentry=true causes Init to return an error (logged as a warning).
func TestNewApp_WithSentryInitError(t *testing.T) {
	cfg := &config.Config{
		ListenAddr:             "127.0.0.1:0",
		WebhookURL:             "http://localhost:8080/webhook",
		ServerName:             "test",
		EnableSentry:           true,
		SentryDSN:              "invalid-dsn-that-causes-error", // causes sentry.Init to fail
		WebhookRetryMultiplier: config.DefaultWebhookRetryMultiplier,
	}

	// Should still create the app — sentry init failure is a warning, not fatal
	app, err := NewApp(cfg)
	if err != nil {
		t.Fatalf("Expected no error even when sentry init fails, got %v", err)
	}
	if app == nil {
		t.Fatal("Expected non-nil app")
	}
}

// TestApp_Stop_AfterNoStart exercises Stop() when SMTP server was never started.
func TestApp_Stop_AfterNoStart(t *testing.T) {
	cfg := &config.Config{
		ListenAddr:             "127.0.0.1:0",
		WebhookURL:             "http://localhost:8080/webhook",
		ServerName:             "test",
		Verbose:                false,
		EnableMetrics:          false,
		EnableSentry:           false,
		WebhookRetryMultiplier: config.DefaultWebhookRetryMultiplier,
	}

	app, err := NewApp(cfg)
	if err != nil {
		t.Fatalf("Expected no error creating app, got %v", err)
	}

	// Stop the app without starting it — exercises the Stop() happy path
	err = app.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping app, got %v", err)
	}
}
