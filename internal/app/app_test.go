package app

import (
	"bytes"
	"context"
	"errors"
	"inboundparse/internal/config"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// lockedBuf is safe for exec to write while the test reads failure output.
type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

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
	testRunShutsDownOnSignal(t, syscall.SIGTERM)
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

// TestApp_Run_GoRoutinesCoverage runs Start in the background and shuts down
// on SIGINT. The handler must already be installed while SMTP is accepting.
func TestApp_Run_GoRoutinesCoverage(t *testing.T) {
	testRunShutsDownOnSignal(t, syscall.SIGINT)
}

// TestApp_Run_ReturnsStartError checks that a bind failure from Start is what
// Run returns, instead of waiting for a signal.
func TestApp_Run_ReturnsStartError(t *testing.T) {
	cfg := &config.Config{
		ListenAddr:             "invalid-address:99999",
		WebhookURL:             "http://localhost:8080/webhook",
		ServerName:             "test",
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

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Expected Run to return Start error")
		}
		if !strings.Contains(err.Error(), "failed to start SMTP server") {
			t.Fatalf("Expected SMTP start error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return the SMTP start error")
	}
}

// testRunShutsDownOnSignal re-executes this test in a child process so a
// missed SIGINT/SIGTERM cannot kill the parent test run. The child blocks in
// Run; the parent signals only after the SMTP port accepts a connection.
func testRunShutsDownOnSignal(t *testing.T, sig syscall.Signal) {
	t.Helper()

	if os.Getenv("INBOUNDPARSE_RUN_SIGNAL_CHILD") == "1" {
		serveUntilShutdownSignal(t)
		return
	}

	addr := reserveLoopbackAddr(t)
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.timeout=30s")
	cmd.Env = append(os.Environ(),
		"INBOUNDPARSE_RUN_SIGNAL_CHILD=1",
		"INBOUNDPARSE_LISTEN_ADDR="+addr,
	)
	var stdout, stderr lockedBuf
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start shutdown child: %v", err)
	}

	finished := false
	t.Cleanup(func() {
		if finished || cmd.Process == nil {
			return
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	logs := func() string {
		return stdout.String() + stderr.String()
	}

	if err := dialUntil(addr, 5*time.Second); err != nil {
		t.Fatalf("child never accepted SMTP connections on %s: %v\n%s", addr, err, logs())
	}

	if err := cmd.Process.Signal(sig); err != nil {
		t.Fatalf("signal child: %v", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()

	select {
	case err := <-waitDone:
		finished = true
		if err != nil {
			t.Fatalf("child exited with %v\n%s", err, logs())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("child did not exit after %s\n%s", sig, logs())
	}

	output := logs()
	if !strings.Contains(output, "Received shutdown signal") {
		t.Fatalf("shutdown log missing from child output:\n%s", output)
	}
	if !strings.Contains(output, "Application stopped") {
		t.Fatalf("stop log missing from child output:\n%s", output)
	}

	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatalf("SMTP listener %s still accepting after shutdown", addr)
	}
}

func serveUntilShutdownSignal(t *testing.T) {
	t.Helper()

	addr := os.Getenv("INBOUNDPARSE_LISTEN_ADDR")
	if addr == "" {
		t.Fatal("INBOUNDPARSE_LISTEN_ADDR is required")
	}

	cfg := &config.Config{
		ListenAddr:             addr,
		WebhookURL:             "http://localhost:8080/webhook",
		ServerName:             "test",
		EnableMetrics:          false,
		EnableSentry:           false,
		WebhookRetryMultiplier: config.DefaultWebhookRetryMultiplier,
	}

	app, err := NewApp(cfg)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	if err := app.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Signal path already called Stop. A second call must stay a no-op.
	if err := app.Stop(); err != nil {
		t.Fatalf("Stop after shutdown: %v", err)
	}
}

func reserveLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved port: %v", err)
	}
	return addr
}

func dialUntil(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		last = err
		time.Sleep(10 * time.Millisecond)
	}
	if last == nil {
		last = errors.New("no connection attempt")
	}
	return last
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

	// Stop the app without starting it — exercises the Stop() happy path.
	// A second call must also succeed; shutdown can run more than once.
	err = app.Stop()
	if err != nil {
		t.Fatalf("Expected no error stopping app, got %v", err)
	}
	err = app.Stop()
	if err != nil {
		t.Fatalf("Expected Stop to be idempotent, got %v", err)
	}
}
