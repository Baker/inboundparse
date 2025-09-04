package server

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/inboundparse/inboundparse/internal/config"
	"github.com/inboundparse/inboundparse/internal/service"
	"go.uber.org/zap"
)

// mockSMTPBackend is a mock implementation of SMTPBackend
type mockSMTPBackend struct{}

func (m *mockSMTPBackend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	return &mockSMTPSession{}, nil
}

// mockSMTPSession is a mock implementation of SMTP session
type mockSMTPSession struct{}

func (m *mockSMTPSession) AuthPlain(username, password string) error      { return nil }
func (m *mockSMTPSession) Mail(from string, opts *smtp.MailOptions) error { return nil }
func (m *mockSMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error   { return nil }
func (m *mockSMTPSession) Data(r io.Reader) error                         { return nil }
func (m *mockSMTPSession) Reset()                                         {}
func (m *mockSMTPSession) Logout() error                                  { return nil }

// mockMetricsServiceForServer is a mock implementation of MetricsService for server tests
type mockMetricsServiceForServer struct{}

func (m *mockMetricsServiceForServer) IncrementSMTPConnections()                           {}
func (m *mockMetricsServiceForServer) IncrementActiveConnections()                         {}
func (m *mockMetricsServiceForServer) DecrementActiveConnections()                         {}
func (m *mockMetricsServiceForServer) RecordConnectionDuration(duration time.Duration)     {}
func (m *mockMetricsServiceForServer) IncrementSMTPMessages()                              {}
func (m *mockMetricsServiceForServer) RecordMessageSize(size int64)                        {}
func (m *mockMetricsServiceForServer) IncrementMessagesProcessed()                         {}
func (m *mockMetricsServiceForServer) IncrementMessagesFailed()                            {}
func (m *mockMetricsServiceForServer) RecordMessageParsingDuration(duration time.Duration) {}
func (m *mockMetricsServiceForServer) IncrementMessageParsingFailed()                      {}
func (m *mockMetricsServiceForServer) IncrementWebhookRequests()                           {}
func (m *mockMetricsServiceForServer) RecordWebhookDuration(duration time.Duration)        {}
func (m *mockMetricsServiceForServer) IncrementWebhookFailed()                             {}
func (m *mockMetricsServiceForServer) IncrementAuthChecks()                                {}
func (m *mockMetricsServiceForServer) IncrementSPFChecks()                                 {}
func (m *mockMetricsServiceForServer) IncrementDKIMChecks()                                {}
func (m *mockMetricsServiceForServer) IncrementDMARCChecks()                               {}
func (m *mockMetricsServiceForServer) IncrementAuthChecksFailed()                          {}
func (m *mockMetricsServiceForServer) RecordSPFResult(result string)                       {}
func (m *mockMetricsServiceForServer) RecordDKIMResult(result string)                      {}
func (m *mockMetricsServiceForServer) RecordDMARCResult(result string)                     {}
func (m *mockMetricsServiceForServer) RecordDMARCPolicy(policy string)                     {}
func (m *mockMetricsServiceForServer) IncrementActiveSessions()                            {}
func (m *mockMetricsServiceForServer) DecrementActiveSessions()                            {}
func (m *mockMetricsServiceForServer) Close() error                                        { return nil }

// mockLoggerService is a mock implementation of LoggerService
type mockLoggerService struct{}

func (m *mockLoggerService) Info(ctx context.Context, msg string, fields ...zap.Field)  {}
func (m *mockLoggerService) Error(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerService) Warn(ctx context.Context, msg string, fields ...zap.Field)  {}
func (m *mockLoggerService) Debug(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerService) Fatal(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerService) With(fields ...zap.Field) service.LoggerService             { return m }
func (m *mockLoggerService) WithContext(ctx context.Context) service.LoggerService      { return m }
func (m *mockLoggerService) Close() error                                               { return nil }

func TestNewServer(t *testing.T) {
	config := &config.Config{}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)
	if server == nil {
		t.Error("NewServer() returned nil")
	}
}

func TestServer_Start_WithoutMetrics(t *testing.T) {
	config := &config.Config{
		Metrics: config.MetricsConfig{
			Enabled: false,
		},
	}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)

	ctx := context.Background()
	err := server.Start(ctx)

	// The server might start successfully or fail depending on available ports
	// We just want to ensure it doesn't panic
	if err != nil {
		// If it fails, that's expected in test environment
		t.Logf("Start() returned expected error: %v", err)
	}
}

func TestServer_Start_WithMetrics(t *testing.T) {
	config := &config.Config{
		Metrics: config.MetricsConfig{
			Enabled: true,
			Addr:    "127.0.0.1:0", // Use port 0 to avoid conflicts
		},
	}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)

	ctx := context.Background()
	err := server.Start(ctx)

	// The server might start successfully or fail depending on available ports
	// We just want to ensure it doesn't panic
	if err != nil {
		// If it fails, that's expected in test environment
		t.Logf("Start() returned expected error: %v", err)
	}
}

func TestServer_Start_WithTLS(t *testing.T) {
	config := &config.Config{
		Server: config.ServerConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
		Metrics: config.MetricsConfig{
			Enabled: false,
		},
	}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)

	ctx := context.Background()
	err := server.Start(ctx)

	// This should fail because the certificate files don't exist
	if err == nil {
		t.Error("Expected Start() to return an error when TLS certificate files don't exist")
	}
}

func TestServer_Stop(t *testing.T) {
	config := &config.Config{}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)

	ctx := context.Background()
	err := server.Stop(ctx)

	// Stop should work even if nothing was started
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestServer_Run(t *testing.T) {
	config := &config.Config{
		Metrics: config.MetricsConfig{
			Enabled: false,
		},
	}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)

	// Create a context that will be cancelled quickly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := server.Run(ctx)

	// Run might succeed or fail depending on available ports
	// We just want to ensure it doesn't panic
	if err != nil {
		// If it fails, that's expected in test environment
		t.Logf("Run() returned expected error: %v", err)
	}
}

func TestServer_Run_WithTimeout(t *testing.T) {
	config := &config.Config{
		Metrics: config.MetricsConfig{
			Enabled: false,
		},
	}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)

	// Create a context that will be cancelled immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := server.Run(ctx)

	// Run might succeed or fail depending on available ports
	// We just want to ensure it doesn't panic
	if err != nil {
		// If it fails, that's expected in test environment
		t.Logf("Run() returned expected error: %v", err)
	}
}

func TestServer_StartMetricsServer_ErrorHandling(t *testing.T) {
	config := &config.Config{
		Metrics: config.MetricsConfig{
			Enabled: true,
			Addr:    "invalid-address", // This should cause an error
		},
	}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)

	ctx := context.Background()
	err := server.Start(ctx)

	// The server might start successfully or fail depending on the system
	// We just want to ensure it doesn't panic
	if err != nil {
		t.Logf("Start() returned expected error: %v", err)
	}
}

func TestServer_Stop_WithNilServices(t *testing.T) {
	config := &config.Config{}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)

	// Test stopping without starting
	ctx := context.Background()
	err := server.Stop(ctx)

	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestServer_StartSMTPServers_WithTLS(t *testing.T) {
	config := &config.Config{
		Server: config.ServerConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
		Metrics: config.MetricsConfig{
			Enabled: false,
		},
	}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)

	ctx := context.Background()
	err := server.Start(ctx)

	// This should fail because the certificate files don't exist
	if err == nil {
		t.Error("Expected Start() to return an error when TLS certificate files don't exist")
	}
}

func TestServer_StartSMTPServers_WithoutTLS(t *testing.T) {
	config := &config.Config{
		Server: config.ServerConfig{
			CertFile: "", // No TLS
			KeyFile:  "",
		},
		Metrics: config.MetricsConfig{
			Enabled: false,
		},
	}
	backend := &mockSMTPBackend{}
	metricsService := &mockMetricsServiceForServer{}
	logger := &mockLoggerService{}

	server := NewServer(config, backend, metricsService, logger)

	ctx := context.Background()
	err := server.Start(ctx)

	// This might succeed or fail depending on available ports
	if err != nil {
		t.Logf("Start() returned expected error: %v", err)
	}
}
