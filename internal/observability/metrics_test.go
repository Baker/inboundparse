package observability

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// createTestMetricsCollector creates a metrics collector using a custom registry for testing
func createTestMetricsCollector(registry *prometheus.Registry) MetricsCollector {
	factory := promauto.With(registry)

	return &metricsCollector{
		// Connection metrics
		smtpConnectionsTotal: factory.NewCounter(prometheus.CounterOpts{
			Name: "smtp_connections_total",
			Help: "Total number of SMTP connections",
		}),
		smtpConnectionsActive: factory.NewGauge(prometheus.GaugeOpts{
			Name: "smtp_connections_active",
			Help: "Number of active SMTP connections",
		}),
		smtpActiveSessions: factory.NewGauge(prometheus.GaugeOpts{
			Name: "smtp_active_sessions",
			Help: "Number of active SMTP sessions",
		}),
		smtpConnectionDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "smtp_connection_duration_seconds",
			Help:    "Duration of SMTP connections in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		// Message metrics
		smtpMessagesTotal: factory.NewCounter(prometheus.CounterOpts{
			Name: "smtp_messages_total",
			Help: "Total number of SMTP messages",
		}),
		smtpMessagesProcessed: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "smtp_messages_processed_total",
			Help: "Total number of SMTP messages processed",
		}, []string{"success"}),
		smtpMessagesFailed: factory.NewCounter(prometheus.CounterOpts{
			Name: "smtp_messages_failed_total",
			Help: "Total number of failed SMTP messages",
		}),
		smtpMessageSize: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "smtp_message_size_bytes",
			Help:    "Size of SMTP messages in bytes",
			Buckets: prometheus.ExponentialBuckets(1024, 2, 20), // 1KB to 1GB
		}),
		// Authentication metrics
		spfResults: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "spf_results_total",
			Help: "Total number of SPF checks",
		}, []string{"result"}),
		dkimResults: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim_results_total",
			Help: "Total number of DKIM checks",
		}, []string{"valid"}),
		dmarcResults: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dmarc_results_total",
			Help: "Total number of DMARC checks",
		}, []string{"result"}),
		dmarcPolicies: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dmarc_policies_total",
			Help: "Total number of DMARC policies",
		}, []string{"policy"}),
		authChecksSPF: factory.NewCounter(prometheus.CounterOpts{
			Name: "auth_checks_spf_total",
			Help: "Total number of SPF authentication checks",
		}),
		authChecksDKIM: factory.NewCounter(prometheus.CounterOpts{
			Name: "auth_checks_dkim_total",
			Help: "Total number of DKIM authentication checks",
		}),
		authChecksDMARC: factory.NewCounter(prometheus.CounterOpts{
			Name: "auth_checks_dmarc_total",
			Help: "Total number of DMARC authentication checks",
		}),
		// Webhook metrics
		webhookRequests: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_requests_total",
			Help: "Total number of webhook requests",
		}, []string{"status_code"}),
		webhookDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "webhook_request_duration_seconds",
			Help:    "Duration of webhook requests in seconds",
			Buckets: prometheus.DefBuckets,
		}),
	}
}

func TestMetricsServer_Start_Disabled(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: false,
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Errorf("Expected no error when metrics disabled, got %v", err)
	}
}

func TestMetricsConfig_DefaultValues(t *testing.T) {
	config := MetricsConfig{}

	if config.EnableMetrics {
		t.Error("Expected EnableMetrics to be false by default")
	}
	if config.MetricsAddr != "" {
		t.Errorf("Expected empty MetricsAddr, got '%s'", config.MetricsAddr)
	}
	if config.MetricsAPIKey != "" {
		t.Errorf("Expected empty MetricsAPIKey, got '%s'", config.MetricsAPIKey)
	}
	if config.MetricsUsername != "" {
		t.Errorf("Expected empty MetricsUsername, got '%s'", config.MetricsUsername)
	}
	if config.MetricsPassword != "" {
		t.Errorf("Expected empty MetricsPassword, got '%s'", config.MetricsPassword)
	}
}

func TestMetricsConfig_WithValues(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics:   true,
		MetricsAddr:     "127.0.0.1:9091",
		MetricsAPIKey:   "test-key",
		MetricsUsername: "testuser",
		MetricsPassword: "testpass",
	}

	if !config.EnableMetrics {
		t.Error("Expected EnableMetrics to be true")
	}
	if config.MetricsAddr != "127.0.0.1:9091" {
		t.Errorf("Expected MetricsAddr '127.0.0.1:9091', got '%s'", config.MetricsAddr)
	}
	if config.MetricsAPIKey != "test-key" {
		t.Errorf("Expected MetricsAPIKey 'test-key', got '%s'", config.MetricsAPIKey)
	}
	if config.MetricsUsername != "testuser" {
		t.Errorf("Expected MetricsUsername 'testuser', got '%s'", config.MetricsUsername)
	}
	if config.MetricsPassword != "testpass" {
		t.Errorf("Expected MetricsPassword 'testpass', got '%s'", config.MetricsPassword)
	}
}

func TestNewMetricsServer(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: false,
	}

	server := NewMetricsServer(config)
	if server == nil {
		t.Error("Expected non-nil metrics server")
	}
}

func TestNewMetricsCollector(t *testing.T) {
	collector := NewMetricsCollector()
	if collector == nil {
		t.Error("Expected non-nil metrics collector")
	}
}

func TestMetricsCollector_TrackConnection(t *testing.T) {
	// Create a test-specific metrics collector using a custom registry
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	// Test connection tracking
	cleanup := collector.TrackConnection()
	if cleanup == nil {
		t.Error("Expected cleanup function to be non-nil")
	}

	// Call cleanup
	cleanup()
}

func TestMetricsCollector_TrackSession(t *testing.T) {
	// Create a test-specific metrics collector using a custom registry
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	// Test session tracking
	cleanup := collector.TrackSession()
	if cleanup == nil {
		t.Error("Expected cleanup function to be non-nil")
	}

	// Call cleanup
	cleanup()
}

func TestMetricsCollector_TrackMessage(t *testing.T) {
	// Create a test-specific metrics collector using a custom registry
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	// Test message tracking
	collector.TrackMessage(1024, true)
	collector.TrackMessage(2048, false)
}

func TestMetricsCollector_TrackSPFResult(t *testing.T) {
	// Create a test-specific metrics collector using a custom registry
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	// Test SPF result tracking
	collector.TrackSPFResult("pass")
	collector.TrackSPFResult("fail")
	collector.TrackSPFResult("temperror")
}

func TestMetricsCollector_TrackDKIMResult(t *testing.T) {
	// Create a test-specific metrics collector using a custom registry
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	// Test DKIM result tracking
	collector.TrackDKIMResult(true)
	collector.TrackDKIMResult(false)
}

func TestMetricsCollector_TrackDMARCResult(t *testing.T) {
	// Create a test-specific metrics collector using a custom registry
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	// Test DMARC result tracking
	collector.TrackDMARCResult("pass", "quarantine")
	collector.TrackDMARCResult("fail", "reject")
	collector.TrackDMARCResult("none", "")
}

func TestMetricsCollector_TrackWebhookRequest(t *testing.T) {
	// Create a test-specific metrics collector using a custom registry
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	// Test webhook request tracking
	collector.TrackWebhookRequest(200, 100*time.Millisecond)
	collector.TrackWebhookRequest(500, 200*time.Millisecond)
}

func TestMetricsServer_Stop_NotStarted(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: false,
	}

	server := NewMetricsServer(config)

	// Should not panic when stopping a server that wasn't started
	server.Stop(context.Background())
}

func TestMetricsServer_Stop_AlreadyStopped(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: false,
	}

	server := NewMetricsServer(config)
	server.Start()
	server.Stop(context.Background())

	// Should not panic when stopping an already stopped server
	server.Stop(context.Background())
}

func TestMetricsCollector_MultipleInstances(t *testing.T) {
	// Test that we can create multiple metrics collectors with separate registries
	registry1 := prometheus.NewRegistry()
	registry2 := prometheus.NewRegistry()
	collector1 := createTestMetricsCollector(registry1)
	collector2 := createTestMetricsCollector(registry2)

	if collector1 == nil {
		t.Error("Expected non-nil collector1")
	}
	if collector2 == nil {
		t.Error("Expected non-nil collector2")
	}
	if collector1 == collector2 {
		t.Error("Expected different collector instances")
	}
}

func TestMetricsCollector_EdgeCases(t *testing.T) {
	// Create a test-specific metrics collector using a custom registry
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	// Test with zero values
	collector.TrackMessage(0, true)
	collector.TrackMessage(0, false)

	// Test with negative values
	collector.TrackMessage(-1, true)

	// Test with very large values
	collector.TrackMessage(999999999, true)

	// Test with empty strings
	collector.TrackSPFResult("")
	collector.TrackDMARCResult("", "")

	// Test with very long strings
	longString := string(make([]byte, 1000))
	collector.TrackSPFResult(longString)
	collector.TrackDMARCResult(longString, longString)

	// Test with negative status codes
	collector.TrackWebhookRequest(-1, time.Millisecond)

	// Test with very long durations
	collector.TrackWebhookRequest(200, 24*time.Hour)
}

func TestMetricsCollector_ConcurrentAccess(t *testing.T) {
	// Create a test-specific metrics collector using a custom registry
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	// Test concurrent access to metrics collector
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			collector.TrackMessage(1024, true)
			collector.TrackSPFResult("pass")
			collector.TrackDKIMResult(true)
			collector.TrackDMARCResult("pass", "quarantine")
			collector.TrackWebhookRequest(200, time.Millisecond)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}
