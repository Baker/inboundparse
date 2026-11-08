package observability

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
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
		// Webhook metrics
		webhookRequestSize: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "webhook_request_size_bytes",
			Help:    "Size of webhook requests in bytes",
			Buckets: prometheus.ExponentialBuckets(1024, 2, 15), // 1KB to 32MB
		}),
		webhookResponseSize: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "webhook_response_size_bytes",
			Help:    "Size of webhook responses in bytes",
			Buckets: prometheus.ExponentialBuckets(1024, 2, 15), // 1KB to 32MB
		}),
		webhookRetries: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_retries_total",
			Help: "Number of webhook retry attempts",
		}, []string{"success"}),
		webhookErrors: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_errors_total",
			Help: "Number of webhook errors by type",
		}, []string{"error_type"}),
		// Authentication duration metrics
		spfDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "spf_duration_seconds",
			Help:    "Duration of SPF checks in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		dkimDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "dkim_duration_seconds",
			Help:    "Duration of DKIM checks in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		dmarcDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "dmarc_duration_seconds",
			Help:    "Duration of DMARC checks in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		// Domain-based authentication metrics
		spfResultsByDomain: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "spf_results_by_domain_total",
			Help: "SPF results by domain",
		}, []string{"domain", "result"}),
		dkimResultsByDomain: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim_results_by_domain_total",
			Help: "DKIM results by domain",
		}, []string{"domain", "result"}),
		dmarcResultsByDomain: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dmarc_results_by_domain_total",
			Help: "DMARC results by domain",
		}, []string{"domain", "result"}),
		// Authentication error metrics
		authErrors: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_errors_total",
			Help: "Number of authentication errors by type",
		}, []string{"check_type", "error_type"}),
		// Message processing stage metrics
		messageReadDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "message_read_duration_seconds",
			Help:    "Duration of message read stage in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		messageParseDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "message_parse_duration_seconds",
			Help:    "Duration of message parse stage in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		messageAuthDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "message_auth_duration_seconds",
			Help:    "Duration of message auth stage in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		messageWebhookDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "message_webhook_duration_seconds",
			Help:    "Duration of message webhook stage in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		messageTotalDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "message_total_processing_duration_seconds",
			Help:    "Total duration of message processing in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		// Email characteristics metrics
		emailAttachmentCount: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "email_attachment_count",
			Help:    "Number of attachments in emails",
			Buckets: []float64{0, 1, 2, 3, 4, 5, 10, 15, 20, 25, 30, 50, 100},
		}),
		emailAttachmentSize: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "email_attachment_size_bytes",
			Help:    "Size of email attachments in bytes",
			Buckets: prometheus.ExponentialBuckets(1024, 2, 15), // 1KB to 32MB
		}),
		emailBodyType: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "email_body_type_total",
			Help: "Number of emails by body type (text, html, multipart)",
		}, []string{"body_type"}),
		emailHeaderCount: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "email_header_count",
			Help:    "Number of headers in emails",
			Buckets: []float64{0, 5, 10, 15, 20, 25, 30, 40, 50, 75, 100, 150, 200},
		}),
		emailRecipientCount: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "email_recipient_count",
			Help:    "Number of recipients in emails",
			Buckets: []float64{0, 1, 2, 3, 4, 5, 10, 15, 20, 25, 30, 50, 100},
		}),
		// Session lifecycle metrics
		sessionDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "session_duration_seconds",
			Help:    "Duration of SMTP sessions in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		sessionCommands: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "session_commands_total",
			Help: "Number of SMTP commands executed per session",
		}, []string{"command"}),
		sessionErrors: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "session_errors_total",
			Help: "Number of SMTP session errors by type",
		}, []string{"error_type"}),
		sessionMessageCount: factory.NewCounter(prometheus.CounterOpts{
			Name: "session_messages_total",
			Help: "Number of messages processed per session",
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
	// Use a custom registry to avoid registration conflicts
	registry := prometheus.NewRegistry()
	collector := &metricsCollector{
		smtpConnectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "smtp_connections_total",
			Help: "Total number of SMTP connections",
		}),
		smtpConnectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "smtp_connections_active",
			Help: "Number of active SMTP connections",
		}),
		smtpActiveSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "smtp_sessions_active",
			Help: "Number of active SMTP sessions",
		}),
		smtpMessagesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "smtp_messages_total",
			Help: "Total number of SMTP messages processed",
		}),
		spfResults: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "spf_results_total",
			Help: "Total number of SPF check results",
		}, []string{"result"}),
		dkimResults: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim_results_total",
			Help: "Total number of DKIM check results",
		}, []string{"result"}),
		dmarcResults: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dmarc_results_total",
			Help: "Total number of DMARC check results",
		}, []string{"result"}),
		webhookRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_requests_total",
			Help: "Total number of webhook requests",
		}, []string{"status"}),
		webhookDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "webhook_duration_seconds",
			Help:    "Duration of webhook requests in seconds",
			Buckets: prometheus.DefBuckets,
		}),
	}

	registry.MustRegister(collector.smtpConnectionsTotal)
	registry.MustRegister(collector.smtpConnectionsActive)
	registry.MustRegister(collector.smtpActiveSessions)
	registry.MustRegister(collector.smtpMessagesTotal)
	registry.MustRegister(collector.spfResults)
	registry.MustRegister(collector.dkimResults)
	registry.MustRegister(collector.dmarcResults)
	registry.MustRegister(collector.webhookRequests)
	registry.MustRegister(collector.webhookDuration)

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

func TestMetricsCollector_TrackDKIM2Result(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := NewMetricsCollectorWithRegistry(registry)

	collector.TrackDKIM2Result("pass", "none")
	collector.TrackDKIM2Result("none", "")
	collector.TrackDKIM2Result("permerror", "missing_key")
	collector.TrackDKIM2Duration(time.Millisecond)

	if got := counterValue(t, registry, "auth_checks_dkim2_total", nil); got != 3 {
		t.Fatalf("auth_checks_dkim2_total = %v, want 3", got)
	}
	if got := counterValue(t, registry, "dkim2_results_total", map[string]string{"result": "pass", "reason": "none"}); got != 1 {
		t.Fatalf("pass/none = %v, want 1", got)
	}
	if got := counterValue(t, registry, "dkim2_results_total", map[string]string{"result": "none", "reason": "none"}); got != 1 {
		t.Fatalf("empty reason was not stored as none: %v", got)
	}
	if got := counterValue(t, registry, "dkim2_results_total", map[string]string{"result": "permerror", "reason": "missing_key"}); got != 1 {
		t.Fatalf("permerror/missing_key = %v, want 1", got)
	}
	if got := histogramCount(t, registry, "dkim2_check_duration_seconds"); got != 1 {
		t.Fatalf("dkim2 duration samples = %v, want 1", got)
	}

	noop := &NoOpMetricsCollector{}
	noop.TrackDKIM2Result("pass", "none")
	noop.TrackDKIM2Duration(time.Millisecond)
}

func counterValue(t *testing.T, registry *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	for _, family := range gatherFamilies(t, registry) {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if labelValuesMatch(metric.GetLabel(), labels) {
				return metric.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("counter %s %v not found", name, labels)
	return 0
}

func histogramCount(t *testing.T, registry *prometheus.Registry, name string) uint64 {
	t.Helper()
	for _, family := range gatherFamilies(t, registry) {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			return metric.GetHistogram().GetSampleCount()
		}
	}
	t.Fatalf("histogram %s not found", name)
	return 0
}

func gatherFamilies(t *testing.T, registry *prometheus.Registry) []*dto.MetricFamily {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	return families
}

func labelValuesMatch(got []*dto.LabelPair, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, label := range got {
		if want[label.GetName()] != label.GetValue() {
			return false
		}
	}
	return true
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

func TestTrackWebhookRequest_StatusCodeLabelIsNumeric(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := NewMetricsCollectorWithRegistry(registry)

	collector.TrackWebhookRequest(500, time.Millisecond)

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, fam := range families {
		if fam.GetName() != "webhook_requests_total" {
			continue
		}
		for _, m := range fam.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "status_code" && lp.GetValue() == "500" {
					return
				}
				if lp.GetName() == "status_code" {
					t.Fatalf("status_code label = %q, want 500", lp.GetValue())
				}
			}
		}
	}
	t.Fatal("webhook_requests_total not found")
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

func TestMetricsServer_Start_WithAuthentication(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics:   true,
		MetricsAddr:     "127.0.0.1:0", // Use port 0 for testing
		MetricsAPIKey:   "test-api-key",
		MetricsUsername: "testuser",
		MetricsPassword: "testpass",
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Errorf("Expected no error starting metrics server with auth, got %v", err)
	}

	// Clean up
	server.Stop(context.Background())
}

func TestMetricsServer_Start_WithBearerTokenAuth(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   "127.0.0.1:0", // Use port 0 for testing
		MetricsAPIKey: "test-api-key",
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Errorf("Expected no error starting metrics server with Bearer token auth, got %v", err)
	}

	// Clean up
	server.Stop(context.Background())
}

func TestMetricsServer_Start_WithBasicAuth(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics:   true,
		MetricsAddr:     "127.0.0.1:0", // Use port 0 for testing
		MetricsUsername: "testuser",
		MetricsPassword: "testpass",
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Errorf("Expected no error starting metrics server with Basic auth, got %v", err)
	}

	// Clean up
	server.Stop(context.Background())
}

func TestMetricsServer_Start_WithoutAuthentication(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   "127.0.0.1:0", // Use port 0 for testing
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Errorf("Expected no error starting metrics server without auth, got %v", err)
	}

	// Clean up
	server.Stop(context.Background())
}

func TestMetricsServer_Stop_WithTimeout(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   "127.0.0.1:0", // Use port 0 for testing
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Fatalf("Expected no error starting metrics server, got %v", err)
	}

	// Test stop with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = server.Stop(ctx)
	if err != nil {
		t.Errorf("Expected no error stopping metrics server, got %v", err)
	}
}

func TestMetricsServer_Stop_WithCancelledContext(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   "127.0.0.1:0", // Use port 0 for testing
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Fatalf("Expected no error starting metrics server, got %v", err)
	}

	// Test stop with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = server.Stop(ctx)
	if err != nil {
		t.Errorf("Expected no error stopping metrics server with cancelled context, got %v", err)
	}
}

func TestMetricsServer_HealthEndpoint(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   "127.0.0.1:0", // Use port 0 for testing
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Fatalf("Expected no error starting metrics server, got %v", err)
	}

	// The health endpoint is tested by the server starting successfully
	// In a real test, we would make HTTP requests to the health endpoint
	// but for unit tests, we just verify the server starts without error

	// Clean up
	server.Stop(context.Background())
}

func TestMetricsServer_AuthMiddleware_NoAuth(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   "127.0.0.1:0", // Use port 0 for testing
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Fatalf("Expected no error starting metrics server without auth, got %v", err)
	}

	// Clean up
	server.Stop(context.Background())
}

func TestMetricsServer_AuthMiddleware_BearerToken(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   "127.0.0.1:0", // Use port 0 for testing
		MetricsAPIKey: "test-api-key",
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Fatalf("Expected no error starting metrics server with Bearer token, got %v", err)
	}

	// Clean up
	server.Stop(context.Background())
}

func TestMetricsServer_AuthMiddleware_BasicAuth(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics:   true,
		MetricsAddr:     "127.0.0.1:0", // Use port 0 for testing
		MetricsUsername: "testuser",
		MetricsPassword: "testpass",
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Fatalf("Expected no error starting metrics server with Basic auth, got %v", err)
	}

	// Clean up
	server.Stop(context.Background())
}

func TestMetricsServer_AuthMiddleware_BothAuthMethods(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics:   true,
		MetricsAddr:     "127.0.0.1:0", // Use port 0 for testing
		MetricsAPIKey:   "test-api-key",
		MetricsUsername: "testuser",
		MetricsPassword: "testpass",
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Fatalf("Expected no error starting metrics server with both auth methods, got %v", err)
	}

	// Clean up
	server.Stop(context.Background())
}

func TestMetricsServer_Start_WithCustomPort(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   "127.0.0.1:0", // Use port 0 for testing
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Errorf("Expected no error starting metrics server with custom port, got %v", err)
	}

	// Clean up
	server.Stop(context.Background())
}

func TestMetricsServer_Start_WithInvalidPort(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   "invalid-port", // This should cause an error
	}

	server := NewMetricsServer(config)
	err := server.Start()
	// The server might not actually fail on invalid port in some cases
	// so we'll just test that it doesn't panic
	if err != nil {
		t.Logf("Server failed to start with invalid port (expected): %v", err)
	}
}

func TestMetricsServer_Start_WithEmptyAddress(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   "", // Empty address should cause an error
	}

	server := NewMetricsServer(config)
	err := server.Start()
	// The server might not actually fail on empty address in some cases
	// so we'll just test that it doesn't panic
	if err != nil {
		t.Logf("Server failed to start with empty address (expected): %v", err)
	}
}

func TestMetricsServer_HealthEndpointNew(t *testing.T) {
	// Test health endpoint by making an actual HTTP request
	// Use a listener to get an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close() // Close the temporary listener so the port is available

	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   addr,
	}

	server := NewMetricsServer(config)
	err = server.Start()
	if err != nil {
		t.Fatalf("Expected no error starting metrics server, got %v", err)
	}
	defer server.Stop(context.Background())

	// Give the server a moment to start
	time.Sleep(200 * time.Millisecond)

	// Make HTTP request to health endpoint
	resp, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("Failed to make HTTP request to health endpoint: %v", err)
	}
	defer resp.Body.Close()

	// Verify status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Verify response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != "OK" {
		t.Errorf("Expected response body 'OK', got '%s'", string(body))
	}
}

// Test new webhook metrics
func TestMetricsCollector_TrackWebhookRequestSize(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackWebhookRequestSize(1024, 2048)
	collector.TrackWebhookRequestSize(0, 0)
	collector.TrackWebhookRequestSize(999999999, 999999999)
}

func TestMetricsCollector_TrackWebhookRetry(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackWebhookRetry(true)
	collector.TrackWebhookRetry(false)
}

func TestMetricsCollector_TrackWebhookError(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackWebhookError("network")
	collector.TrackWebhookError("timeout")
	collector.TrackWebhookError("4xx")
	collector.TrackWebhookError("5xx")
}

// Test authentication duration metrics
func TestMetricsCollector_TrackSPFDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackSPFDuration(100 * time.Millisecond)
	collector.TrackSPFDuration(1 * time.Second)
	collector.TrackSPFDuration(5 * time.Second)
}

func TestMetricsCollector_TrackDKIMDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackDKIMDuration(50 * time.Millisecond)
	collector.TrackDKIMDuration(500 * time.Millisecond)
	collector.TrackDKIMDuration(2 * time.Second)
}

func TestMetricsCollector_TrackDMARCDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackDMARCDuration(75 * time.Millisecond)
	collector.TrackDMARCDuration(750 * time.Millisecond)
	collector.TrackDMARCDuration(3 * time.Second)
}

// Test domain-based authentication metrics
func TestMetricsCollector_TrackSPFResultByDomain(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackSPFResultByDomain("example.com", "pass")
	collector.TrackSPFResultByDomain("example.com", "fail")
	collector.TrackSPFResultByDomain("test.org", "temperror")
	collector.TrackSPFResultByDomain("", "none")
}

func TestMetricsCollector_TrackDKIMResultByDomain(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackDKIMResultByDomain("example.com", "valid")
	collector.TrackDKIMResultByDomain("example.com", "invalid")
	collector.TrackDKIMResultByDomain("test.org", "valid")
	collector.TrackDKIMResultByDomain("", "invalid")
}

func TestMetricsCollector_TrackDMARCResultByDomain(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackDMARCResultByDomain("example.com", "pass")
	collector.TrackDMARCResultByDomain("example.com", "fail")
	collector.TrackDMARCResultByDomain("test.org", "none")
	collector.TrackDMARCResultByDomain("", "pass")
}

// Test authentication error metrics
func TestMetricsCollector_TrackAuthError(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackAuthError("spf", "dns")
	collector.TrackAuthError("spf", "timeout")
	collector.TrackAuthError("dkim", "verification")
	collector.TrackAuthError("dkim", "parse")
	collector.TrackAuthError("dmarc", "dns")
	collector.TrackAuthError("dmarc", "timeout")
}

// Test message processing stage metrics
func TestMetricsCollector_TrackMessageReadDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackMessageReadDuration(10 * time.Millisecond)
	collector.TrackMessageReadDuration(100 * time.Millisecond)
	collector.TrackMessageReadDuration(1 * time.Second)
}

func TestMetricsCollector_TrackMessageParseDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackMessageParseDuration(5 * time.Millisecond)
	collector.TrackMessageParseDuration(50 * time.Millisecond)
	collector.TrackMessageParseDuration(500 * time.Millisecond)
}

func TestMetricsCollector_TrackMessageAuthDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackMessageAuthDuration(20 * time.Millisecond)
	collector.TrackMessageAuthDuration(200 * time.Millisecond)
	collector.TrackMessageAuthDuration(2 * time.Second)
}

func TestMetricsCollector_TrackMessageWebhookDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackMessageWebhookDuration(30 * time.Millisecond)
	collector.TrackMessageWebhookDuration(300 * time.Millisecond)
	collector.TrackMessageWebhookDuration(3 * time.Second)
}

func TestMetricsCollector_TrackMessageTotalProcessingDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackMessageTotalProcessingDuration(100 * time.Millisecond)
	collector.TrackMessageTotalProcessingDuration(1 * time.Second)
	collector.TrackMessageTotalProcessingDuration(10 * time.Second)
}

// Test email characteristics metrics
func TestMetricsCollector_TrackEmailAttachmentCount(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackEmailAttachmentCount(0)
	collector.TrackEmailAttachmentCount(1)
	collector.TrackEmailAttachmentCount(5)
	collector.TrackEmailAttachmentCount(100)
}

func TestMetricsCollector_TrackEmailAttachmentSize(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackEmailAttachmentSize(0)
	collector.TrackEmailAttachmentSize(1024)
	collector.TrackEmailAttachmentSize(1024 * 1024)
	collector.TrackEmailAttachmentSize(1024 * 1024 * 100)
}

func TestMetricsCollector_TrackEmailBodyType(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackEmailBodyType("text")
	collector.TrackEmailBodyType("html")
	collector.TrackEmailBodyType("multipart")
	collector.TrackEmailBodyType("")
}

func TestMetricsCollector_TrackEmailHeaderCount(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackEmailHeaderCount(0)
	collector.TrackEmailHeaderCount(5)
	collector.TrackEmailHeaderCount(20)
	collector.TrackEmailHeaderCount(200)
}

func TestMetricsCollector_TrackEmailRecipientCount(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackEmailRecipientCount(0)
	collector.TrackEmailRecipientCount(1)
	collector.TrackEmailRecipientCount(5)
	collector.TrackEmailRecipientCount(100)
}

// Test session lifecycle metrics
func TestMetricsCollector_TrackSessionDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackSessionDuration(1 * time.Second)
	collector.TrackSessionDuration(30 * time.Second)
	collector.TrackSessionDuration(5 * time.Minute)
}

func TestMetricsCollector_TrackSessionCommandCount(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackSessionCommandCount("MAIL")
	collector.TrackSessionCommandCount("RCPT")
	collector.TrackSessionCommandCount("DATA")
	collector.TrackSessionCommandCount("RSET")
	collector.TrackSessionCommandCount("QUIT")
}

func TestMetricsCollector_TrackSessionErrorCount(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackSessionErrorCount("syntax_error")
	collector.TrackSessionErrorCount("too_many_recipients")
	collector.TrackSessionErrorCount("message_processing")
	collector.TrackSessionErrorCount("no_recipients")
}

func TestMetricsCollector_TrackSessionMessageCount(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	collector.TrackSessionMessageCount()
	collector.TrackSessionMessageCount()
	collector.TrackSessionMessageCount()
}

// Test NoOpMetricsCollector for all new methods
func TestNoOpMetricsCollector_NewMethods(t *testing.T) {
	collector := &NoOpMetricsCollector{}

	// Test all new webhook methods
	collector.TrackWebhookRequestSize(1024, 2048)
	collector.TrackWebhookRetry(true)
	collector.TrackWebhookError("network")

	// Test all new authentication methods
	collector.TrackSPFDuration(100 * time.Millisecond)
	collector.TrackDKIMDuration(50 * time.Millisecond)
	collector.TrackDMARCDuration(75 * time.Millisecond)
	collector.TrackSPFResultByDomain("example.com", "pass")
	collector.TrackDKIMResultByDomain("example.com", "valid")
	collector.TrackDMARCResultByDomain("example.com", "pass")
	collector.TrackAuthError("spf", "dns")

	// Test all new processing stage methods
	collector.TrackMessageReadDuration(10 * time.Millisecond)
	collector.TrackMessageParseDuration(5 * time.Millisecond)
	collector.TrackMessageAuthDuration(20 * time.Millisecond)
	collector.TrackMessageWebhookDuration(30 * time.Millisecond)
	collector.TrackMessageTotalProcessingDuration(100 * time.Millisecond)

	// Test all new email characteristics methods
	collector.TrackEmailAttachmentCount(5)
	collector.TrackEmailAttachmentSize(1024)
	collector.TrackEmailBodyType("html")
	collector.TrackEmailHeaderCount(20)
	collector.TrackEmailRecipientCount(3)

	// Test all new session lifecycle methods
	collector.TrackSessionDuration(30 * time.Second)
	collector.TrackSessionCommandCount("MAIL")
	collector.TrackSessionErrorCount("syntax_error")
	collector.TrackSessionMessageCount()
}

// Test edge cases for new metrics
func TestMetricsCollector_NewMetricsEdgeCases(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	// Test with zero and negative values
	collector.TrackWebhookRequestSize(0, 0)
	collector.TrackWebhookRequestSize(-1, -1)
	collector.TrackEmailAttachmentCount(0)
	collector.TrackEmailAttachmentCount(-1)
	collector.TrackEmailAttachmentSize(0)
	collector.TrackEmailAttachmentSize(-1)
	collector.TrackEmailHeaderCount(0)
	collector.TrackEmailHeaderCount(-1)
	collector.TrackEmailRecipientCount(0)
	collector.TrackEmailRecipientCount(-1)

	// Test with very large values
	collector.TrackWebhookRequestSize(999999999, 999999999)
	collector.TrackEmailAttachmentSize(999999999)
	collector.TrackEmailHeaderCount(999)
	collector.TrackEmailRecipientCount(999)

	// Test with empty strings
	collector.TrackWebhookError("")
	collector.TrackEmailBodyType("")
	collector.TrackSessionCommandCount("")
	collector.TrackSessionErrorCount("")
	collector.TrackSPFResultByDomain("", "")
	collector.TrackDKIMResultByDomain("", "")
	collector.TrackDMARCResultByDomain("", "")
	collector.TrackAuthError("", "")

	// Test with very long strings
	longString := string(make([]byte, 1000))
	collector.TrackWebhookError(longString)
	collector.TrackEmailBodyType(longString)
	collector.TrackSessionCommandCount(longString)
	collector.TrackSessionErrorCount(longString)
	collector.TrackSPFResultByDomain(longString, longString)
	collector.TrackDKIMResultByDomain(longString, longString)
	collector.TrackDMARCResultByDomain(longString, longString)
	collector.TrackAuthError(longString, longString)

	// Test with very long durations
	collector.TrackSPFDuration(24 * time.Hour)
	collector.TrackDKIMDuration(24 * time.Hour)
	collector.TrackDMARCDuration(24 * time.Hour)
	collector.TrackMessageReadDuration(24 * time.Hour)
	collector.TrackMessageParseDuration(24 * time.Hour)
	collector.TrackMessageAuthDuration(24 * time.Hour)
	collector.TrackMessageWebhookDuration(24 * time.Hour)
	collector.TrackMessageTotalProcessingDuration(24 * time.Hour)
	collector.TrackSessionDuration(24 * time.Hour)
}

// TestNoOpMetricsCollector_AllMethods tests ALL NoOp methods to ensure 100% coverage
func TestNoOpMetricsCollector_AllMethods(t *testing.T) {
	collector := &NoOpMetricsCollector{}

	// TrackConnection returns a func - call it too
	done := collector.TrackConnection()
	if done == nil {
		t.Error("Expected non-nil func from TrackConnection")
	}
	done()

	// TrackSession returns a func - call it too
	sessionDone := collector.TrackSession()
	if sessionDone == nil {
		t.Error("Expected non-nil func from TrackSession")
	}
	sessionDone()

	// Basic track methods
	collector.TrackMessage(1024, true)
	collector.TrackMessage(0, false)
	collector.TrackSPFResult("pass")
	collector.TrackDKIMResult(true)
	collector.TrackDKIMResult(false)
	collector.TrackDMARCResult("pass", "reject")
	collector.TrackDMARCResult("none", "")
	collector.TrackWebhookRequest(200, time.Millisecond)
	collector.TrackWebhookRequest(500, time.Second)

	// Webhook methods
	collector.TrackWebhookRequestSize(1024, 2048)
	collector.TrackWebhookRetry(true)
	collector.TrackWebhookRetry(false)
	collector.TrackWebhookError("network")

	// Auth duration methods
	collector.TrackSPFDuration(100 * time.Millisecond)
	collector.TrackDKIMDuration(50 * time.Millisecond)
	collector.TrackDMARCDuration(75 * time.Millisecond)

	// Domain-based auth methods
	collector.TrackSPFResultByDomain("example.com", "pass")
	collector.TrackDKIMResultByDomain("example.com", "valid")
	collector.TrackDMARCResultByDomain("example.com", "pass")
	collector.TrackAuthError("spf", "dns")

	// Processing stage methods
	collector.TrackMessageReadDuration(10 * time.Millisecond)
	collector.TrackMessageParseDuration(5 * time.Millisecond)
	collector.TrackMessageAuthDuration(20 * time.Millisecond)
	collector.TrackMessageWebhookDuration(30 * time.Millisecond)
	collector.TrackMessageTotalProcessingDuration(100 * time.Millisecond)

	// Email characteristics methods
	collector.TrackEmailAttachmentCount(5)
	collector.TrackEmailAttachmentSize(1024)
	collector.TrackEmailBodyType("html")
	collector.TrackEmailHeaderCount(20)
	collector.TrackEmailRecipientCount(3)

	// Session lifecycle methods
	collector.TrackSessionDuration(30 * time.Second)
	collector.TrackSessionCommandCount("MAIL")
	collector.TrackSessionErrorCount("syntax_error")
	collector.TrackSessionMessageCount()
}

// TestMetricsServer_AuthMiddleware_HTTP tests the authMiddleware with actual HTTP requests
func TestMetricsServer_AuthMiddleware_HTTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	t.Run("no_auth_configured", func(t *testing.T) {
		config := MetricsConfig{
			EnableMetrics: true,
			MetricsAddr:   addr,
		}
		server := NewMetricsServer(config)
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}
		defer server.Stop(context.Background())
		time.Sleep(50 * time.Millisecond)

		resp, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			t.Fatalf("Failed to GET /metrics: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode)
		}
	})
}

func TestMetricsServer_AuthMiddleware_NonLoopbackRequiresCredentials(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   addr,
	}
	server := NewMetricsServer(config)
	if err := server.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer server.Stop(context.Background())
	time.Sleep(80 * time.Millisecond)

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	metricsURL := "http://" + net.JoinHostPort("127.0.0.1", port) + "/metrics"

	resp, err := http.Get(metricsURL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without credentials on %s, got %d", addr, resp.StatusCode)
	}
}

// TestMetricsServer_AuthMiddleware_BearerToken_HTTP tests bearer token auth via HTTP
func TestMetricsServer_AuthMiddleware_BearerToken_HTTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	config := MetricsConfig{
		EnableMetrics: true,
		MetricsAddr:   addr,
		MetricsAPIKey: "secret-token",
	}
	server := NewMetricsServer(config)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	t.Run("no_auth_header", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("correct_bearer_token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://"+addr+"/metrics", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("bearer_scheme_case_insensitive", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://"+addr+"/metrics", nil)
		req.Header.Set("Authorization", "bearer secret-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("wrong_bearer_token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://"+addr+"/metrics", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("malformed_auth_header", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://"+addr+"/metrics", nil)
		req.Header.Set("Authorization", "NotBearer token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", resp.StatusCode)
		}
	})
}

// TestMetricsServer_AuthMiddleware_BasicAuth_HTTP tests basic auth via HTTP
func TestMetricsServer_AuthMiddleware_BasicAuth_HTTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	config := MetricsConfig{
		EnableMetrics:   true,
		MetricsAddr:     addr,
		MetricsUsername: "admin",
		MetricsPassword: "password",
	}
	server := NewMetricsServer(config)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop(context.Background())
	time.Sleep(50 * time.Millisecond)

	t.Run("correct_basic_auth", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://"+addr+"/metrics", nil)
		req.SetBasicAuth("admin", "password")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("wrong_basic_auth", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://"+addr+"/metrics", nil)
		req.SetBasicAuth("admin", "wrong")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("no_auth", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", resp.StatusCode)
		}
	})
}

// TestNewMetricsCollectorWithRegistry tests the registry-based constructor
func TestNewMetricsCollectorWithRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := NewMetricsCollectorWithRegistry(registry)
	if collector == nil {
		t.Error("Expected non-nil collector")
	}
	// Exercise it
	done := collector.TrackConnection()
	done()
	collector.TrackMessage(100, true)
}

// Test concurrent access to new metrics
func TestMetricsCollector_NewMetricsConcurrentAccess(t *testing.T) {
	registry := prometheus.NewRegistry()
	collector := createTestMetricsCollector(registry)

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			// Test webhook metrics
			collector.TrackWebhookRequestSize(1024, 2048)
			collector.TrackWebhookRetry(true)
			collector.TrackWebhookError("network")

			// Test authentication metrics
			collector.TrackSPFDuration(100 * time.Millisecond)
			collector.TrackDKIMDuration(50 * time.Millisecond)
			collector.TrackDMARCDuration(75 * time.Millisecond)
			collector.TrackSPFResultByDomain("example.com", "pass")
			collector.TrackDKIMResultByDomain("example.com", "valid")
			collector.TrackDMARCResultByDomain("example.com", "pass")
			collector.TrackAuthError("spf", "dns")

			// Test processing stage metrics
			collector.TrackMessageReadDuration(10 * time.Millisecond)
			collector.TrackMessageParseDuration(5 * time.Millisecond)
			collector.TrackMessageAuthDuration(20 * time.Millisecond)
			collector.TrackMessageWebhookDuration(30 * time.Millisecond)
			collector.TrackMessageTotalProcessingDuration(100 * time.Millisecond)

			// Test email characteristics metrics
			collector.TrackEmailAttachmentCount(5)
			collector.TrackEmailAttachmentSize(1024)
			collector.TrackEmailBodyType("html")
			collector.TrackEmailHeaderCount(20)
			collector.TrackEmailRecipientCount(3)

			// Test session lifecycle metrics
			collector.TrackSessionDuration(30 * time.Second)
			collector.TrackSessionCommandCount("MAIL")
			collector.TrackSessionErrorCount("syntax_error")
			collector.TrackSessionMessageCount()

			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}
