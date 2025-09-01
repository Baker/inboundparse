package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all the metrics for the application
type Metrics struct {
	// Prometheus metrics
	SMTPConnectionsTotal    prometheus.Counter
	SMTPConnectionsActive   prometheus.Gauge
	SMTPConnectionsDuration prometheus.Histogram
	SMTPMessagesTotal       prometheus.Counter
	SMTPMessagesSize        prometheus.Histogram
	SMTPMessagesProcessed   prometheus.Counter
	SMTPMessagesFailed      prometheus.Counter
	WebhookRequestsTotal    prometheus.Counter
	WebhookRequestsDuration prometheus.Histogram
	WebhookRequestsFailed   prometheus.Counter
	AuthChecksTotal         prometheus.Counter
	AuthChecksSPF           prometheus.Counter
	AuthChecksDKIM          prometheus.Counter
	AuthChecksDMARC         prometheus.Counter
	AuthChecksFailed        prometheus.Counter
	MessageParsingDuration  prometheus.Histogram
	MessageParsingFailed    prometheus.Counter
	ActiveSessions          prometheus.Gauge
	ServerUptime            prometheus.Gauge

	// Whether metrics are enabled
	enabled bool
}

// NewMetrics creates a new Metrics instance
func NewMetrics(enabled bool) (*Metrics, error) {
	m := &Metrics{
		enabled: enabled,
	}

	// Only initialize Prometheus metrics if enabled
	if !enabled {
		return m, nil
	}

	// Initialize Prometheus metrics
	m.SMTPConnectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_connections_total",
		Help: "Total number of SMTP connections",
	})

	m.SMTPConnectionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "smtp_connections_active",
		Help: "Number of active SMTP connections",
	})

	m.SMTPConnectionsDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "smtp_connection_duration_seconds",
		Help:    "Duration of SMTP connections in seconds",
		Buckets: prometheus.DefBuckets,
	})

	m.SMTPMessagesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_messages_total",
		Help: "Total number of SMTP messages received",
	})

	m.SMTPMessagesSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "smtp_message_size_bytes",
		Help:    "Size of SMTP messages in bytes",
		Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600}, // 1KB, 10KB, 100KB, 1MB, 10MB, 100MB
	})

	m.SMTPMessagesProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_messages_processed_total",
		Help: "Total number of SMTP messages successfully processed",
	})

	m.SMTPMessagesFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_messages_failed_total",
		Help: "Total number of SMTP messages that failed to process",
	})

	m.WebhookRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "webhook_requests_total",
		Help: "Total number of webhook requests sent",
	})

	m.WebhookRequestsDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "webhook_request_duration_seconds",
		Help:    "Duration of webhook requests in seconds",
		Buckets: prometheus.DefBuckets,
	})

	m.WebhookRequestsFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "webhook_requests_failed_total",
		Help: "Total number of failed webhook requests",
	})

	m.AuthChecksTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_checks_total",
		Help: "Total number of authentication checks performed",
	})

	m.AuthChecksSPF = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_checks_spf_total",
		Help: "Total number of SPF checks performed",
	})

	m.AuthChecksDKIM = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_checks_dkim_total",
		Help: "Total number of DKIM checks performed",
	})

	m.AuthChecksDMARC = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_checks_dmarc_total",
		Help: "Total number of DMARC checks performed",
	})

	m.AuthChecksFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_checks_failed_total",
		Help: "Total number of failed authentication checks",
	})

	m.MessageParsingDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "message_parsing_duration_seconds",
		Help:    "Duration of message parsing in seconds",
		Buckets: prometheus.DefBuckets,
	})

	m.MessageParsingFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "message_parsing_failed_total",
		Help: "Total number of failed message parsing attempts",
	})

	m.ActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "smtp_active_sessions",
		Help: "Number of active SMTP sessions",
	})

	m.ServerUptime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "server_uptime_seconds",
		Help: "Server uptime in seconds",
	})

	// Start uptime counter
	go m.startUptimeCounter()

	return m, nil
}

// NewMetricsDisabled creates a disabled Metrics instance
func NewMetricsDisabled() *Metrics {
	return &Metrics{enabled: false}
}

// startUptimeCounter updates the uptime metric every second
func (m *Metrics) startUptimeCounter() {
	if !m.enabled {
		return
	}
	startTime := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.ServerUptime.Set(time.Since(startTime).Seconds())
	}
}

// IncrementSMTPConnections increments the SMTP connections counter
func (m *Metrics) IncrementSMTPConnections() {
	if !m.enabled {
		return
	}
	m.SMTPConnectionsTotal.Inc()
}

// IncrementActiveConnections increments the active connections gauge
func (m *Metrics) IncrementActiveConnections() {
	if !m.enabled {
		return
	}
	m.SMTPConnectionsActive.Inc()
}

// DecrementActiveConnections decrements the active connections gauge
func (m *Metrics) DecrementActiveConnections() {
	if !m.enabled {
		return
	}
	m.SMTPConnectionsActive.Dec()
}

// RecordConnectionDuration records the duration of an SMTP connection
func (m *Metrics) RecordConnectionDuration(duration time.Duration) {
	if !m.enabled {
		return
	}
	m.SMTPConnectionsDuration.Observe(duration.Seconds())
}

// IncrementSMTPMessages increments the SMTP messages counter
func (m *Metrics) IncrementSMTPMessages() {
	if !m.enabled {
		return
	}
	m.SMTPMessagesTotal.Inc()
}

// RecordMessageSize records the size of an SMTP message
func (m *Metrics) RecordMessageSize(size int64) {
	if !m.enabled {
		return
	}
	m.SMTPMessagesSize.Observe(float64(size))
}

// IncrementMessagesProcessed increments the processed messages counter
func (m *Metrics) IncrementMessagesProcessed() {
	if !m.enabled {
		return
	}
	m.SMTPMessagesProcessed.Inc()
}

// IncrementMessagesFailed increments the failed messages counter
func (m *Metrics) IncrementMessagesFailed() {
	if !m.enabled {
		return
	}
	m.SMTPMessagesFailed.Inc()
}

// IncrementWebhookRequests increments the webhook requests counter
func (m *Metrics) IncrementWebhookRequests() {
	if !m.enabled {
		return
	}
	m.WebhookRequestsTotal.Inc()
}

// RecordWebhookDuration records the duration of a webhook request
func (m *Metrics) RecordWebhookDuration(duration time.Duration) {
	if !m.enabled {
		return
	}
	m.WebhookRequestsDuration.Observe(duration.Seconds())
}

// IncrementWebhookFailed increments the failed webhook requests counter
func (m *Metrics) IncrementWebhookFailed() {
	if !m.enabled {
		return
	}
	m.WebhookRequestsFailed.Inc()
}

// IncrementAuthChecks increments the authentication checks counter
func (m *Metrics) IncrementAuthChecks() {
	if !m.enabled {
		return
	}
	m.AuthChecksTotal.Inc()
}

// IncrementSPFChecks increments the SPF checks counter
func (m *Metrics) IncrementSPFChecks() {
	if !m.enabled {
		return
	}
	m.AuthChecksSPF.Inc()
}

// IncrementDKIMChecks increments the DKIM checks counter
func (m *Metrics) IncrementDKIMChecks() {
	if !m.enabled {
		return
	}
	m.AuthChecksDKIM.Inc()
}

// IncrementDMARCChecks increments the DMARC checks counter
func (m *Metrics) IncrementDMARCChecks() {
	if !m.enabled {
		return
	}
	m.AuthChecksDMARC.Inc()
}

// IncrementAuthChecksFailed increments the failed authentication checks counter
func (m *Metrics) IncrementAuthChecksFailed() {
	if !m.enabled {
		return
	}
	m.AuthChecksFailed.Inc()
}

// RecordMessageParsingDuration records the duration of message parsing
func (m *Metrics) RecordMessageParsingDuration(duration time.Duration) {
	if !m.enabled {
		return
	}
	m.MessageParsingDuration.Observe(duration.Seconds())
}

// IncrementMessageParsingFailed increments the failed message parsing counter
func (m *Metrics) IncrementMessageParsingFailed() {
	if !m.enabled {
		return
	}
	m.MessageParsingFailed.Inc()
}

// IncrementActiveSessions increments the active sessions gauge
func (m *Metrics) IncrementActiveSessions() {
	if !m.enabled {
		return
	}
	m.ActiveSessions.Inc()
}

// DecrementActiveSessions decrements the active sessions gauge
func (m *Metrics) DecrementActiveSessions() {
	if !m.enabled {
		return
	}
	m.ActiveSessions.Dec()
}

// Close closes the metrics (no-op for Prometheus-only implementation)
func (m *Metrics) Close() error {
	return nil
}

// MetricsHandler returns an HTTP handler for Prometheus metrics
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// HealthHandler returns an HTTP handler for health checks
func HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
	})
}
