package service

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metricsService implements the MetricsService interface
type metricsService struct {
	enabled bool

	// Connection metrics
	smtpConnections    prometheus.Counter
	activeConnections  prometheus.Gauge
	connectionDuration prometheus.Histogram

	// Message metrics
	smtpMessages           prometheus.Counter
	messageSize            prometheus.Histogram
	messagesProcessed      prometheus.Counter
	messagesFailed         prometheus.Counter
	messageParsingDuration prometheus.Histogram
	messageParsingFailed   prometheus.Counter

	// Webhook metrics
	webhookRequests prometheus.Counter
	webhookDuration prometheus.Histogram
	webhookFailed   prometheus.Counter

	// Authentication metrics
	authChecks       prometheus.Counter
	spfChecks        prometheus.Counter
	dkimChecks       prometheus.Counter
	dmarcChecks      prometheus.Counter
	authChecksFailed prometheus.Counter

	// SPF result metrics
	spfResults *prometheus.CounterVec

	// DKIM result metrics
	dkimResults *prometheus.CounterVec

	// DMARC result metrics
	dmarcResults  *prometheus.CounterVec
	dmarcPolicies *prometheus.CounterVec

	// Session metrics
	activeSessions prometheus.Gauge

	// Uptime metric
	uptimeCounter prometheus.Counter
}

// NewMetricsService creates a new metrics service
func NewMetricsService(enabled bool) MetricsService {
	if !enabled {
		return &metricsService{enabled: false}
	}

	ms := &metricsService{
		enabled: true,
	}

	// Connection metrics
	ms.smtpConnections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_connections_total",
		Help: "Total number of SMTP connections",
	})

	ms.activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "smtp_active_connections",
		Help: "Number of active SMTP connections",
	})

	ms.connectionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "smtp_connection_duration_seconds",
		Help:    "Duration of SMTP connections",
		Buckets: prometheus.DefBuckets,
	})

	// Message metrics
	ms.smtpMessages = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_messages_total",
		Help: "Total number of SMTP messages received",
	})

	ms.messageSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "smtp_message_size_bytes",
		Help:    "Size of SMTP messages in bytes",
		Buckets: prometheus.ExponentialBuckets(1024, 2, 20), // 1KB to 1GB
	})

	ms.messagesProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_messages_processed_total",
		Help: "Total number of messages successfully processed",
	})

	ms.messagesFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_messages_failed_total",
		Help: "Total number of messages that failed processing",
	})

	ms.messageParsingDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "smtp_message_parsing_duration_seconds",
		Help:    "Duration of message parsing",
		Buckets: prometheus.DefBuckets,
	})

	ms.messageParsingFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_message_parsing_failed_total",
		Help: "Total number of message parsing failures",
	})

	// Webhook metrics
	ms.webhookRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "webhook_requests_total",
		Help: "Total number of webhook requests sent",
	})

	ms.webhookDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "webhook_duration_seconds",
		Help:    "Duration of webhook requests",
		Buckets: prometheus.DefBuckets,
	})

	ms.webhookFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "webhook_failed_total",
		Help: "Total number of failed webhook requests",
	})

	// Authentication metrics
	ms.authChecks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_checks_total",
		Help: "Total number of authentication checks performed",
	})

	ms.spfChecks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "spf_checks_total",
		Help: "Total number of SPF checks performed",
	})

	ms.dkimChecks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dkim_checks_total",
		Help: "Total number of DKIM checks performed",
	})

	ms.dmarcChecks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "dmarc_checks_total",
		Help: "Total number of DMARC checks performed",
	})

	ms.authChecksFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_checks_failed_total",
		Help: "Total number of failed authentication checks",
	})

	// Result metrics
	ms.spfResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "spf_results_total",
		Help: "Total number of SPF results by result type",
	}, []string{"result"})

	ms.dkimResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dkim_results_total",
		Help: "Total number of DKIM results by result type",
	}, []string{"result"})

	ms.dmarcResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dmarc_results_total",
		Help: "Total number of DMARC results by result type",
	}, []string{"result"})

	ms.dmarcPolicies = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dmarc_policies_total",
		Help: "Total number of DMARC policies by policy type",
	}, []string{"policy"})

	// Session metrics
	ms.activeSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "smtp_active_sessions",
		Help: "Number of active SMTP sessions",
	})

	// Uptime metric
	ms.uptimeCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_uptime_seconds_total",
		Help: "Total uptime in seconds",
	})

	// Start uptime counter
	ms.startUptimeCounter()

	return ms
}

// Connection metrics
func (m *metricsService) IncrementSMTPConnections() {
	if m.enabled && m.smtpConnections != nil {
		m.smtpConnections.Inc()
	}
}

func (m *metricsService) IncrementActiveConnections() {
	if m.enabled && m.activeConnections != nil {
		m.activeConnections.Inc()
	}
}

func (m *metricsService) DecrementActiveConnections() {
	if m.enabled && m.activeConnections != nil {
		m.activeConnections.Dec()
	}
}

func (m *metricsService) RecordConnectionDuration(duration time.Duration) {
	if m.enabled && m.connectionDuration != nil {
		m.connectionDuration.Observe(duration.Seconds())
	}
}

// Message metrics
func (m *metricsService) IncrementSMTPMessages() {
	if m.enabled && m.smtpMessages != nil {
		m.smtpMessages.Inc()
	}
}

func (m *metricsService) RecordMessageSize(size int64) {
	if m.enabled && m.messageSize != nil {
		m.messageSize.Observe(float64(size))
	}
}

func (m *metricsService) IncrementMessagesProcessed() {
	if m.enabled && m.messagesProcessed != nil {
		m.messagesProcessed.Inc()
	}
}

func (m *metricsService) IncrementMessagesFailed() {
	if m.enabled && m.messagesFailed != nil {
		m.messagesFailed.Inc()
	}
}

func (m *metricsService) RecordMessageParsingDuration(duration time.Duration) {
	if m.enabled && m.messageParsingDuration != nil {
		m.messageParsingDuration.Observe(duration.Seconds())
	}
}

func (m *metricsService) IncrementMessageParsingFailed() {
	if m.enabled && m.messageParsingFailed != nil {
		m.messageParsingFailed.Inc()
	}
}

// Webhook metrics
func (m *metricsService) IncrementWebhookRequests() {
	if m.enabled && m.webhookRequests != nil {
		m.webhookRequests.Inc()
	}
}

func (m *metricsService) RecordWebhookDuration(duration time.Duration) {
	if m.enabled && m.webhookDuration != nil {
		m.webhookDuration.Observe(duration.Seconds())
	}
}

func (m *metricsService) IncrementWebhookFailed() {
	if m.enabled && m.webhookFailed != nil {
		m.webhookFailed.Inc()
	}
}

// Authentication metrics
func (m *metricsService) IncrementAuthChecks() {
	if m.enabled && m.authChecks != nil {
		m.authChecks.Inc()
	}
}

func (m *metricsService) IncrementSPFChecks() {
	if m.enabled && m.spfChecks != nil {
		m.spfChecks.Inc()
	}
}

func (m *metricsService) IncrementDKIMChecks() {
	if m.enabled && m.dkimChecks != nil {
		m.dkimChecks.Inc()
	}
}

func (m *metricsService) IncrementDMARCChecks() {
	if m.enabled && m.dmarcChecks != nil {
		m.dmarcChecks.Inc()
	}
}

func (m *metricsService) IncrementAuthChecksFailed() {
	if m.enabled && m.authChecksFailed != nil {
		m.authChecksFailed.Inc()
	}
}

// Result metrics
func (m *metricsService) RecordSPFResult(result string) {
	if m.enabled && m.spfResults != nil {
		m.spfResults.WithLabelValues(result).Inc()
	}
}

func (m *metricsService) RecordDKIMResult(result string) {
	if m.enabled && m.dkimResults != nil {
		m.dkimResults.WithLabelValues(result).Inc()
	}
}

func (m *metricsService) RecordDMARCResult(result string) {
	if m.enabled && m.dmarcResults != nil {
		m.dmarcResults.WithLabelValues(result).Inc()
	}
}

func (m *metricsService) RecordDMARCPolicy(policy string) {
	if m.enabled && m.dmarcPolicies != nil {
		m.dmarcPolicies.WithLabelValues(policy).Inc()
	}
}

// Session metrics
func (m *metricsService) IncrementActiveSessions() {
	if m.enabled && m.activeSessions != nil {
		m.activeSessions.Inc()
	}
}

func (m *metricsService) DecrementActiveSessions() {
	if m.enabled && m.activeSessions != nil {
		m.activeSessions.Dec()
	}
}

// startUptimeCounter starts a goroutine that increments the uptime counter every second
func (m *metricsService) startUptimeCounter() {
	if !m.enabled || m.uptimeCounter == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for range ticker.C {
			m.uptimeCounter.Inc()
		}
	}()
}

// Close implements the MetricsService interface
func (m *metricsService) Close() error {
	// Prometheus metrics don't need explicit cleanup
	return nil
}

// MetricsHandler returns an HTTP handler for Prometheus metrics
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// HealthHandler returns an HTTP handler for health checks
func HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}
