package observability

import (
	"context"
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	EnableMetrics   bool
	MetricsAddr     string
	MetricsAPIKey   string
	MetricsUsername string
	MetricsPassword string
}

// MetricsCollector interface for metrics collection
type MetricsCollector interface {
	TrackConnection() func()
	TrackSession() func()
	TrackMessage(size int64, success bool)
	TrackSPFResult(result string)
	TrackDKIMResult(valid bool)
	TrackDMARCResult(result, policy string)
	TrackWebhookRequest(statusCode int, duration time.Duration)
	TrackWebhookRequestSize(requestSize, responseSize int64)
	TrackWebhookRetry(success bool)
	TrackWebhookError(errorType string)
	TrackSPFDuration(duration time.Duration)
	TrackDKIMDuration(duration time.Duration)
	TrackDMARCDuration(duration time.Duration)
	TrackSPFResultByDomain(domain, result string)
	TrackDKIMResultByDomain(domain, result string)
	TrackDMARCResultByDomain(domain, result string)
	TrackAuthError(checkType, errorType string)
	TrackMessageReadDuration(duration time.Duration)
	TrackMessageParseDuration(duration time.Duration)
	TrackMessageAuthDuration(duration time.Duration)
	TrackMessageWebhookDuration(duration time.Duration)
	TrackMessageTotalProcessingDuration(duration time.Duration)

	// Email characteristics metrics
	TrackEmailAttachmentCount(count int)
	TrackEmailAttachmentSize(size int64)
	TrackEmailBodyType(bodyType string)
	TrackEmailHeaderCount(count int)
	TrackEmailRecipientCount(count int)

	// Session lifecycle metrics
	TrackSessionDuration(duration time.Duration)
	TrackSessionCommandCount(command string)
	TrackSessionErrorCount(errorType string)
	TrackSessionMessageCount()
}

// MetricsServer manages the Prometheus metrics HTTP server
type MetricsServer interface {
	Start() error
	Stop(ctx context.Context) error
}

// metricsCollector implements MetricsCollector interface
type metricsCollector struct {
	// Connection metrics
	smtpConnectionsTotal   prometheus.Counter
	smtpConnectionsActive  prometheus.Gauge
	smtpActiveSessions     prometheus.Gauge
	smtpConnectionDuration prometheus.Histogram

	// Message metrics
	smtpMessagesTotal     prometheus.Counter
	smtpMessagesProcessed *prometheus.CounterVec
	smtpMessagesFailed    prometheus.Counter
	smtpMessageSize       prometheus.Histogram

	// Authentication metrics
	spfResults      *prometheus.CounterVec
	dkimResults     *prometheus.CounterVec
	dmarcResults    *prometheus.CounterVec
	dmarcPolicies   *prometheus.CounterVec
	authChecksSPF   prometheus.Counter
	authChecksDKIM  prometheus.Counter
	authChecksDMARC prometheus.Counter

	// Webhook metrics
	webhookRequests     *prometheus.CounterVec
	webhookDuration     prometheus.Histogram
	webhookRequestSize  prometheus.Histogram
	webhookResponseSize prometheus.Histogram
	webhookRetries      *prometheus.CounterVec
	webhookErrors       *prometheus.CounterVec

	// Authentication duration metrics
	spfDuration   prometheus.Histogram
	dkimDuration  prometheus.Histogram
	dmarcDuration prometheus.Histogram

	// Domain-based authentication metrics
	spfResultsByDomain   *prometheus.CounterVec
	dkimResultsByDomain  *prometheus.CounterVec
	dmarcResultsByDomain *prometheus.CounterVec

	// Authentication error metrics
	authErrors *prometheus.CounterVec

	// Message processing stage metrics
	messageReadDuration    prometheus.Histogram
	messageParseDuration   prometheus.Histogram
	messageAuthDuration    prometheus.Histogram
	messageWebhookDuration prometheus.Histogram
	messageTotalDuration   prometheus.Histogram

	// Email characteristics metrics
	emailAttachmentCount prometheus.Histogram
	emailAttachmentSize  prometheus.Histogram
	emailBodyType        *prometheus.CounterVec
	emailHeaderCount     prometheus.Histogram
	emailRecipientCount  prometheus.Histogram

	// Session lifecycle metrics
	sessionDuration     prometheus.Histogram
	sessionCommands     *prometheus.CounterVec
	sessionErrors       *prometheus.CounterVec
	sessionMessageCount prometheus.Counter
}

var (
	defaultMetricsOnce sync.Once
	defaultMetrics     MetricsCollector
)

// NewMetricsCollector creates a new metrics collector using the default Prometheus registry.
// This function uses sync.Once to ensure metrics are only registered once globally.
// For tests or when you need isolated metrics, use NewMetricsCollectorWithRegistry instead.
func NewMetricsCollector() MetricsCollector {
	defaultMetricsOnce.Do(func() {
		defaultMetrics = newMetricsCollectorWithFactory(promauto.Factory{})
	})
	return defaultMetrics
}

// NewMetricsCollectorWithRegistry creates a new metrics collector using a custom Prometheus registry.
// This is useful for testing to avoid duplicate registration errors.
func NewMetricsCollectorWithRegistry(registry *prometheus.Registry) MetricsCollector {
	factory := promauto.With(registry)
	return newMetricsCollectorWithFactory(factory)
}

// newMetricsCollectorWithFactory creates a metrics collector using the provided factory.
// This is an internal helper function used by both NewMetricsCollector and NewMetricsCollectorWithRegistry.
func newMetricsCollectorWithFactory(factory promauto.Factory) MetricsCollector {
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
			Help: "Total number of SMTP messages received",
		}),
		smtpMessagesProcessed: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "smtp_messages_processed_total",
			Help: "Total number of SMTP messages processed by status",
		}, []string{"status"}),
		smtpMessagesFailed: factory.NewCounter(prometheus.CounterOpts{
			Name: "smtp_messages_failed_total",
			Help: "Total number of failed SMTP messages",
		}),
		smtpMessageSize: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "smtp_message_size_bytes",
			Help:    "Size of SMTP messages in bytes",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600},
		}),

		// Authentication metrics
		spfResults: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "spf_results_total",
			Help: "Total SPF validation results",
		}, []string{"result"}),
		dkimResults: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim_results_total",
			Help: "Total DKIM validation results",
		}, []string{"result"}),
		dmarcResults: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dmarc_results_total",
			Help: "Total DMARC validation results",
		}, []string{"result"}),
		dmarcPolicies: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dmarc_policies_total",
			Help: "Total DMARC policies observed",
		}, []string{"policy"}),
		authChecksSPF: factory.NewCounter(prometheus.CounterOpts{
			Name: "auth_checks_spf_total",
			Help: "Total SPF authentication checks performed",
		}),
		authChecksDKIM: factory.NewCounter(prometheus.CounterOpts{
			Name: "auth_checks_dkim_total",
			Help: "Total DKIM authentication checks performed",
		}),
		authChecksDMARC: factory.NewCounter(prometheus.CounterOpts{
			Name: "auth_checks_dmarc_total",
			Help: "Total DMARC authentication checks performed",
		}),

		// Webhook metrics
		webhookRequests: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_requests_total",
			Help: "Total webhook requests by status code",
		}, []string{"status_code"}),
		webhookDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "webhook_duration_seconds",
			Help:    "Duration of webhook requests in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		webhookRequestSize: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "webhook_request_size_bytes",
			Help:    "Size of webhook request payloads in bytes",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600},
		}),
		webhookResponseSize: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "webhook_response_size_bytes",
			Help:    "Size of webhook response payloads in bytes",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600},
		}),
		webhookRetries: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_retry_attempts_total",
			Help: "Total webhook retry attempts",
		}, []string{"success"}),
		webhookErrors: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_errors_total",
			Help: "Total webhook errors by type",
		}, []string{"error_type"}),

		// Authentication duration metrics
		spfDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "spf_check_duration_seconds",
			Help:    "Duration of SPF authentication checks in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		dkimDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "dkim_check_duration_seconds",
			Help:    "Duration of DKIM authentication checks in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		dmarcDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "dmarc_check_duration_seconds",
			Help:    "Duration of DMARC authentication checks in seconds",
			Buckets: prometheus.DefBuckets,
		}),

		// Domain-based authentication metrics
		spfResultsByDomain: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "spf_results_by_domain_total",
			Help: "SPF authentication results by domain",
		}, []string{"domain", "result"}),
		dkimResultsByDomain: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim_results_by_domain_total",
			Help: "DKIM authentication results by domain",
		}, []string{"domain", "result"}),
		dmarcResultsByDomain: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "dmarc_results_by_domain_total",
			Help: "DMARC authentication results by domain",
		}, []string{"domain", "result"}),

		// Authentication error metrics
		authErrors: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_errors_total",
			Help: "Authentication errors by check type and error type",
		}, []string{"check_type", "error_type"}),

		// Message processing stage metrics
		messageReadDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "message_read_duration_seconds",
			Help:    "Duration of message reading stage in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		messageParseDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "message_parse_duration_seconds",
			Help:    "Duration of message parsing stage in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		messageAuthDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "message_auth_duration_seconds",
			Help:    "Duration of message authentication stage in seconds",
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

// TrackConnection increments connection metrics
func (m *metricsCollector) TrackConnection() func() {
	m.smtpConnectionsTotal.Inc()
	m.smtpConnectionsActive.Inc()
	start := time.Now()

	return func() {
		m.smtpConnectionsActive.Dec()
		m.smtpConnectionDuration.Observe(time.Since(start).Seconds())
	}
}

// TrackSession increments session metrics
func (m *metricsCollector) TrackSession() func() {
	m.smtpActiveSessions.Inc()
	return func() {
		m.smtpActiveSessions.Dec()
	}
}

// TrackMessage records message metrics
func (m *metricsCollector) TrackMessage(size int64, success bool) {
	m.smtpMessagesTotal.Inc()
	m.smtpMessageSize.Observe(float64(size))

	if success {
		m.smtpMessagesProcessed.WithLabelValues("success").Inc()
	} else {
		m.smtpMessagesProcessed.WithLabelValues("failure").Inc()
		m.smtpMessagesFailed.Inc()
	}
}

// TrackSPFResult records SPF validation result
func (m *metricsCollector) TrackSPFResult(result string) {
	m.authChecksSPF.Inc()
	m.spfResults.WithLabelValues(result).Inc()
}

// TrackDKIMResult records DKIM validation result
func (m *metricsCollector) TrackDKIMResult(valid bool) {
	m.authChecksDKIM.Inc()
	if valid {
		m.dkimResults.WithLabelValues("pass").Inc()
	} else {
		m.dkimResults.WithLabelValues("fail").Inc()
	}
}

// TrackDMARCResult records DMARC validation result and policy
func (m *metricsCollector) TrackDMARCResult(result, policy string) {
	m.authChecksDMARC.Inc()
	m.dmarcResults.WithLabelValues(result).Inc()
	if policy != "" {
		m.dmarcPolicies.WithLabelValues(policy).Inc()
	}
}

// TrackWebhookRequest records webhook request metrics
func (m *metricsCollector) TrackWebhookRequest(statusCode int, duration time.Duration) {
	m.webhookRequests.WithLabelValues(http.StatusText(statusCode)).Inc()
	m.webhookDuration.Observe(duration.Seconds())
}

// TrackWebhookRequestSize records webhook request and response size metrics
func (m *metricsCollector) TrackWebhookRequestSize(requestSize, responseSize int64) {
	m.webhookRequestSize.Observe(float64(requestSize))
	m.webhookResponseSize.Observe(float64(responseSize))
}

// TrackWebhookRetry records webhook retry attempts
func (m *metricsCollector) TrackWebhookRetry(success bool) {
	status := "failure"
	if success {
		status = "success"
	}
	m.webhookRetries.WithLabelValues(status).Inc()
}

// TrackWebhookError records webhook errors by type
func (m *metricsCollector) TrackWebhookError(errorType string) {
	m.webhookErrors.WithLabelValues(errorType).Inc()
}

// TrackSPFDuration records SPF check duration
func (m *metricsCollector) TrackSPFDuration(duration time.Duration) {
	m.spfDuration.Observe(duration.Seconds())
}

// TrackDKIMDuration records DKIM check duration
func (m *metricsCollector) TrackDKIMDuration(duration time.Duration) {
	m.dkimDuration.Observe(duration.Seconds())
}

// TrackDMARCDuration records DMARC check duration
func (m *metricsCollector) TrackDMARCDuration(duration time.Duration) {
	m.dmarcDuration.Observe(duration.Seconds())
}

// TrackSPFResultByDomain records SPF results by domain
func (m *metricsCollector) TrackSPFResultByDomain(domain, result string) {
	m.spfResultsByDomain.WithLabelValues(domain, result).Inc()
}

// TrackDKIMResultByDomain records DKIM results by domain
func (m *metricsCollector) TrackDKIMResultByDomain(domain, result string) {
	m.dkimResultsByDomain.WithLabelValues(domain, result).Inc()
}

// TrackDMARCResultByDomain records DMARC results by domain
func (m *metricsCollector) TrackDMARCResultByDomain(domain, result string) {
	m.dmarcResultsByDomain.WithLabelValues(domain, result).Inc()
}

// TrackAuthError records authentication errors by check type and error type
func (m *metricsCollector) TrackAuthError(checkType, errorType string) {
	m.authErrors.WithLabelValues(checkType, errorType).Inc()
}

// TrackMessageReadDuration records message reading stage duration
func (m *metricsCollector) TrackMessageReadDuration(duration time.Duration) {
	m.messageReadDuration.Observe(duration.Seconds())
}

// TrackMessageParseDuration records message parsing stage duration
func (m *metricsCollector) TrackMessageParseDuration(duration time.Duration) {
	m.messageParseDuration.Observe(duration.Seconds())
}

// TrackMessageAuthDuration records message authentication stage duration
func (m *metricsCollector) TrackMessageAuthDuration(duration time.Duration) {
	m.messageAuthDuration.Observe(duration.Seconds())
}

// TrackMessageWebhookDuration records message webhook stage duration
func (m *metricsCollector) TrackMessageWebhookDuration(duration time.Duration) {
	m.messageWebhookDuration.Observe(duration.Seconds())
}

// TrackMessageTotalProcessingDuration records total message processing duration
func (m *metricsCollector) TrackMessageTotalProcessingDuration(duration time.Duration) {
	m.messageTotalDuration.Observe(duration.Seconds())
}

// TrackEmailAttachmentCount records the number of attachments in an email
func (m *metricsCollector) TrackEmailAttachmentCount(count int) {
	m.emailAttachmentCount.Observe(float64(count))
}

// TrackEmailAttachmentSize records the size of email attachments
func (m *metricsCollector) TrackEmailAttachmentSize(size int64) {
	m.emailAttachmentSize.Observe(float64(size))
}

// TrackEmailBodyType records the body type of emails
func (m *metricsCollector) TrackEmailBodyType(bodyType string) {
	m.emailBodyType.WithLabelValues(bodyType).Inc()
}

// TrackEmailHeaderCount records the number of headers in an email
func (m *metricsCollector) TrackEmailHeaderCount(count int) {
	m.emailHeaderCount.Observe(float64(count))
}

// TrackEmailRecipientCount records the number of recipients in an email
func (m *metricsCollector) TrackEmailRecipientCount(count int) {
	m.emailRecipientCount.Observe(float64(count))
}

// TrackSessionDuration records the duration of SMTP sessions
func (m *metricsCollector) TrackSessionDuration(duration time.Duration) {
	m.sessionDuration.Observe(duration.Seconds())
}

// TrackSessionCommandCount records the number of SMTP commands executed
func (m *metricsCollector) TrackSessionCommandCount(command string) {
	m.sessionCommands.WithLabelValues(command).Inc()
}

// TrackSessionErrorCount records the number of SMTP session errors by type
func (m *metricsCollector) TrackSessionErrorCount(errorType string) {
	m.sessionErrors.WithLabelValues(errorType).Inc()
}

// TrackSessionMessageCount records the number of messages processed per session
func (m *metricsCollector) TrackSessionMessageCount() {
	m.sessionMessageCount.Inc()
}

// metricsServer implements MetricsServer interface
type metricsServer struct {
	server *http.Server
	config MetricsConfig
}

// NewMetricsServer creates a new metrics server
func NewMetricsServer(config MetricsConfig) MetricsServer {
	return &metricsServer{
		config: config,
	}
}

// Start starts the metrics HTTP server
func (m *metricsServer) Start() error {
	if !m.config.EnableMetrics {
		return nil
	}

	mux := http.NewServeMux()

	// Health endpoint (unauthenticated)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			// Log error but don't fail the request - this is expected behavior
			_ = err
		}
	})

	// Metrics endpoint (authenticated)
	metricsHandler := promhttp.Handler()
	mux.Handle("/metrics", m.authMiddleware(metricsHandler))

	m.server = &http.Server{
		Addr:         m.config.MetricsAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics server: ListenAndServe: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the metrics server
func (m *metricsServer) Stop(ctx context.Context) error {
	if m.server == nil {
		return nil
	}

	return m.server.Shutdown(ctx)
}

// metricsAddrAllowsUnauthenticatedMetrics is true only for loopback binds where
// open /metrics is acceptable (local development and unit tests).
func metricsAddrAllowsUnauthenticatedMetrics(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func constantTimeEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// authMiddleware provides authentication for the metrics endpoint
func (m *metricsServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasBearer := m.config.MetricsAPIKey != ""
		hasBasic := m.config.MetricsUsername != "" && m.config.MetricsPassword != ""

		if !hasBearer && !hasBasic {
			if metricsAddrAllowsUnauthenticatedMetrics(m.config.MetricsAddr) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		authenticated := false

		// Check Bearer token authentication
		if hasBearer {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
					token := strings.TrimSpace(parts[1])
					if constantTimeEqualString(token, m.config.MetricsAPIKey) {
						authenticated = true
					}
				}
			}
		}

		// Check Basic authentication
		if !authenticated && hasBasic {
			username, password, ok := r.BasicAuth()
			if ok && username == m.config.MetricsUsername &&
				constantTimeEqualString(password, m.config.MetricsPassword) {
				authenticated = true
			}
		}

		if !authenticated {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// NoOpMetricsCollector is a no-op implementation of MetricsCollector
type NoOpMetricsCollector struct{}

// TrackConnection returns a no-op function
func (n *NoOpMetricsCollector) TrackConnection() func() {
	return func() {}
}

// TrackSession returns a no-op function
func (n *NoOpMetricsCollector) TrackSession() func() {
	return func() {}
}

// TrackMessage does nothing
func (n *NoOpMetricsCollector) TrackMessage(size int64, success bool) {}

// TrackSPFResult does nothing
func (n *NoOpMetricsCollector) TrackSPFResult(result string) {}

// TrackDKIMResult does nothing
func (n *NoOpMetricsCollector) TrackDKIMResult(valid bool) {}

// TrackDMARCResult does nothing
func (n *NoOpMetricsCollector) TrackDMARCResult(result, policy string) {}

// TrackWebhookRequest does nothing
func (n *NoOpMetricsCollector) TrackWebhookRequest(status int, duration time.Duration) {}

// TrackWebhookRequestSize does nothing
func (n *NoOpMetricsCollector) TrackWebhookRequestSize(requestSize, responseSize int64) {}

// TrackWebhookRetry does nothing
func (n *NoOpMetricsCollector) TrackWebhookRetry(success bool) {}

// TrackWebhookError does nothing
func (n *NoOpMetricsCollector) TrackWebhookError(errorType string) {}

// TrackSPFDuration does nothing
func (n *NoOpMetricsCollector) TrackSPFDuration(duration time.Duration) {}

// TrackDKIMDuration does nothing
func (n *NoOpMetricsCollector) TrackDKIMDuration(duration time.Duration) {}

// TrackDMARCDuration does nothing
func (n *NoOpMetricsCollector) TrackDMARCDuration(duration time.Duration) {}

// TrackSPFResultByDomain does nothing
func (n *NoOpMetricsCollector) TrackSPFResultByDomain(domain, result string) {}

// TrackDKIMResultByDomain does nothing
func (n *NoOpMetricsCollector) TrackDKIMResultByDomain(domain, result string) {}

// TrackDMARCResultByDomain does nothing
func (n *NoOpMetricsCollector) TrackDMARCResultByDomain(domain, result string) {}

// TrackAuthError does nothing
func (n *NoOpMetricsCollector) TrackAuthError(checkType, errorType string) {}

// TrackMessageReadDuration does nothing
func (n *NoOpMetricsCollector) TrackMessageReadDuration(duration time.Duration) {}

// TrackMessageParseDuration does nothing
func (n *NoOpMetricsCollector) TrackMessageParseDuration(duration time.Duration) {}

// TrackMessageAuthDuration does nothing
func (n *NoOpMetricsCollector) TrackMessageAuthDuration(duration time.Duration) {}

// TrackMessageWebhookDuration does nothing
func (n *NoOpMetricsCollector) TrackMessageWebhookDuration(duration time.Duration) {}

// TrackMessageTotalProcessingDuration does nothing
func (n *NoOpMetricsCollector) TrackMessageTotalProcessingDuration(duration time.Duration) {}

// TrackEmailAttachmentCount does nothing
func (n *NoOpMetricsCollector) TrackEmailAttachmentCount(count int) {}

// TrackEmailAttachmentSize does nothing
func (n *NoOpMetricsCollector) TrackEmailAttachmentSize(size int64) {}

// TrackEmailBodyType does nothing
func (n *NoOpMetricsCollector) TrackEmailBodyType(bodyType string) {}

// TrackEmailHeaderCount does nothing
func (n *NoOpMetricsCollector) TrackEmailHeaderCount(count int) {}

// TrackEmailRecipientCount does nothing
func (n *NoOpMetricsCollector) TrackEmailRecipientCount(count int) {}

// TrackSessionDuration does nothing
func (n *NoOpMetricsCollector) TrackSessionDuration(duration time.Duration) {}

// TrackSessionCommandCount does nothing
func (n *NoOpMetricsCollector) TrackSessionCommandCount(command string) {}

// TrackSessionErrorCount does nothing
func (n *NoOpMetricsCollector) TrackSessionErrorCount(errorType string) {}

// TrackSessionMessageCount does nothing
func (n *NoOpMetricsCollector) TrackSessionMessageCount() {}
