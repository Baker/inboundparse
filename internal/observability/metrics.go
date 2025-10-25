package observability

import (
	"context"
	"net/http"
	"strings"
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
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() MetricsCollector {
	return &metricsCollector{
		// Connection metrics
		smtpConnectionsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "smtp_connections_total",
			Help: "Total number of SMTP connections",
		}),
		smtpConnectionsActive: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "smtp_connections_active",
			Help: "Number of active SMTP connections",
		}),
		smtpActiveSessions: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "smtp_active_sessions",
			Help: "Number of active SMTP sessions",
		}),
		smtpConnectionDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "smtp_connection_duration_seconds",
			Help:    "Duration of SMTP connections in seconds",
			Buckets: prometheus.DefBuckets,
		}),

		// Message metrics
		smtpMessagesTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "smtp_messages_total",
			Help: "Total number of SMTP messages received",
		}),
		smtpMessagesProcessed: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "smtp_messages_processed_total",
			Help: "Total number of SMTP messages processed by status",
		}, []string{"status"}),
		smtpMessagesFailed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "smtp_messages_failed_total",
			Help: "Total number of failed SMTP messages",
		}),
		smtpMessageSize: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "smtp_message_size_bytes",
			Help:    "Size of SMTP messages in bytes",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600},
		}),

		// Authentication metrics
		spfResults: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "spf_results_total",
			Help: "Total SPF validation results",
		}, []string{"result"}),
		dkimResults: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim_results_total",
			Help: "Total DKIM validation results",
		}, []string{"result"}),
		dmarcResults: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "dmarc_results_total",
			Help: "Total DMARC validation results",
		}, []string{"result"}),
		dmarcPolicies: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "dmarc_policies_total",
			Help: "Total DMARC policies observed",
		}, []string{"policy"}),
		authChecksSPF: promauto.NewCounter(prometheus.CounterOpts{
			Name: "auth_checks_spf_total",
			Help: "Total SPF authentication checks performed",
		}),
		authChecksDKIM: promauto.NewCounter(prometheus.CounterOpts{
			Name: "auth_checks_dkim_total",
			Help: "Total DKIM authentication checks performed",
		}),
		authChecksDMARC: promauto.NewCounter(prometheus.CounterOpts{
			Name: "auth_checks_dmarc_total",
			Help: "Total DMARC authentication checks performed",
		}),

		// Webhook metrics
		webhookRequests: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_requests_total",
			Help: "Total webhook requests by status code",
		}, []string{"status_code"}),
		webhookDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "webhook_duration_seconds",
			Help:    "Duration of webhook requests in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		webhookRequestSize: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "webhook_request_size_bytes",
			Help:    "Size of webhook request payloads in bytes",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600},
		}),
		webhookResponseSize: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "webhook_response_size_bytes",
			Help:    "Size of webhook response payloads in bytes",
			Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600},
		}),
		webhookRetries: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_retry_attempts_total",
			Help: "Total webhook retry attempts",
		}, []string{"success"}),
		webhookErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "webhook_errors_total",
			Help: "Total webhook errors by type",
		}, []string{"error_type"}),

		// Authentication duration metrics
		spfDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "spf_check_duration_seconds",
			Help:    "Duration of SPF authentication checks in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		dkimDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "dkim_check_duration_seconds",
			Help:    "Duration of DKIM authentication checks in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		dmarcDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "dmarc_check_duration_seconds",
			Help:    "Duration of DMARC authentication checks in seconds",
			Buckets: prometheus.DefBuckets,
		}),

		// Domain-based authentication metrics
		spfResultsByDomain: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "spf_results_by_domain_total",
			Help: "SPF authentication results by domain",
		}, []string{"domain", "result"}),
		dkimResultsByDomain: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "dkim_results_by_domain_total",
			Help: "DKIM authentication results by domain",
		}, []string{"domain", "result"}),
		dmarcResultsByDomain: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "dmarc_results_by_domain_total",
			Help: "DMARC authentication results by domain",
		}, []string{"domain", "result"}),

		// Authentication error metrics
		authErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_errors_total",
			Help: "Authentication errors by check type and error type",
		}, []string{"check_type", "error_type"}),
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
			// Log error but don't fail the application - this is expected behavior
			_ = err
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

// authMiddleware provides authentication for the metrics endpoint
func (m *metricsServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If no authentication is configured, allow access
		if m.config.MetricsAPIKey == "" && m.config.MetricsUsername == "" {
			next.ServeHTTP(w, r)
			return
		}

		authenticated := false

		// Check Bearer token authentication
		if m.config.MetricsAPIKey != "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && parts[0] == "Bearer" {
					if parts[1] == m.config.MetricsAPIKey {
						authenticated = true
					}
				}
			}
		}

		// Check Basic authentication
		if !authenticated && m.config.MetricsUsername != "" && m.config.MetricsPassword != "" {
			username, password, ok := r.BasicAuth()
			if ok && username == m.config.MetricsUsername && password == m.config.MetricsPassword {
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
