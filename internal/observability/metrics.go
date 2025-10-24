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
	webhookRequests *prometheus.CounterVec
	webhookDuration prometheus.Histogram
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
