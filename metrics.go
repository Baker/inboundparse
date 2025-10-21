package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

var (
	// Connection metrics
	smtpConnectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_connections_total",
		Help: "Total number of SMTP connections",
	})

	smtpConnectionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "smtp_connections_active",
		Help: "Number of active SMTP connections",
	})

	smtpActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "smtp_active_sessions",
		Help: "Number of active SMTP sessions",
	})

	smtpConnectionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "smtp_connection_duration_seconds",
		Help:    "Duration of SMTP connections in seconds",
		Buckets: prometheus.DefBuckets,
	})

	// Message metrics
	smtpMessagesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_messages_total",
		Help: "Total number of SMTP messages received",
	})

	smtpMessagesProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "smtp_messages_processed_total",
		Help: "Total number of SMTP messages processed by status",
	}, []string{"status"})

	smtpMessagesFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "smtp_messages_failed_total",
		Help: "Total number of failed SMTP messages",
	})

	smtpMessageSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "smtp_message_size_bytes",
		Help:    "Size of SMTP messages in bytes",
		Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600},
	})

	// Authentication metrics
	spfResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "spf_results_total",
		Help: "Total SPF validation results",
	}, []string{"result"})

	dkimResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dkim_results_total",
		Help: "Total DKIM validation results",
	}, []string{"result"})

	dmarcResults = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dmarc_results_total",
		Help: "Total DMARC validation results",
	}, []string{"result"})

	dmarcPolicies = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dmarc_policies_total",
		Help: "Total DMARC policies observed",
	}, []string{"policy"})

	authChecksSPF = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_checks_spf_total",
		Help: "Total SPF authentication checks performed",
	})

	authChecksDKIM = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_checks_dkim_total",
		Help: "Total DKIM authentication checks performed",
	})

	authChecksDMARC = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_checks_dmarc_total",
		Help: "Total DMARC authentication checks performed",
	})

	// Webhook metrics
	webhookRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "webhook_requests_total",
		Help: "Total webhook requests by status code",
	}, []string{"status_code"})

	webhookDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "webhook_duration_seconds",
		Help:    "Duration of webhook requests in seconds",
		Buckets: prometheus.DefBuckets,
	})
)

// MetricsServer manages the Prometheus metrics HTTP server
type MetricsServer struct {
	server *http.Server
	config *ServerConfig
}

// NewMetricsServer creates a new metrics server
func NewMetricsServer(config *ServerConfig) *MetricsServer {
	return &MetricsServer{
		config: config,
	}
}

// Start starts the metrics HTTP server
func (m *MetricsServer) Start() error {
	if !m.config.EnableMetrics {
		return nil
	}

	mux := http.NewServeMux()

	// Health endpoint (unauthenticated)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			log.Warn().Err(err).Msg("Failed to write health response")
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

	log.Info().
		Str("address", m.config.MetricsAddr).
		Msg("Starting Prometheus metrics server")

	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Metrics server error")
		}
	}()

	return nil
}

// Stop gracefully stops the metrics server
func (m *MetricsServer) Stop(ctx context.Context) error {
	if m.server == nil {
		return nil
	}

	log.Info().Msg("Stopping metrics server")
	return m.server.Shutdown(ctx)
}

// authMiddleware provides authentication for the metrics endpoint
func (m *MetricsServer) authMiddleware(next http.Handler) http.Handler {
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
			log.Warn().
				Str("remote_addr", r.RemoteAddr).
				Str("path", r.URL.Path).
				Msg("Unauthorized metrics access attempt")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Metrics tracking helpers

// TrackConnection increments connection metrics
func TrackConnection() func() {
	smtpConnectionsTotal.Inc()
	smtpConnectionsActive.Inc()
	start := time.Now()

	return func() {
		smtpConnectionsActive.Dec()
		smtpConnectionDuration.Observe(time.Since(start).Seconds())
	}
}

// TrackSession increments session metrics
func TrackSession() func() {
	smtpActiveSessions.Inc()
	return func() {
		smtpActiveSessions.Dec()
	}
}

// TrackMessage records message metrics
func TrackMessage(size int64, success bool) {
	smtpMessagesTotal.Inc()
	smtpMessageSize.Observe(float64(size))

	if success {
		smtpMessagesProcessed.WithLabelValues("success").Inc()
	} else {
		smtpMessagesProcessed.WithLabelValues("failure").Inc()
		smtpMessagesFailed.Inc()
	}
}

// TrackSPFResult records SPF validation result
func TrackSPFResult(result string) {
	authChecksSPF.Inc()
	spfResults.WithLabelValues(result).Inc()
}

// TrackDKIMResult records DKIM validation result
func TrackDKIMResult(valid bool) {
	authChecksDKIM.Inc()
	if valid {
		dkimResults.WithLabelValues("pass").Inc()
	} else {
		dkimResults.WithLabelValues("fail").Inc()
	}
}

// TrackDMARCResult records DMARC validation result and policy
func TrackDMARCResult(result, policy string) {
	authChecksDMARC.Inc()
	dmarcResults.WithLabelValues(result).Inc()
	if policy != "" {
		dmarcPolicies.WithLabelValues(policy).Inc()
	}
}

// TrackWebhookRequest records webhook request metrics
func TrackWebhookRequest(statusCode int, duration time.Duration) {
	webhookRequests.WithLabelValues(http.StatusText(statusCode)).Inc()
	webhookDuration.Observe(duration.Seconds())
}
