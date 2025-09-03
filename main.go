package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/joho/godotenv"
)

var (
	listenAddr      = flag.String("listen", "0.0.0.0:25", "SMTP server listen address")
	listenAddrTLS   = flag.String("listen-tls", "0.0.0.0:587", "SMTP server listen address for TLS")
	webhookURL      = flag.String("webhook", "http://localhost:8080/webhook", "Webhook URL to send email data to")
	webhookUser     = flag.String("webhook-user", "", "Basic auth username for webhook")
	webhookPass     = flag.String("webhook-pass", "", "Basic auth password for webhook")
	serverName      = flag.String("name", "mx.inboundparse.com", "SMTP server name")
	maxMessageSize  = flag.Int64("max-size", 10*1024*1024, "Maximum message size in bytes")
	readTimeout     = flag.Int("read-timeout", 30, "Read timeout in seconds")
	writeTimeout    = flag.Int("write-timeout", 30, "Write timeout in seconds")
	enableSPF       = flag.Bool("enable-spf", true, "Enable SPF validation")
	enableDKIM      = flag.Bool("enable-dkim", true, "Enable DKIM validation")
	enableDMARC     = flag.Bool("enable-dmarc", true, "Enable DMARC validation")
	certFile        = flag.String("cert-file", "", "TLS certificate file")
	keyFile         = flag.String("key-file", "", "TLS key file")
	verbose         = flag.Bool("verbose", false, "Enable verbose logging")
	metricsAddr     = flag.String("metrics-addr", "0.0.0.0:9090", "Metrics server listen address")
	enableMetrics   = flag.Bool("enable-metrics", false, "Enable Prometheus metrics collection")
	metricsApiKey   = flag.String("metrics-api-key", "", "Metrics API key")
	metricsUsername = flag.String("metrics-username", "", "Metrics username")
	metricsPassword = flag.String("metrics-password", "", "Metrics password")
	enableSentry    = flag.Bool("enable-sentry", false, "Enable Sentry error tracking")
	sentryDSN       = flag.String("sentry-dsn", "", "Sentry DSN for error tracking")
	sentryEnv       = flag.String("sentry-env", "production", "Sentry environment (production, staging, development)")
	sentryRelease   = flag.String("sentry-release", "", "Sentry release version")
)

func loadConfig() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using default values")
	}

	flag.Parse()

	loadServerConfig()
	loadWebhookConfig()
	loadAuthConfig()
	loadMetricsConfig()
	loadSentryConfig()
}

func loadServerConfig() {
	if env := os.Getenv("LISTEN_ADDR"); env != "" {
		*listenAddr = env
	}
	if env := os.Getenv("LISTEN_ADDR_TLS"); env != "" {
		*listenAddrTLS = env
	}
	if env := os.Getenv("CERT_FILE"); env != "" {
		*certFile = env
	}
	if env := os.Getenv("KEY_FILE"); env != "" {
		*keyFile = env
	}
	if env := os.Getenv("VERBOSE"); env != "" {
		*verbose = env == "true"
	}
}

func loadWebhookConfig() {
	if env := os.Getenv("WEBHOOK_URL"); env != "" {
		*webhookURL = env
	}
	if env := os.Getenv("WEBHOOK_USER"); env != "" {
		*webhookUser = env
	}
	if env := os.Getenv("WEBHOOK_PASS"); env != "" {
		*webhookPass = env
	}
}

func loadAuthConfig() {
	if env := os.Getenv("ENABLE_SPF"); env != "" {
		*enableSPF = env == "true"
	}
	if env := os.Getenv("ENABLE_DKIM"); env != "" {
		*enableDKIM = env == "true"
	}
	if env := os.Getenv("ENABLE_DMARC"); env != "" {
		*enableDMARC = env == "true"
	}
}

func loadMetricsConfig() {
	if env := os.Getenv("METRICS_ADDR"); env != "" {
		*metricsAddr = env
	}
	if env := os.Getenv("ENABLE_METRICS"); env != "" {
		*enableMetrics = env == "true"
	}
	if env := os.Getenv("METRICS_API_KEY"); env != "" {
		*metricsApiKey = env
	}
	if env := os.Getenv("METRICS_USERNAME"); env != "" {
		*metricsUsername = env
	}
	if env := os.Getenv("METRICS_PASSWORD"); env != "" {
		*metricsPassword = env
	}
}

func loadSentryConfig() {
	if env := os.Getenv("ENABLE_SENTRY"); env != "" {
		*enableSentry = env == "true"
	}
	if env := os.Getenv("SENTRY_DSN"); env != "" {
		*sentryDSN = env
	}
	if env := os.Getenv("SENTRY_ENV"); env != "" {
		*sentryEnv = env
	}
	if env := os.Getenv("SENTRY_RELEASE"); env != "" {
		*sentryRelease = env
	}
}

func initializeMetrics() *Metrics {
	if !*enableMetrics {
		return NewMetricsDisabled()
	}

	metrics, err := NewMetrics(true)
	if err != nil {
		log.Fatal("Failed to initialize metrics:", err)
	}

	// Start metrics server
	go func() {
		mux := http.NewServeMux()

		// Add authentication middleware for metrics endpoints
		authMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// If no auth configured, allow access
				hasBasicAuth := *metricsUsername != "" && *metricsPassword != ""
				apiKey := *metricsApiKey
				hasApiKey := apiKey != ""

				// If neither auth method is configured, allow access
				if !hasBasicAuth && !hasApiKey {
					next.ServeHTTP(w, r)
					return
				}

				// Check API key first (header: X-API-Key)
				if hasApiKey {
					if reqApiKey := r.Header.Get("X-API-Key"); reqApiKey != "" {
						if reqApiKey == apiKey {
							next.ServeHTTP(w, r)
							return
						}
					}
				}

				// Check basic auth
				if hasBasicAuth {
					username, password, ok := r.BasicAuth()
					if ok && username == *webhookUser && password == *webhookPass {
						next.ServeHTTP(w, r)
						return
					}
				}

				// Authentication failed
				w.Header().Set("WWW-Authenticate", `Basic realm="Metrics"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			})
		}

		mux.Handle("/metrics", authMiddleware(MetricsHandler()))
		mux.Handle("/health", authMiddleware(HealthHandler()))

		log.Printf("Starting metrics server on %s", *metricsAddr)
		server := &http.Server{
			Addr:         *metricsAddr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
			ErrorLog:     log.New(os.Stderr, "metrics-server: ", log.LstdFlags),
		}

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	return metrics
}

func initializeSentry() {
	if !*enableSentry {
		return
	}

	if *sentryDSN == "" {
		log.Println("Sentry enabled but no DSN provided, skipping Sentry initialization")
		return
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              *sentryDSN,
		Environment:      *sentryEnv,
		Release:          *sentryRelease,
		TracesSampleRate: 0.1, // Sample 10% of transactions for performance monitoring
		Debug:            *verbose,
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			// Add custom tags
			event.Tags["service"] = "inboundparse"
			event.Tags["component"] = "smtp-server"
			return event
		},
	})
	if err != nil {
		log.Printf("Failed to initialize Sentry: %v", err)
		return
	}

	log.Printf("Sentry initialized for environment: %s", *sentryEnv)
	if *sentryRelease != "" {
		log.Printf("Sentry release: %s", *sentryRelease)
	}
}

func logServerInfo() {
	log.Printf("Starting SMTP server on %s", *listenAddr)
	if *certFile != "" && *keyFile != "" {
		log.Printf("Starting TLS SMTP server on %s", *listenAddrTLS)
	}
	log.Printf("Webhook URL: %s", *webhookURL)
	log.Printf("SPF validation: %v", *enableSPF)
	log.Printf("DKIM validation: %v", *enableDKIM)
	log.Printf("DMARC validation: %v", *enableDMARC)
	log.Printf("Verbose: %v", *verbose)
	log.Printf("Cert File: %s", *certFile)
	log.Printf("Key File: %s", *keyFile)
	if *enableMetrics {
		log.Printf("Metrics enabled on: %s", *metricsAddr)
	} else {
		log.Printf("Metrics disabled")
	}
	if *enableSentry {
		log.Printf("Sentry enabled for environment: %s", *sentryEnv)
	} else {
		log.Printf("Sentry disabled")
	}
}

func main() {
	if os.Getenv("INBOUNDPARSE_TEST_EXIT") == "1" {
		return
	}

	loadConfig()

	// Check required configuration before initializing Sentry
	if *webhookURL == "" {
		log.Fatal("Webhook URL is required. Use -webhook flag or WEBHOOK_URL environment variable")
	}

	// Initialize Sentry early to capture any startup errors
	initializeSentry()
	defer sentry.Flush(2 * time.Second)

	metrics := initializeMetrics()
	defer func() {
		if err := metrics.Close(); err != nil {
			log.Printf("Failed to close metrics: %v", err)
		}
	}()

	config := &ServerConfig{
		ListenAddr:     *listenAddr,
		ListenAddrTLS:  *listenAddrTLS,
		WebhookURL:     *webhookURL,
		WebhookUser:    *webhookUser,
		WebhookPass:    *webhookPass,
		ServerName:     *serverName,
		MaxMessageSize: *maxMessageSize,
		ReadTimeout:    *readTimeout,
		WriteTimeout:   *writeTimeout,
		EnableSPF:      *enableSPF,
		EnableDKIM:     *enableDKIM,
		EnableDMARC:    *enableDMARC,
		Verbose:        *verbose,
		CertFile:       *certFile,
		KeyFile:        *keyFile,
		Metrics:        metrics,
	}

	server, err := NewSMTPServer(config)
	if err != nil {
		log.Printf("Failed to initialize SMTP server: %v", err)
		return
	}

	logServerInfo()

	if err := server.Start(); err != nil {
		log.Printf("Failed to start SMTP server: %v", err)
		return
	}
}
