package observability

import (
	"time"

	"github.com/getsentry/sentry-go"
)

// SentryConfig holds Sentry configuration
type SentryConfig struct {
	EnableSentry  bool
	SentryDSN     string
	SentryEnv     string
	SentryRelease string
}

// SentryClient interface for error tracking
type SentryClient interface {
	Init(config SentryConfig) error
	Flush()
	CaptureError(err error, context map[string]interface{})
	CaptureMessage(message string, level sentry.Level, context map[string]interface{})
	RecoverWithSentry()
}

// sentryClient implements SentryClient interface
type sentryClient struct {
	enabled bool
}

// NewSentryClient creates a new Sentry client
func NewSentryClient() SentryClient {
	return &sentryClient{}
}

// Init initializes Sentry error tracking
func (s *sentryClient) Init(config SentryConfig) error {
	if !config.EnableSentry {
		return nil
	}

	if config.SentryDSN == "" {
		return nil // Silently skip if no DSN provided
	}

	s.enabled = true

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              config.SentryDSN,
		Environment:      config.SentryEnv,
		Release:          config.SentryRelease,
		AttachStacktrace: true,
		TracesSampleRate: 0.1, // Sample 10% of transactions for performance monitoring
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			// Filter out test events if needed
			return event
		},
	})

	return err
}

// Flush flushes any pending Sentry events
func (s *sentryClient) Flush() {
	if s.enabled {
		sentry.Flush(2 * time.Second)
	}
}

// CaptureError sends an error to Sentry with optional context
func (s *sentryClient) CaptureError(err error, context map[string]interface{}) {
	if !s.enabled || err == nil {
		return
	}

	hub := sentry.CurrentHub()
	hub.WithScope(func(scope *sentry.Scope) {
		// Add context to the scope as extras
		for key, value := range context {
			scope.SetExtra(key, value)
		}
		hub.CaptureException(err)
	})
}

// CaptureMessage sends a message to Sentry with optional context
func (s *sentryClient) CaptureMessage(message string, level sentry.Level, context map[string]interface{}) {
	if !s.enabled {
		return
	}

	hub := sentry.CurrentHub()
	hub.WithScope(func(scope *sentry.Scope) {
		scope.SetLevel(level)
		for key, value := range context {
			scope.SetExtra(key, value)
		}
		hub.CaptureMessage(message)
	})
}

// RecoverWithSentry recovers from panics and sends them to Sentry
func (s *sentryClient) RecoverWithSentry() {
	if !s.enabled {
		return
	}

	if err := recover(); err != nil {
		sentry.CurrentHub().Recover(err)
		sentry.Flush(2 * time.Second)
		panic(err) // Re-panic after capturing
	}
}
