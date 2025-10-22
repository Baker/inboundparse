package main

import (
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog/log"
)

// InitSentry initializes Sentry error tracking
func InitSentry(config *ServerConfig) error {
	if !config.EnableSentry {
		return nil
	}

	if config.SentryDSN == "" {
		log.Warn().Msg("Sentry enabled but no DSN provided, skipping initialization")
		return nil
	}

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
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize Sentry")
		return err
	}

	log.Info().
		Str("environment", config.SentryEnv).
		Str("release", config.SentryRelease).
		Msg("Sentry error tracking initialized")

	return nil
}

// FlushSentry flushes any pending Sentry events
func FlushSentry() {
	sentry.Flush(2 * time.Second)
}

// CaptureError sends an error to Sentry with optional context
func CaptureError(err error, context map[string]interface{}) {
	if err == nil {
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
func CaptureMessage(message string, level sentry.Level, context map[string]interface{}) {
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
func RecoverWithSentry() {
	if err := recover(); err != nil {
		sentry.CurrentHub().Recover(err)
		sentry.Flush(2 * time.Second)
		panic(err) // Re-panic after capturing
	}
}
