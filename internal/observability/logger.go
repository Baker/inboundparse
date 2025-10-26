package observability

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logger interface for structured logging
type Logger interface {
	Debug() *zerolog.Event
	Info() *zerolog.Event
	Warn() *zerolog.Event
	Error() *zerolog.Event
	Fatal() *zerolog.Event
	With() zerolog.Context
}

// LoggerConfig holds logger configuration
type LoggerConfig struct {
	Verbose bool
}

// NewLogger creates a new structured logger
func NewLogger(config LoggerConfig) Logger {
	// Configure zerolog for human-readable output in development
	// and JSON in production
	zerolog.TimeFieldFormat = time.RFC3339

	// Set log level based on verbose flag
	if config.Verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Always use JSON format for structured logging
	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "inboundparse").
		Logger()

	// Set the global logger
	log.Logger = logger

	return &logger
}

// DefaultLogger returns a default logger instance
func DefaultLogger() Logger {
	return NewLogger(LoggerConfig{Verbose: false})
}

// sessionLoggerWrapper wraps zerolog.Logger to implement observability.Logger interface
type sessionLoggerWrapper struct {
	logger zerolog.Logger
}

func (w *sessionLoggerWrapper) Debug() *zerolog.Event {
	return w.logger.Debug()
}

func (w *sessionLoggerWrapper) Info() *zerolog.Event {
	return w.logger.Info()
}

func (w *sessionLoggerWrapper) Warn() *zerolog.Event {
	return w.logger.Warn()
}

func (w *sessionLoggerWrapper) Error() *zerolog.Event {
	return w.logger.Error()
}

func (w *sessionLoggerWrapper) Fatal() *zerolog.Event {
	return w.logger.Fatal()
}

func (w *sessionLoggerWrapper) With() zerolog.Context {
	return w.logger.With()
}

// NewSessionLogger creates a session-aware logger with session_id and remote_addr context
func NewSessionLogger(baseLogger Logger, sessionID string, remoteAddr string) Logger {
	// Extract the underlying zerolog.Logger from the base logger
	// We need to create a new zerolog.Logger with session context
	// Since we can't access the underlying zerolog.Logger directly from the interface,
	// we'll create a new one with the session context
	sessionLogger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "inboundparse").
		Str("session_id", sessionID).
		Str("remote_addr", remoteAddr).
		Logger()

	return &sessionLoggerWrapper{logger: sessionLogger}
}
