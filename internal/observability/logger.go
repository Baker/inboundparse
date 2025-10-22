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
