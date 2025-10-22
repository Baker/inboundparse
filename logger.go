package main

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var logger zerolog.Logger

// InitLogger initializes the global logger with appropriate configuration
func InitLogger(verbose bool) {
	// Configure zerolog for human-readable output in development
	// and JSON in production
	zerolog.TimeFieldFormat = time.RFC3339

	// Set log level based on verbose flag
	if verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Always use JSON format for structured logging
	logger = zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "inboundparse").
		Logger()

	log.Logger = logger
}

// GetLogger returns the global logger instance
func GetLogger() *zerolog.Logger {
	return &logger
}
