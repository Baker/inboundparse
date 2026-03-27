package observability

import (
	"bytes"
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func TestNewLogger_VerboseMode(t *testing.T) {
	// Capture output
	var buf bytes.Buffer
	oldOutput := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := NewLogger(LoggerConfig{Verbose: true})

	// Check that debug level is enabled
	if zerolog.GlobalLevel() != zerolog.DebugLevel {
		t.Errorf("Expected debug level, got %v", zerolog.GlobalLevel())
	}

	// Write a debug log
	logger.Debug().Msg("test debug message")

	w.Close()
	os.Stdout = oldOutput

	// Read the output
	buf.ReadFrom(r)
	output := buf.String()

	// Check that debug message was logged
	if !contains(output, "test debug message") {
		t.Errorf("Expected debug message in output, got: %s", output)
	}
}

func TestNewLogger_NonVerboseMode(t *testing.T) {
	// Capture output
	var buf bytes.Buffer
	oldOutput := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := NewLogger(LoggerConfig{Verbose: false})

	// Check that info level is enabled
	if zerolog.GlobalLevel() != zerolog.InfoLevel {
		t.Errorf("Expected info level, got %v", zerolog.GlobalLevel())
	}

	// Write a debug log (should not appear)
	logger.Debug().Msg("test debug message")
	// Write an info log (should appear)
	logger.Info().Msg("test info message")

	w.Close()
	os.Stdout = oldOutput

	// Read the output
	buf.ReadFrom(r)
	output := buf.String()

	// Check that debug message was not logged
	if contains(output, "test debug message") {
		t.Errorf("Expected debug message to be filtered out, got: %s", output)
	}

	// Check that info message was logged
	if !contains(output, "test info message") {
		t.Errorf("Expected info message in output, got: %s", output)
	}
}

func TestDefaultLogger(t *testing.T) {
	logger := DefaultLogger()
	if logger == nil {
		t.Error("Expected default logger to be non-nil")
	}
}

func TestLoggerConfig_DefaultValues(t *testing.T) {
	config := LoggerConfig{}

	if config.Verbose {
		t.Error("Expected Verbose to be false by default")
	}
}

func TestLoggerConfig_WithVerbose(t *testing.T) {
	config := LoggerConfig{Verbose: true}

	if !config.Verbose {
		t.Error("Expected Verbose to be true")
	}
}

func TestLogger_LogLevels(t *testing.T) {
	logger := NewLogger(LoggerConfig{Verbose: true})

	// Test different log levels
	logger.Debug().Msg("debug message")
	logger.Info().Msg("info message")
	logger.Warn().Msg("warn message")
	logger.Error().Msg("error message")
	// Skip Fatal() as it calls os.Exit(1) and would terminate the test process
	// logger.Fatal().Msg("fatal message")

	// If we get here without panicking, the test passes
}

func TestLogger_WithFields(t *testing.T) {
	logger := NewLogger(LoggerConfig{Verbose: true})

	// Test logging with fields
	logger.Info().
		Str("key1", "value1").
		Int("key2", 42).
		Bool("key3", true).
		Msg("message with fields")

	// If we get here without panicking, the test passes
}

func TestLogger_WithError(t *testing.T) {
	logger := NewLogger(LoggerConfig{Verbose: true})

	// Test logging with error
	err := &testError{message: "test error"}
	logger.Error().Err(err).Msg("error occurred")

	// If we get here without panicking, the test passes
}

func TestSessionLoggerWrapper_AllMethods(t *testing.T) {
	// Test the sessionLoggerWrapper methods (Fatal and With)
	logger := NewSessionLogger(DefaultLogger(), "test-session-123", "192.168.1.1")

	// Test With() - line 81
	ctx := logger.With()
	// Just verify we can call Logger() on the context without panicking
	_ = ctx.Logger()

	// Test all other methods
	logger.Debug().Msg("debug from session logger")
	logger.Info().Msg("info from session logger")
	logger.Warn().Msg("warn from session logger")
	logger.Error().Msg("error from session logger")
	// Note: Fatal() calls os.Exit, skip it

	// Test NewSessionLogger returns non-nil
	if logger == nil {
		t.Error("Expected non-nil session logger")
	}
}

func TestSessionLoggerWrapper_Fatal(t *testing.T) {
	// We can't actually call Fatal() because it calls os.Exit(1)
	// But we can test that the method exists on the wrapper
	// by creating the wrapper and checking the type
	logger := NewSessionLogger(DefaultLogger(), "session-id", "127.0.0.1")

	// Verify it implements the Logger interface (which includes Fatal)
	var _ Logger = logger
}

// Helper functions and types

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			contains(s[1:], substr))))
}

type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}
