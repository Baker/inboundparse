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

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			contains(s[1:], substr))))
}
