package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func TestInitLogger_VerboseMode(t *testing.T) {
	// Capture output
	var buf bytes.Buffer
	oldOutput := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	InitLogger(true)

	// Check that debug level is enabled
	if zerolog.GlobalLevel() != zerolog.DebugLevel {
		t.Errorf("Expected debug level, got %v", zerolog.GlobalLevel())
	}

	// Write a debug log
	logger.Debug().Msg("test debug message")

	w.Close()
	os.Stdout = oldOutput
	buf.ReadFrom(r)

	// Verify log was written
	if buf.Len() == 0 {
		t.Error("Expected debug log to be written in verbose mode")
	}

	// Verify it's JSON
	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Errorf("Expected JSON log output, got error: %v", err)
	}

	// Verify service field
	if service, ok := logEntry["service"].(string); !ok || service != "inboundparse" {
		t.Errorf("Expected service field to be 'inboundparse', got %v", logEntry["service"])
	}
}

func TestInitLogger_StandardMode(t *testing.T) {
	InitLogger(false)

	// Check that info level is enabled
	if zerolog.GlobalLevel() != zerolog.InfoLevel {
		t.Errorf("Expected info level, got %v", zerolog.GlobalLevel())
	}

	// Verify that debug logs would be filtered
	// (In production, debug logs won't be written at Info level)
	if zerolog.GlobalLevel() <= zerolog.DebugLevel {
		t.Error("Debug level should not be active in standard mode")
	}
}

func TestGetLogger(t *testing.T) {
	InitLogger(false)

	retrievedLogger := GetLogger()
	if retrievedLogger == nil {
		t.Error("Expected non-nil logger")
	}

	// Verify it's the same logger instance
	if retrievedLogger != &logger {
		t.Error("Expected GetLogger to return the global logger instance")
	}
}

func TestLogger_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	InitLogger(false)
	logger.Info().
		Str("test_field", "test_value").
		Int("test_number", 42).
		Msg("test message")

	w.Close()
	os.Stdout = oldOutput
	buf.ReadFrom(r)

	var logEntry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Errorf("Expected valid JSON output, got error: %v\nOutput: %s", err, buf.String())
	}

	// Verify structured fields
	if msg, ok := logEntry["message"].(string); !ok || msg != "test message" {
		t.Errorf("Expected message field, got %v", logEntry["message"])
	}

	if testField, ok := logEntry["test_field"].(string); !ok || testField != "test_value" {
		t.Errorf("Expected test_field to be 'test_value', got %v", logEntry["test_field"])
	}

	if testNumber, ok := logEntry["test_number"].(float64); !ok || testNumber != 42 {
		t.Errorf("Expected test_number to be 42, got %v", logEntry["test_number"])
	}

	// Verify timestamp exists
	if _, ok := logEntry["time"]; !ok {
		t.Error("Expected timestamp field in log output")
	}
}
