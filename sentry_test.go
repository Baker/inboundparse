package main

import (
	"errors"
	"testing"

	"github.com/getsentry/sentry-go"
)

func TestInitSentry_Disabled(t *testing.T) {
	config := &ServerConfig{
		EnableSentry: false,
	}

	err := InitSentry(config)
	if err != nil {
		t.Errorf("Expected no error when Sentry disabled, got %v", err)
	}
}

func TestInitSentry_NoDSN(t *testing.T) {
	// Initialize logger first (required for sentry.go logging)
	InitLogger(false)

	config := &ServerConfig{
		EnableSentry: true,
		SentryDSN:    "", // No DSN provided
	}

	err := InitSentry(config)
	if err != nil {
		t.Errorf("Expected no error when DSN not provided, got %v", err)
	}
}

func TestInitSentry_InvalidDSN(t *testing.T) {
	// Initialize logger first
	InitLogger(false)

	config := &ServerConfig{
		EnableSentry: true,
		SentryDSN:    "invalid-dsn-format",
		SentryEnv:    "test",
	}

	err := InitSentry(config)
	// Invalid DSN should return an error from sentry.Init
	if err == nil {
		t.Error("Expected error with invalid DSN")
	}
}

func TestInitSentry_ValidConfiguration(t *testing.T) {
	// Initialize logger first
	InitLogger(false)

	// Use a test DSN format (won't actually send data)
	config := &ServerConfig{
		EnableSentry:  true,
		SentryDSN:     "https://public@sentry.example.com/1",
		SentryEnv:     "test",
		SentryRelease: "v1.0.0-test",
	}

	// Close any existing Sentry client first
	sentry.Flush(0)

	err := InitSentry(config)
	if err != nil {
		t.Errorf("Expected no error with valid configuration, got %v", err)
	}

	// Clean up
	sentry.Flush(0)
}

func TestFlushSentry(t *testing.T) {
	// This should not panic even if Sentry is not initialized
	FlushSentry()
}

func TestCaptureError_NilError(t *testing.T) {
	// Should handle nil error gracefully
	CaptureError(nil, map[string]interface{}{
		"test": "context",
	})
	// Should not panic
}

func TestCaptureError_WithContext(t *testing.T) {
	// Initialize logger first
	InitLogger(false)

	// Initialize Sentry with test configuration
	config := &ServerConfig{
		EnableSentry: true,
		SentryDSN:    "https://public@sentry.example.com/1",
		SentryEnv:    "test",
	}
	_ = InitSentry(config)

	testErr := errors.New("test error")
	context := map[string]interface{}{
		"session_id": "test-session-123",
		"user_id":    42,
		"action":     "test_action",
	}

	// Should not panic
	CaptureError(testErr, context)

	// Clean up
	sentry.Flush(0)
}

func TestCaptureMessage_WithContext(t *testing.T) {
	// Initialize logger first
	InitLogger(false)

	// Initialize Sentry with test configuration
	config := &ServerConfig{
		EnableSentry: true,
		SentryDSN:    "https://public@sentry.example.com/1",
		SentryEnv:    "test",
	}
	_ = InitSentry(config)

	context := map[string]interface{}{
		"session_id": "test-session-456",
		"severity":   "high",
	}

	// Should not panic
	CaptureMessage("Test message", sentry.LevelWarning, context)

	// Clean up
	sentry.Flush(0)
}

func TestCaptureMessage_DifferentLevels(t *testing.T) {
	// Initialize logger first
	InitLogger(false)

	// Initialize Sentry with test configuration
	config := &ServerConfig{
		EnableSentry: true,
		SentryDSN:    "https://public@sentry.example.com/1",
		SentryEnv:    "test",
	}
	_ = InitSentry(config)

	levels := []sentry.Level{
		sentry.LevelDebug,
		sentry.LevelInfo,
		sentry.LevelWarning,
		sentry.LevelError,
		sentry.LevelFatal,
	}

	for _, level := range levels {
		CaptureMessage("Test message at level", level, map[string]interface{}{
			"level": string(level),
		})
	}

	// Clean up
	sentry.Flush(0)
}

func TestRecoverWithSentry_NoPanic(t *testing.T) {
	// Should do nothing if there's no panic
	defer RecoverWithSentry()

	// Normal execution
}

func TestRecoverWithSentry_WithPanic(t *testing.T) {
	// Initialize logger first
	InitLogger(false)

	// Initialize Sentry with test configuration
	config := &ServerConfig{
		EnableSentry: true,
		SentryDSN:    "https://public@sentry.example.com/1",
		SentryEnv:    "test",
	}
	_ = InitSentry(config)

	defer func() {
		// Catch the re-panic
		if r := recover(); r != nil {
			// Expected: RecoverWithSentry should re-panic after capturing
			if r != "test panic" {
				t.Errorf("Expected panic value 'test panic', got %v", r)
			}
		} else {
			t.Error("Expected panic to be re-thrown")
		}

		// Clean up
		sentry.Flush(0)
	}()

	defer RecoverWithSentry()

	// Trigger a panic
	panic("test panic")
}

func TestCaptureError_EmptyContext(t *testing.T) {
	// Initialize logger first
	InitLogger(false)

	// Initialize Sentry with test configuration
	config := &ServerConfig{
		EnableSentry: true,
		SentryDSN:    "https://public@sentry.example.com/1",
		SentryEnv:    "test",
	}
	_ = InitSentry(config)

	testErr := errors.New("test error without context")

	// Should not panic with empty context
	CaptureError(testErr, map[string]interface{}{})

	// Should not panic with nil context map
	CaptureError(testErr, nil)

	// Clean up
	sentry.Flush(0)
}

func TestSentryConfiguration_SampleRate(t *testing.T) {
	// This test verifies that the configuration sets the sample rate
	// We can't directly test the sampling behavior, but we can verify
	// the configuration is accepted

	InitLogger(false)

	config := &ServerConfig{
		EnableSentry:  true,
		SentryDSN:     "https://public@sentry.example.com/1",
		SentryEnv:     "production",
		SentryRelease: "v2.0.0",
	}

	err := InitSentry(config)
	if err != nil {
		t.Errorf("Expected successful initialization with sample rate, got %v", err)
	}

	// Clean up
	sentry.Flush(0)
}
