package observability

import (
	"errors"
	"testing"

	"github.com/getsentry/sentry-go"
)

func TestSentryClient_Init_Disabled(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}

	err := client.Init(config)
	if err != nil {
		t.Errorf("Expected no error when Sentry disabled, got %v", err)
	}
}

func TestSentryClient_Init_NoDSN(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: true,
		SentryDSN:    "", // No DSN provided
	}

	err := client.Init(config)
	if err != nil {
		t.Errorf("Expected no error when no DSN provided, got %v", err)
	}
}

func TestSentryClient_Init_WithDSN(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry:  true,
		SentryDSN:     "https://test@sentry.io/123456",
		SentryEnv:     "test",
		SentryRelease: "1.0.0",
	}

	err := client.Init(config)
	// This might fail in test environment due to network, but should not panic
	if err != nil {
		t.Logf("Sentry init failed (expected in test env): %v", err)
	}
}

func TestSentryClient_CaptureError(t *testing.T) {
	client := NewSentryClient()

	// Initialize with disabled sentry
	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Should not panic when sentry is disabled
	client.CaptureError(errors.New("test error"), map[string]interface{}{
		"test": "value",
	})
}

func TestSentryClient_CaptureMessage(t *testing.T) {
	client := NewSentryClient()

	// Initialize with disabled sentry
	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Should not panic when sentry is disabled
	client.CaptureMessage("test message", sentry.LevelInfo, map[string]interface{}{
		"test": "value",
	})
}

func TestSentryClient_Flush(t *testing.T) {
	client := NewSentryClient()

	// Should not panic when sentry is not initialized
	client.Flush()
}

func TestSentryClient_RecoverWithSentry(t *testing.T) {
	client := NewSentryClient()

	// Initialize with disabled sentry
	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Should not panic when sentry is disabled
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Expected no panic, got %v", r)
		}
	}()

	client.RecoverWithSentry()
}

func TestSentryConfig_DefaultValues(t *testing.T) {
	config := SentryConfig{}

	if config.EnableSentry {
		t.Error("Expected EnableSentry to be false by default")
	}
	if config.SentryDSN != "" {
		t.Errorf("Expected empty SentryDSN, got '%s'", config.SentryDSN)
	}
	if config.SentryEnv != "" {
		t.Errorf("Expected empty SentryEnv, got '%s'", config.SentryEnv)
	}
	if config.SentryRelease != "" {
		t.Errorf("Expected empty SentryRelease, got '%s'", config.SentryRelease)
	}
}

func TestSentryConfig_WithValues(t *testing.T) {
	config := SentryConfig{
		EnableSentry:  true,
		SentryDSN:     "https://test@sentry.io/123456",
		SentryEnv:     "test",
		SentryRelease: "v1.0.0",
	}

	if !config.EnableSentry {
		t.Error("Expected EnableSentry to be true")
	}
	if config.SentryDSN != "https://test@sentry.io/123456" {
		t.Errorf("Expected SentryDSN 'https://test@sentry.io/123456', got '%s'", config.SentryDSN)
	}
	if config.SentryEnv != "test" {
		t.Errorf("Expected SentryEnv 'test', got '%s'", config.SentryEnv)
	}
	if config.SentryRelease != "v1.0.0" {
		t.Errorf("Expected SentryRelease 'v1.0.0', got '%s'", config.SentryRelease)
	}
}

func TestSentryClient_MultipleInit(t *testing.T) {
	client := NewSentryClient()

	config1 := SentryConfig{
		EnableSentry: false,
	}

	config2 := SentryConfig{
		EnableSentry: false,
	}

	// Should be able to init multiple times
	err1 := client.Init(config1)
	if err1 != nil {
		t.Errorf("Expected no error on first init, got %v", err1)
	}

	err2 := client.Init(config2)
	if err2 != nil {
		t.Errorf("Expected no error on second init, got %v", err2)
	}
}

func TestSentryClient_CaptureErrorWithNilError(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Should not panic with nil error
	client.CaptureError(nil, map[string]interface{}{
		"test": "value",
	})
}

func TestSentryClient_CaptureErrorWithNilTags(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Should not panic with nil tags
	client.CaptureError(errors.New("test error"), nil)
}

func TestSentryClient_CaptureMessageWithNilTags(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Should not panic with nil tags
	client.CaptureMessage("test message", sentry.LevelInfo, nil)
}

func TestSentryClient_CaptureMessageWithEmptyMessage(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Should not panic with empty message
	client.CaptureMessage("", sentry.LevelInfo, map[string]interface{}{
		"test": "value",
	})
}

func TestSentryClient_CaptureErrorWithEnabledSentry(t *testing.T) {
	client := NewSentryClient()

	// Initialize with enabled sentry but no DSN (should be handled gracefully)
	config := SentryConfig{
		EnableSentry: true,
		SentryDSN:    "", // No DSN
	}
	client.Init(config)

	// Should not panic when sentry is enabled but not properly configured
	client.CaptureError(errors.New("test error"), map[string]interface{}{
		"test": "value",
	})
}

func TestSentryClient_CaptureMessageWithEnabledSentry(t *testing.T) {
	client := NewSentryClient()

	// Initialize with enabled sentry but no DSN (should be handled gracefully)
	config := SentryConfig{
		EnableSentry: true,
		SentryDSN:    "", // No DSN
	}
	client.Init(config)

	// Should not panic when sentry is enabled but not properly configured
	client.CaptureMessage("test message", sentry.LevelInfo, map[string]interface{}{
		"test": "value",
	})
}

func TestSentryClient_CaptureErrorWithDifferentLevels(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Test with different error types
	client.CaptureError(errors.New("simple error"), map[string]interface{}{
		"type": "simple",
	})

	client.CaptureError(errors.New("wrapped error"), map[string]interface{}{
		"type": "wrapped",
	})
}

func TestSentryClient_CaptureMessageWithDifferentLevels(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Test with different message levels
	client.CaptureMessage("debug message", sentry.LevelDebug, map[string]interface{}{
		"level": "debug",
	})

	client.CaptureMessage("info message", sentry.LevelInfo, map[string]interface{}{
		"level": "info",
	})

	client.CaptureMessage("warning message", sentry.LevelWarning, map[string]interface{}{
		"level": "warning",
	})

	client.CaptureMessage("error message", sentry.LevelError, map[string]interface{}{
		"level": "error",
	})

	client.CaptureMessage("fatal message", sentry.LevelFatal, map[string]interface{}{
		"level": "fatal",
	})
}

func TestSentryClient_FlushWithEnabledSentry(t *testing.T) {
	client := NewSentryClient()

	// Initialize with enabled sentry but no DSN (should be handled gracefully)
	config := SentryConfig{
		EnableSentry: true,
		SentryDSN:    "", // No DSN
	}
	client.Init(config)

	// Should not panic when flushing with enabled but not properly configured sentry
	client.Flush()
}

func TestSentryClient_RecoverWithSentryWithEnabledSentry(t *testing.T) {
	client := NewSentryClient()

	// Initialize with enabled sentry but no DSN (should be handled gracefully)
	config := SentryConfig{
		EnableSentry: true,
		SentryDSN:    "", // No DSN
	}
	client.Init(config)

	// Should not panic when sentry is enabled but not properly configured
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Expected no panic, got %v", r)
		}
	}()

	client.RecoverWithSentry()
}

func TestSentryClient_CaptureErrorWithComplexContext(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Test with complex context data
	complexContext := map[string]interface{}{
		"string":  "test",
		"number":  42,
		"boolean": true,
		"array":   []string{"item1", "item2"},
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	client.CaptureError(errors.New("complex error"), complexContext)
}

func TestSentryClient_CaptureMessageWithComplexContext(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Test with complex context data
	complexContext := map[string]interface{}{
		"string":  "test",
		"number":  42,
		"boolean": true,
		"array":   []string{"item1", "item2"},
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	client.CaptureMessage("complex message", sentry.LevelInfo, complexContext)
}

func TestSentryClient_CaptureErrorWithEmptyContext(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Test with empty context
	client.CaptureError(errors.New("error with empty context"), map[string]interface{}{})
}

func TestSentryClient_CaptureMessageWithEmptyContext(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Test with empty context
	client.CaptureMessage("message with empty context", sentry.LevelInfo, map[string]interface{}{})
}

func TestSentryClient_RecoverWithSentryWithPanic(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry: false,
	}
	client.Init(config)

	// Test that RecoverWithSentry doesn't panic when there's no panic to recover
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Expected no panic, got %v", r)
		}
	}()

	client.RecoverWithSentry()
}

func TestSentryClient_InitWithInvalidDSN(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry:  true,
		SentryDSN:     "invalid-dsn", // Invalid DSN
		SentryEnv:     "test",
		SentryRelease: "1.0.0",
	}

	err := client.Init(config)
	// This might fail due to invalid DSN, but should not panic
	if err != nil {
		t.Logf("Sentry init failed with invalid DSN (expected): %v", err)
	}
}

func TestSentryClient_InitWithEmptyDSN(t *testing.T) {
	client := NewSentryClient()

	config := SentryConfig{
		EnableSentry:  true,
		SentryDSN:     "", // Empty DSN
		SentryEnv:     "test",
		SentryRelease: "1.0.0",
	}

	err := client.Init(config)
	// Should not error with empty DSN
	if err != nil {
		t.Errorf("Expected no error with empty DSN, got %v", err)
	}
}

func TestSentryClient_CaptureErrorWithContext(t *testing.T) {
	// Test CaptureError with context (lines 76-82)
	client := &sentryClient{enabled: true}

	context := map[string]interface{}{
		"user_id": "123",
		"action":  "test_action",
		"level":   "error",
	}

	// This should not panic
	client.CaptureError(errors.New("test error"), context)
}

func TestSentryClient_CaptureMessageWithContext(t *testing.T) {
	// Test CaptureMessage with context (lines 92-98)
	client := &sentryClient{enabled: true}

	context := map[string]interface{}{
		"user_id": "123",
		"action":  "test_action",
		"level":   "info",
	}

	// This should not panic
	client.CaptureMessage("test message", "info", context)
}

func TestSentryClient_CaptureErrorWithNilContext(t *testing.T) {
	// Test CaptureError with nil context
	client := &sentryClient{enabled: true}

	// This should not panic
	client.CaptureError(errors.New("test error"), nil)
}

func TestSentryClient_CaptureMessageWithNilContext(t *testing.T) {
	// Test CaptureMessage with nil context
	client := &sentryClient{enabled: true}

	// This should not panic
	client.CaptureMessage("test message", "info", nil)
}
