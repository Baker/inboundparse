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
