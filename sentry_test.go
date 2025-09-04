package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"testing"
)

func TestSentryConfiguration(t *testing.T) {
	// Test Sentry configuration flags
	// We can't easily test the actual Sentry initialization without a real DSN,
	// but we can test the configuration logic
	
	// Test that Sentry flags are defined
	if enableSentry == nil {
		t.Fatal("enableSentry flag not defined")
	}
	if sentryDSN == nil {
		t.Fatal("sentryDSN flag not defined")
	}
	if sentryEnv == nil {
		t.Fatal("sentryEnv flag not defined")
	}
	if sentryRelease == nil {
		t.Fatal("sentryRelease flag not defined")
	}
}

func TestInitializeSentry_Disabled(t *testing.T) {
	// Test initializeSentry when disabled
	originalEnableSentry := *enableSentry
	defer func() {
		*enableSentry = originalEnableSentry
	}()
	
	*enableSentry = false
	initializeSentry()
	
	// Should not panic or error when disabled
}

func TestInitializeSentry_NoDSN(t *testing.T) {
	// Test initializeSentry when enabled but no DSN provided
	originalEnableSentry := *enableSentry
	originalSentryDSN := *sentryDSN
	defer func() {
		*enableSentry = originalEnableSentry
		*sentryDSN = originalSentryDSN
	}()
	
	*enableSentry = true
	*sentryDSN = ""
	initializeSentry()
	
	// Should not panic or error when no DSN provided
}

func TestSentryEnvironmentVariables(t *testing.T) {
	// Test that Sentry environment variables are properly handled
	// This is tested indirectly through the loadConfig function
	// We can't easily test the actual environment variable loading
	// without modifying the global state, but we can verify the flags exist
	
	if enableSentry == nil {
		t.Fatal("enableSentry flag not defined")
	}
	if sentryDSN == nil {
		t.Fatal("sentryDSN flag not defined")
	}
	if sentryEnv == nil {
		t.Fatal("sentryEnv flag not defined")
	}
	if sentryRelease == nil {
		t.Fatal("sentryRelease flag not defined")
	}
}

func TestSentryIntegration_MessageProcessing(t *testing.T) {
	// Test that Sentry integration doesn't break message processing
	// when Sentry is disabled
	
	// Create a message processor with Sentry disabled
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: "http://example.com/webhook",
		},
		from: "sender@example.com",
		to:   []string{"recipient@example.com"},
	}
	
	// Test that ProcessMessage still works (it will fail due to invalid webhook URL,
	// but that's expected and not related to Sentry)
	message := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	err := mp.ProcessMessage(bytes.NewBufferString(message))
	
	// Should fail due to webhook URL, not Sentry
	if err == nil {
		t.Fatal("Expected ProcessMessage to fail with invalid webhook URL")
	}
}

func TestSentryIntegration_WebhookSending(t *testing.T) {
	// Test that Sentry integration doesn't break webhook sending
	// when Sentry is disabled
	
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: "http://invalid-url:9999",
		},
	}
	
	payload := &WebhookPayload{
		From: []*mail.Address{{Address: "sender@example.com"}},
		To:   []*mail.Address{{Address: "recipient@example.com"}},
	}
	
	// Test that sendWebhook still works (it will fail due to invalid URL,
	// but that's expected and not related to Sentry)
	err := mp.sendWebhook(payload)
	
	// Should fail due to invalid URL, not Sentry
	if err == nil {
		t.Fatal("Expected sendWebhook to fail with invalid URL")
	}
}

func TestReportToSentry(t *testing.T) {
	// Test reportToSentry function
	// This should not panic when Sentry is not initialized
	
	// Test with nil error
	reportToSentry(nil)
	
	// Test with actual error
	err := errors.New("test error")
	reportToSentry(err)
	
	// Test with wrapped error
	wrappedErr := fmt.Errorf("wrapped error: %w", err)
	reportToSentry(wrappedErr)
	
	// Test with different error types
	reportToSentry(errors.New("simple error"))
	reportToSentry(fmt.Errorf("formatted error: %s", "test"))
	reportToSentry(fmt.Errorf("multi-level wrapped: %w", wrappedErr))
}

func TestReportToSentry_EdgeCases(t *testing.T) {
	// Test reportToSentry with various edge cases
	
	// Test with empty error message
	reportToSentry(errors.New(""))
	
	// Test with very long error message
	longMsg := string(make([]byte, 1000))
	for i := range longMsg {
		longMsg = longMsg[:i] + "a" + longMsg[i+1:]
	}
	reportToSentry(errors.New(longMsg))
	
	// Test with special characters
	reportToSentry(errors.New("error with special chars: éñü"))
	reportToSentry(errors.New("error with newlines\n\n\n"))
	reportToSentry(errors.New("error with tabs\t\t\t"))
}