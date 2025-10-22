package auth

import (
	"context"
	"testing"
)

func TestDKIMChecker_CheckDKIM_ValidMessage(t *testing.T) {
	checker := NewDKIMChecker()

	// Create a simple test message
	rawMessage := `From: test@example.com
To: recipient@example.com
Subject: Test
Date: Mon, 01 Jan 2024 12:00:00 +0000

This is a test message.`

	result, err := checker.CheckDKIM(context.Background(), rawMessage)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Result depends on whether DKIM signature is present
	// We just verify the structure is correct
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestDKIMChecker_CheckDKIM_EmptyMessage(t *testing.T) {
	checker := NewDKIMChecker()

	result, err := checker.CheckDKIM(context.Background(), "")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestDKIMChecker_CheckDKIM_InvalidMessage(t *testing.T) {
	checker := NewDKIMChecker()

	// Create an invalid message that might cause parsing issues
	rawMessage := "invalid message content"

	result, err := checker.CheckDKIM(context.Background(), rawMessage)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected non-nil result")
	}
}
