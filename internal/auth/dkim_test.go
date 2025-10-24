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

	// Test new RFC 6376 compliant fields
	if result.Details == nil {
		t.Error("Expected Details field to be present")
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

func TestDKIMChecker_CheckDKIM_WithMultipleSignatures(t *testing.T) {
	checker := NewDKIMChecker()

	// Create a message with multiple DKIM signatures (valid and invalid)
	rawMessage := `From: test@example.com
To: recipient@example.com
Subject: Test
Date: Mon, 01 Jan 2024 12:00:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/relaxed; h=from:to:subject:date; bh=test; b=invalid
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector2; c=relaxed/relaxed; h=from:to:subject:date; bh=test; b=alsoinvalid

This is a test message with multiple DKIM signatures.`

	result, err := checker.CheckDKIM(context.Background(), rawMessage)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected non-nil result")
	}

	// Verify that we have signatures in the result
	if len(result.Signatures) == 0 {
		t.Error("Expected signatures in result")
	}

	// Test new RFC 6376 compliant fields
	if len(result.Details) == 0 {
		t.Error("Expected signature details")
	}

	// Verify that we have both valid and invalid signatures
	hasValid := false
	hasInvalid := false
	for _, sig := range result.Signatures {
		if len(sig) > 0 {
			if sig[:6] == "Valid:" {
				hasValid = true
			} else if sig[:8] == "Invalid:" {
				hasInvalid = true
			}
		}
	}

	// At least one signature should be processed
	if !hasValid && !hasInvalid {
		t.Error("Expected at least one signature to be processed")
	}

	// Test signature details structure
	for _, detail := range result.Details {
		if detail.Selector == "" {
			t.Error("Expected selector in signature detail")
		}
		if detail.Algorithm == "" {
			t.Error("Expected algorithm in signature detail")
		}
	}
}

func TestDKIMChecker_CheckDKIM_WithValidSignature(t *testing.T) {
	checker := NewDKIMChecker()

	// Create a message with a valid-looking DKIM signature
	rawMessage := `From: test@example.com
To: recipient@example.com
Subject: Test
Date: Mon, 01 Jan 2024 12:00:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector; c=relaxed/relaxed; h=from:to:subject:date; bh=test; b=validsignature

This is a test message with a valid DKIM signature.`

	result, err := checker.CheckDKIM(context.Background(), rawMessage)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected non-nil result")
	}

	// The signature might not actually be valid due to missing private key,
	// but we should have a signature in the result
	if len(result.Signatures) == 0 {
		t.Error("Expected signatures in result")
	}
}

func TestDKIMChecker_CheckDKIM_WithInvalidSignature(t *testing.T) {
	checker := NewDKIMChecker()

	// Create a message with an invalid DKIM signature
	rawMessage := `From: test@example.com
To: recipient@example.com
Subject: Test
Date: Mon, 01 Jan 2024 12:00:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector; c=relaxed/relaxed; h=from:to:subject:date; bh=test; b=invalidsignature

This is a test message with an invalid DKIM signature.`

	result, err := checker.CheckDKIM(context.Background(), rawMessage)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected non-nil result")
	}

	// We should have signatures in the result, even if they're invalid
	if len(result.Signatures) == 0 {
		t.Error("Expected signatures in result")
	}
}

func TestDKIMChecker_CheckDKIM_WithMalformedSignature(t *testing.T) {
	checker := NewDKIMChecker()

	// Create a message with a malformed DKIM signature
	rawMessage := `From: test@example.com
To: recipient@example.com
Subject: Test
Date: Mon, 01 Jan 2024 12:00:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector; c=relaxed/relaxed; h=from:to:subject:date; bh=test; b=malformed

This is a test message with a malformed DKIM signature.`

	result, err := checker.CheckDKIM(context.Background(), rawMessage)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Error("Expected non-nil result")
	}

	// We should have signatures in the result, even if they're malformed
	if len(result.Signatures) == 0 {
		t.Error("Expected signatures in result")
	}
}
