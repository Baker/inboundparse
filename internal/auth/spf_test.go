package auth

import (
	"context"
	"net"
	"testing"
)

func TestExtractDomainFromEmail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"user@example.com", "example.com"},
		{"<user@example.com>", "example.com"},
		{"John <user@example.com>", "example.com"},
		{"no-at", ""},
	}
	for _, c := range cases {
		if got := ExtractDomainFromEmail(c.in); got != c.want {
			t.Fatalf("ExtractDomainFromEmail(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestSPFChecker_CheckSPF_NoRemoteIP(t *testing.T) {
	checker := NewSPFChecker()

	result, err := checker.CheckSPF(context.Background(), nil, "example.com", "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "temperror" {
		t.Errorf("Expected result 'temperror', got %s", result.Result)
	}
}

func TestSPFChecker_CheckSPF_NoDomain(t *testing.T) {
	checker := NewSPFChecker()

	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "", "test@")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "none" {
		t.Errorf("Expected result 'none', got %s", result.Result)
	}
}

func TestSPFChecker_CheckSPF_ValidDomain(t *testing.T) {
	checker := NewSPFChecker()

	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Result depends on actual SPF record, but should not be empty
	if result.Result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestSPFChecker_CheckSPF_WithError(t *testing.T) {
	checker := NewSPFChecker()

	// Test with a domain that might cause SPF lookup errors
	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "nonexistent-domain-that-should-fail.com", "test@nonexistent-domain-that-should-fail.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should handle the error gracefully and return a result
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSPFChecker_CheckSPF_WithInvalidIP(t *testing.T) {
	checker := NewSPFChecker()

	// Test with an invalid IP address
	remoteIP := net.ParseIP("invalid-ip")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should handle the invalid IP gracefully
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSPFChecker_CheckSPF_WithIPv6(t *testing.T) {
	checker := NewSPFChecker()

	// Test with IPv6 address
	remoteIP := net.ParseIP("2001:db8::1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should handle IPv6 addresses
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSPFChecker_CheckSPF_WithLocalhost(t *testing.T) {
	checker := NewSPFChecker()

	// Test with localhost IP
	remoteIP := net.ParseIP("127.0.0.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should handle localhost IPs
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSPFChecker_CheckSPF_WithPrivateIP(t *testing.T) {
	checker := NewSPFChecker()

	// Test with private IP address
	remoteIP := net.ParseIP("10.0.0.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should handle private IPs
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSPFChecker_CheckSPF_WithEmptyFrom(t *testing.T) {
	checker := NewSPFChecker()

	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should handle empty from address
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSPFChecker_CheckSPF_WithMalformedFrom(t *testing.T) {
	checker := NewSPFChecker()

	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "malformed-email-address")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should handle malformed from address
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSPFChecker_CheckSPF_WithSpecialCharactersInDomain(t *testing.T) {
	checker := NewSPFChecker()

	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example-with-dashes.com", "test@example-with-dashes.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should handle domains with special characters
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSPFChecker_CheckSPF_WithSubdomain(t *testing.T) {
	checker := NewSPFChecker()

	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "sub.example.com", "test@sub.example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should handle subdomains
	if result == nil {
		t.Error("Expected non-nil result")
	}
}
