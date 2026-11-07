package auth

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/zaccone/spf"
)

func TestExtractDomainFromEmail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"user@example.com", "example.com"},
		{"<user@example.com>", "example.com"},
		{"John <user@example.com>", "example.com"},
		{"no-at", ""},
		// angleEnd <= angleStart: '>' appears before '<' (not at boundaries so not trimmed)
		// e.g. "John > <user@example.com" has '>' at index 5 and '<' at index 7: 5 < 7 so skip
		{"John > <user@example.com", "example.com"},
		// angleEnd > angleStart with trailing content: brackets not at edges so Trim doesn't remove them
		{"John <user@example.com> extra", "example.com"},
	}
	for _, c := range cases {
		if got := ExtractDomainFromEmail(c.in); got != c.want {
			t.Fatalf("ExtractDomainFromEmail(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestSPFChecker_CheckSPF_NoRemoteIP(t *testing.T) {
	checker := NewSPFChecker()

	result, err := checker.CheckSPF(context.Background(), nil, "example.com", "test@example.com", &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "temperror" {
		t.Errorf("Expected result 'temperror', got %s", result.Result)
	}

	// Test new RFC 7208 compliant fields
	if result.Sender != "test@example.com" {
		t.Errorf("Expected sender 'test@example.com', got %s", result.Sender)
	}

	if result.Problem == "" {
		t.Error("Expected problem description for temperror result")
	}
}

func TestSPFChecker_CheckSPF_NoDomain(t *testing.T) {
	checker := NewSPFChecker()

	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "", "test@", &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "none" {
		t.Errorf("Expected result 'none', got %s", result.Result)
	}

	// Test new RFC 7208 compliant fields
	if result.Sender != "test@" {
		t.Errorf("Expected sender 'test@', got %s", result.Sender)
	}

	if result.Problem == "" {
		t.Error("Expected problem description for none result")
	}
}

func TestSPFChecker_CheckSPF_ValidDomain(t *testing.T) {
	checker := NewSPFChecker()

	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "test@example.com", &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Result depends on actual SPF record, but should not be empty
	if result.Result == "" {
		t.Error("Expected non-empty result")
	}

	// Test new RFC 7208 compliant fields
	if result.Sender != "test@example.com" {
		t.Errorf("Expected sender 'test@example.com', got %s", result.Sender)
	}
}

func TestSPFChecker_CheckSPF_WithError(t *testing.T) {
	checker := NewSPFChecker()

	// Test with a domain that might cause SPF lookup errors
	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "nonexistent-domain-that-should-fail.com", "test@nonexistent-domain-that-should-fail.com", &MockLogger{}, &mockMetricsCollector{})
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
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "test@example.com", &MockLogger{}, &mockMetricsCollector{})
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
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "test@example.com", &MockLogger{}, &mockMetricsCollector{})
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
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "test@example.com", &MockLogger{}, &mockMetricsCollector{})
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
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "test@example.com", &MockLogger{}, &mockMetricsCollector{})
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
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "", &MockLogger{}, &mockMetricsCollector{})
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
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example.com", "malformed-email-address", &MockLogger{}, &mockMetricsCollector{})
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
	result, err := checker.CheckSPF(context.Background(), remoteIP, "example-with-dashes.com", "test@example-with-dashes.com", &MockLogger{}, &mockMetricsCollector{})
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
	result, err := checker.CheckSPF(context.Background(), remoteIP, "sub.example.com", "test@sub.example.com", &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should handle subdomains
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestSPFResultOnError(t *testing.T) {
	cases := []struct {
		name   string
		result spf.Result
		err    error
		want   string
	}{
		{"none with permanent DNS error", spf.None, errors.New("permanent DNS error"), "none"},
		{"none when record missing", spf.None, errors.New("SPF record not found"), "none"},
		{"permerror", spf.Permerror, errors.New("too many SPF records"), "permerror"},
		{"temperror", spf.Temperror, errors.New("temporary DNS error"), "temperror"},
		{"zero result permanent text", 0, errors.New("permanent DNS error"), "permerror"},
		{"zero result other text", 0, errors.New("temporary DNS error"), "temperror"},
		{"unknown result permanent text", spf.Result(99), errors.New("permanent DNS error"), "permerror"},
		{"unknown result other text", spf.Result(99), errors.New("lookup failed"), "temperror"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := spfResultOnError(tc.result, tc.err); got != tc.want {
				t.Fatalf("spfResultOnError(%v, %v) = %q, want %q", tc.result, tc.err, got, tc.want)
			}
		})
	}
}

func TestSPFChecker_CheckSPF_NoSuchHost(t *testing.T) {
	checker := NewSPFChecker()
	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(context.Background(), remoteIP, "no-such-host.invalid", "test@no-such-host.invalid", &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result.Result != "none" {
		t.Fatalf("Expected result 'none' for NXDOMAIN, got %s (%s)", result.Result, result.Raw)
	}
}

func TestSPFChecker_CheckSPF_ContextCanceled(t *testing.T) {
	checker := NewSPFChecker()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(ctx, remoteIP, "example.com", "test@example.com", &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result.Result != "temperror" {
		t.Fatalf("Expected result 'temperror', got %s", result.Result)
	}
	if !strings.Contains(result.Problem, ctx.Err().Error()) {
		t.Fatalf("Expected problem to describe %v, got %q", ctx.Err(), result.Problem)
	}
}

func TestSPFChecker_CheckSPF_CanceledContextEmptyDomain(t *testing.T) {
	checker := NewSPFChecker()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	remoteIP := net.ParseIP("192.168.1.1")
	result, err := checker.CheckSPF(ctx, remoteIP, "", "test@", &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result.Result != "none" {
		t.Fatalf("Expected result 'none', got %s", result.Result)
	}
}
