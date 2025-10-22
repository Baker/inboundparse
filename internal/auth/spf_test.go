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
