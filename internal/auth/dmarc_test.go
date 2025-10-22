package auth

import (
	"context"
	"net/mail"
	"testing"

	"github.com/mnako/letters"
)

func TestDMARCChecker_GetParentDomain(t *testing.T) {
	checker := &dmarcChecker{}

	if got := checker.getParentDomain("a.b.example.com"); got != "b.example.com" {
		t.Fatalf("getParentDomain('a.b.example.com') = %q, want 'b.example.com'", got)
	}
	if got := checker.getParentDomain("example.com"); got != "" {
		t.Fatalf("getParentDomain('example.com') = %q, want ''", got)
	}
}

func TestDMARCChecker_IsOrganizationalDomainMatch(t *testing.T) {
	checker := &dmarcChecker{}

	if !checker.isOrganizationalDomainMatch("a.example.com", "b.example.com") {
		t.Fatal("Expected match for a.example.com and b.example.com")
	}
	if !checker.isOrganizationalDomainMatch("example.com", "example.com") {
		t.Fatal("Expected match for example.com and example.com")
	}
	if checker.isOrganizationalDomainMatch("example.com", "other.com") {
		t.Fatal("Expected no match for example.com and other.com")
	}
}

func TestDMARCChecker_CheckDMARC_NoFromHeader(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "none" {
		t.Errorf("Expected result 'none', got %s", result.Result)
	}
}

func TestDMARCChecker_CheckDMARC_EmptyFromHeader(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{nil},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "none" {
		t.Errorf("Expected result 'none', got %s", result.Result)
	}
}

func TestDMARCChecker_CheckDMARC_NoDomainInFrom(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "invalid-email"},
		},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "none" {
		t.Errorf("Expected result 'none', got %s", result.Result)
	}
}

func TestDMARCChecker_IsDMARCNotFoundError(t *testing.T) {
	checker := &dmarcChecker{}

	tests := []struct {
		err      error
		expected bool
	}{
		{&netError{msg: "not found"}, true},
		{&netError{msg: "no such host"}, true},
		{&netError{msg: "nxdomain"}, true},
		{&netError{msg: "no data"}, true},
		{&netError{msg: "timeout"}, false},
		{&netError{msg: "connection refused"}, false},
	}

	for _, tt := range tests {
		if got := checker.isDMARCNotFoundError(tt.err); got != tt.expected {
			t.Errorf("isDMARCNotFoundError(%v) = %v, want %v", tt.err, got, tt.expected)
		}
	}
}

// Helper type for testing
type netError struct {
	msg string
}

func (e *netError) Error() string {
	return e.msg
}
