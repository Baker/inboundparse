package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"inboundparse/internal/domain"

	"github.com/croessner/dkim2"
)

//go:embed testdata/dkim2_ed25519.eml
var ed25519Fixture []byte

//go:embed testdata/dkim2_null_sender.eml
var nullSenderFixture []byte

const dkim2FixtureSeed = "inboundparse-dkim2-ed25519-test-key"

func dkim2FixtureClock() time.Time {
	return time.Unix(1_700_000_000, 0).UTC()
}

type stubPublicKeyProvider struct {
	public  ed25519.PublicKey
	missing bool
}

func (s stubPublicKeyProvider) LookupPublicKey(_ context.Context, query dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	if s.missing || query.Algorithm() != dkim2.AlgorithmEd25519SHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundEd25519PublicKey(s.public), nil
}

func testDKIM2Verifier(t *testing.T, missing bool) *dkim2.Verifier {
	t.Helper()
	seed := sha256.Sum256([]byte(dkim2FixtureSeed))
	private := ed25519.NewKeyFromSeed(seed[:])
	verifier, err := dkim2.NewVerifier(
		stubPublicKeyProvider{public: private.Public().(ed25519.PublicKey), missing: missing},
		dkim2.WithoutSubdomainFromAuthorization(),
		dkim2.WithVerificationClock(dkim2FixtureClock),
	)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return verifier
}

func checkDKIM2(t *testing.T, verifier *dkim2.Verifier, raw, from string, to []string) *domain.DKIM2Result {
	t.Helper()
	result, err := NewDKIM2Checker(verifier).CheckDKIM2(context.Background(), raw, from, to, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("CheckDKIM2() error = %v", err)
	}
	if result == nil {
		t.Fatal("CheckDKIM2() result is nil")
	}
	return result
}

func TestDKIM2FixturesKeepCRLF(t *testing.T) {
	for _, fixture := range [][]byte{ed25519Fixture, nullSenderFixture} {
		if bytes.Count(fixture, []byte("\r\n")) == 0 {
			t.Fatal("fixture has no CRLF")
		}
		if bytes.Contains(bytes.ReplaceAll(fixture, []byte("\r\n"), nil), []byte("\n")) {
			t.Fatal("fixture has a bare LF, so the DKIM2 body hash would not survive checkout")
		}
	}
}

func TestCheckDKIM2_None(t *testing.T) {
	raw := "From: alice@example.test\r\nTo: bob@example.net\r\nSubject: unsigned\r\n\r\nbody\r\n"
	result := checkDKIM2(t, testDKIM2Verifier(t, false), raw, "", []string{"bob@example.net"})
	if result.Result != "none" {
		t.Fatalf("result = %q, want none", result.Result)
	}
	if result.Reason != "" || len(result.Signatures) != 0 || len(result.Checks) != 0 {
		t.Fatalf("none result carried verification facts: %#v", result)
	}
}

func TestCheckDKIM2_Pass(t *testing.T) {
	verifier := testDKIM2Verifier(t, false)
	for _, from := range []string{"alice@example.test", "<alice@example.test>", "  alice@example.test  "} {
		result := checkDKIM2(t, verifier, string(ed25519Fixture), from, []string{"bob@example.net"})
		if result.Result != "pass" || result.Reason != "none" {
			t.Fatalf("from %q result = %s/%s, want pass/none", from, result.Result, result.Reason)
		}
		if result.Scope != "chain" || result.Sequence != 1 || result.Instance != 1 {
			t.Fatalf("from %q target = scope %s sequence %d instance %d", from, result.Scope, result.Sequence, result.Instance)
		}
		if result.HistoricalContent != "complete" || result.HistoricalSignatures != "complete" || result.Custody != "not_present" {
			t.Fatalf("from %q coverage = content %s signatures %s custody %s", from, result.HistoricalContent, result.HistoricalSignatures, result.Custody)
		}
		if len(result.Signatures) != 1 {
			t.Fatalf("from %q signatures = %#v", from, result.Signatures)
		}
		signature := result.Signatures[0]
		if signature.Algorithm != "ed25519-sha256" || signature.Status != "pass" || signature.Reason != "none" || signature.Selector != "" {
			t.Fatalf("from %q signature = %#v", from, signature)
		}
		if len(result.Checks) == 0 {
			t.Fatal("pass result has no checks")
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "example.test") || strings.Contains(string(encoded), "selector") {
			t.Fatalf("pass result attested identity: %s", encoded)
		}
	}
}

func TestCheckDKIM2_MissingKey(t *testing.T) {
	result := checkDKIM2(t, testDKIM2Verifier(t, true), string(ed25519Fixture), "alice@example.test", []string{"bob@example.net"})
	if result.Result != "permerror" || result.Reason != "missing_key" {
		t.Fatalf("result = %s/%s, want permerror/missing_key", result.Result, result.Reason)
	}
	if len(result.Signatures) != 1 || result.Signatures[0].Selector != "ed" {
		t.Fatalf("signature = %#v", result.Signatures)
	}
}

func TestCheckDKIM2_EnvelopeMismatch(t *testing.T) {
	verifier := testDKIM2Verifier(t, false)
	cases := []struct {
		name string
		from string
		to   []string
	}{
		{name: "mail from", from: "carol@example.test", to: []string{"bob@example.net"}},
		{name: "null sender", from: "", to: []string{"bob@example.net"}},
		{name: "local part case", from: "Alice@example.test", to: []string{"bob@example.net"}},
		{name: "recipient", from: "alice@example.test", to: []string{"carol@example.net", "bob@example.net"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := checkDKIM2(t, verifier, string(ed25519Fixture), tc.from, tc.to)
			if result.Result != "fail" || result.Reason != "envelope_mismatch" {
				t.Fatalf("result = %s/%s, want fail/envelope_mismatch", result.Result, result.Reason)
			}
		})
	}
}

func TestCheckDKIM2_NullSender(t *testing.T) {
	verifier := testDKIM2Verifier(t, false)
	for _, from := range []string{"", "<>", "  <>  "} {
		result := checkDKIM2(t, verifier, string(nullSenderFixture), from, []string{"<bob@example.net>"})
		if result.Result != "pass" || result.Reason != "none" {
			t.Fatalf("from %q result = %s/%s, want pass/none", from, result.Result, result.Reason)
		}
	}
	mismatched := checkDKIM2(t, verifier, string(nullSenderFixture), "alice@example.test", []string{"bob@example.net"})
	if mismatched.Result != "fail" || mismatched.Reason != "envelope_mismatch" {
		t.Fatalf("address against null signature = %s/%s, want fail/envelope_mismatch", mismatched.Result, mismatched.Reason)
	}
}

func TestCheckDKIM2_Canceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := NewDKIM2Checker(testDKIM2Verifier(t, false)).CheckDKIM2(
		ctx, string(ed25519Fixture), "alice@example.test", []string{"bob@example.net"}, &MockLogger{}, &mockMetricsCollector{},
	)
	if err != nil {
		t.Fatalf("CheckDKIM2() error = %v", err)
	}
	if result == nil || result.Result != "temperror" || result.Reason != "unavailable" {
		t.Fatalf("result = %#v, want temperror/unavailable", result)
	}
}

func TestCheckDKIM2_Deadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel()
	result, err := NewDKIM2Checker(testDKIM2Verifier(t, false)).CheckDKIM2(
		ctx, "From: alice@example.test\r\n\r\nbody\r\n", "", nil, &MockLogger{}, &mockMetricsCollector{},
	)
	if err != nil {
		t.Fatalf("CheckDKIM2() error = %v", err)
	}
	if result == nil || result.Result != "temperror" || result.Reason != "unavailable" {
		t.Fatalf("result = %#v, want temperror/unavailable", result)
	}
}

func TestCheckDKIM2_Disabled(t *testing.T) {
	checker := NewAuthChecker(AuthConfig{EnableDKIM2: false})
	result, err := checker.CheckDKIM2(context.Background(), string(ed25519Fixture), "alice@example.test", []string{"bob@example.net"}, &MockLogger{}, &mockMetricsCollector{})
	if err != nil || result != nil {
		t.Fatalf("disabled result = %#v err = %v", result, err)
	}
}

func TestCheckDKIM2_NilVerifier(t *testing.T) {
	checker := NewAuthChecker(AuthConfig{EnableDKIM2: true})
	result, err := checker.CheckDKIM2(context.Background(), string(ed25519Fixture), "alice@example.test", []string{"bob@example.net"}, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("CheckDKIM2() error = %v", err)
	}
	if result == nil || result.Result != "permerror" || result.Reason != "invalid_request" {
		t.Fatalf("result = %#v, want permerror/invalid_request", result)
	}
}
