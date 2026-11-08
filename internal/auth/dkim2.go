package auth

import (
	"context"
	"errors"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"strings"
	"time"

	"github.com/croessner/dkim2"
)

// dkim2Checker verifies inbound messages with a process-wide Verifier.
// Signing stays out of this path.
type dkim2Checker struct {
	verifier *dkim2.Verifier
}

// NewDKIM2Checker returns a checker that reuses verifier.
func NewDKIM2Checker(verifier *dkim2.Verifier) DKIM2Checker {
	return &dkim2Checker{verifier: verifier}
}

// CheckDKIM2 reports draft-09 verification. A message with no DKIM2 fields is
// none. Protocol failures stay on the result. A canceled context is temperror
// with reason unavailable so the webhook still receives a value.
func (c *dkim2Checker) CheckDKIM2(ctx context.Context, rawMessage string, from string, to []string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DKIM2Result, error) {
	start := time.Now()
	defer func() {
		metrics.TrackDKIM2Duration(time.Since(start))
	}()

	if c == nil || c.verifier == nil {
		metrics.TrackAuthError("dkim2", "verifier_error")
		logger.Error().Msg("DKIM2 verifier is not configured")
		return &domain.DKIM2Result{Result: "permerror", Reason: "invalid_request"}, nil
	}

	reverse := bracketEnvelopePath(from)
	forwards := make([][]byte, len(to))
	for i, rcpt := range to {
		forwards[i] = []byte(bracketEnvelopePath(rcpt))
	}

	assessment, err := c.verifier.Assess(ctx, dkim2.NewVerifyRequest([]byte(rawMessage), []byte(reverse), forwards))
	if err != nil {
		if canceled(ctx, err) {
			metrics.TrackAuthError("dkim2", "canceled")
			logger.Warn().
				Err(err).
				Str("result", "temperror").
				Str("reason", "unavailable").
				Msg("DKIM2 verification canceled")
			return &domain.DKIM2Result{Result: "temperror", Reason: "unavailable"}, nil
		}
		metrics.TrackAuthError("dkim2", "verifier_error")
		logger.Warn().
			Err(err).
			Str("result", "permerror").
			Str("reason", "invalid_request").
			Msg("DKIM2 verification error")
		return &domain.DKIM2Result{Result: "permerror", Reason: "invalid_request"}, nil
	}

	result := mapDKIM2Assessment(assessment)
	logger.Debug().
		Str("result", result.Result).
		Str("reason", result.Reason).
		Msg("DKIM2 verification completed")
	return result, nil
}

// bracketEnvelopePath turns the SMTP envelope into the bracketed form DKIM2
// compares. A null reverse-path arrives as "" and must be sent as "<>".
// Local parts stay case-sensitive. Paths that are already bracketed are kept.
func bracketEnvelopePath(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "<>"
	}
	if len(addr) >= 2 && strings.HasPrefix(addr, "<") && strings.HasSuffix(addr, ">") {
		return addr
	}
	return "<" + addr + ">"
}

func canceled(ctx context.Context, err error) bool {
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func mapDKIM2Assessment(assessment dkim2.VerificationAssessment) *domain.DKIM2Result {
	if !assessment.Applicable() {
		return &domain.DKIM2Result{Result: "none"}
	}
	verification, ok := assessment.Verification()
	if !ok {
		return &domain.DKIM2Result{Result: "permerror", Reason: "invalid_request"}
	}

	checks := verification.Checks()
	mappedChecks := make([]domain.DKIM2Check, 0, len(checks))
	for _, check := range checks {
		mappedChecks = append(mappedChecks, domain.DKIM2Check{
			Class:  string(check.Class()),
			Reason: string(check.Reason()),
		})
	}

	sets := verification.SignatureSets()
	signatures := make([]domain.DKIM2Signature, 0, len(sets))
	for _, set := range sets {
		signature := domain.DKIM2Signature{
			Algorithm: string(set.Algorithm()),
			Status:    string(set.Status()),
			Reason:    string(set.Reason()),
		}
		if selector, present := set.Selector(); present {
			signature.Selector = selector
		}
		signatures = append(signatures, signature)
	}

	target := verification.Target()
	return &domain.DKIM2Result{
		Result:               strings.ToLower(string(verification.State())),
		Reason:               string(verification.PrimaryReason()),
		Scope:                string(verification.Scope()),
		HistoricalContent:    string(verification.HistoricalContent()),
		HistoricalSignatures: string(verification.HistoricalSignatures()),
		Custody:              string(verification.CustodyStructure()),
		Sequence:             target.Sequence(),
		Instance:             target.Instance(),
		Checks:               mappedChecks,
		Signatures:           signatures,
	}
}
