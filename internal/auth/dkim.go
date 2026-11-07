package auth

import (
	"context"
	"fmt"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// dkimChecker implements DKIMChecker interface
type dkimChecker struct{}

// NewDKIMChecker creates a new DKIM checker
func NewDKIMChecker() DKIMChecker {
	return &dkimChecker{}
}

// CheckDKIM performs DKIM authentication check following RFC 6376
func (d *dkimChecker) CheckDKIM(ctx context.Context, rawMessage string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DKIMResult, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		metrics.TrackDKIMDuration(duration)
	}()
	// Verify does not take a context. Run it aside so a canceled
	// MESSAGE_PROCESSING_TIMEOUT can return without waiting on DNS.
	type dkimLookup struct {
		verifications []*dkim.Verification
		err           error
	}
	lookup, ok := callWithContext(ctx, func() dkimLookup {
		verifications, err := dkim.Verify(strings.NewReader(rawMessage))
		return dkimLookup{verifications: verifications, err: err}
	})
	if !ok {
		metrics.TrackAuthError("dkim", "timeout_error")
		logger.Warn().
			Err(ctx.Err()).
			Msg("DKIM verification canceled")
		return &domain.DKIMResult{
			Valid: false,
			Raw:   fmt.Sprintf("DKIM verification error: %v", ctx.Err()),
			Error: ctx.Err().Error(),
		}, nil
	}
	verifications, err := lookup.verifications, lookup.err
	if err != nil {
		// Determine error type for metrics
		errorType := "verification_error"
		switch {
		case strings.Contains(err.Error(), "timeout"):
			errorType = "timeout_error"
		case strings.Contains(err.Error(), "parse"):
			errorType = "parse_error"
		case strings.Contains(err.Error(), "DNS"):
			errorType = "dns_error"
		}
		metrics.TrackAuthError("dkim", errorType)

		logger.Warn().
			Err(err).
			Msg("DKIM verification error")
		return &domain.DKIMResult{
			Valid: false,
			Raw:   fmt.Sprintf("DKIM verification error: %v", err),
			Error: err.Error(),
		}, nil
	}

	var signatures []string
	details := make([]domain.DKIMSignatureDetail, 0) // Initialize as empty slice, not nil
	hasValidSignature := false

	// RFC 6376 Section 3.5: Parse each DKIM signature header
	for _, verification := range verifications {
		detail := domain.DKIMSignatureDetail{
			Valid: verification.Err == nil,
		}

		if verification.Err != nil {
			// Invalid signature
			signatures = append(signatures, fmt.Sprintf("Invalid: %v", verification.Err))
			detail.Error = verification.Err.Error()
		} else {
			// Valid signature
			signatures = append(signatures, fmt.Sprintf("Valid: %s", verification.Domain))
			detail.Domain = verification.Domain
			hasValidSignature = true
		}

		// Extract available fields from go-msgauth Verification struct
		detail.HeadersSigned = verification.HeaderKeys
		if !verification.Time.IsZero() {
			detail.Timestamp = verification.Time.Unix()
		}
		if !verification.Expiration.IsZero() {
			detail.Expiration = verification.Expiration.Unix()
		}

		details = append(details, detail)
	}

	logger.Debug().
		Bool("valid", hasValidSignature).
		Int("signature_count", len(verifications)).
		Strs("signatures", signatures).
		Msg("DKIM check completed")

	// Track results by domain for each signature
	for _, verification := range verifications {
		if verification.Err == nil {
			metrics.TrackDKIMResultByDomain(verification.Domain, "valid")
		} else {
			metrics.TrackDKIMResultByDomain(verification.Domain, "invalid")
		}
	}

	return &domain.DKIMResult{
		Valid:      hasValidSignature,
		Signatures: signatures,
		Details:    details,
		Raw:        fmt.Sprintf("DKIM verification found %d signatures", len(verifications)),
	}, nil
}
