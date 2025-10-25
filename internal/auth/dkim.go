package auth

import (
	"context"
	"fmt"
	"inboundparse/internal/domain"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/rs/zerolog/log"
)

// dkimChecker implements DKIMChecker interface
type dkimChecker struct{}

// NewDKIMChecker creates a new DKIM checker
func NewDKIMChecker() DKIMChecker {
	return &dkimChecker{}
}

// CheckDKIM performs DKIM authentication check following RFC 6376
func (d *dkimChecker) CheckDKIM(ctx context.Context, rawMessage string) (*domain.DKIMResult, error) {
	verifications, err := dkim.Verify(strings.NewReader(rawMessage))
	if err != nil {
		log.Warn().
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

	log.Debug().
		Bool("valid", hasValidSignature).
		Int("signature_count", len(verifications)).
		Strs("signatures", signatures).
		Msg("DKIM check completed")

	return &domain.DKIMResult{
		Valid:      hasValidSignature,
		Signatures: signatures,
		Details:    details,
		Raw:        fmt.Sprintf("DKIM verification found %d signatures", len(verifications)),
	}, nil
}
