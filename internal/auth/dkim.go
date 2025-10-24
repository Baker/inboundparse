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
	var details []domain.DKIMSignatureDetail
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

		// Extract additional signature details if available
		// Note: The go-msgauth/dkim library doesn't expose all signature fields
		// In a full implementation, we would parse the DKIM-Signature header directly
		// to extract selector, algorithm, headers signed, body hash, timestamps, etc.
		detail.Selector = "unknown"       // Would be extracted from s= tag
		detail.Algorithm = "unknown"      // Would be extracted from a= tag
		detail.HeadersSigned = []string{} // Would be extracted from h= tag
		detail.BodyHash = "unknown"       // Would be extracted from bh= tag

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
