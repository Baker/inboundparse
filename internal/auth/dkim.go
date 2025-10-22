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

// CheckDKIM performs DKIM authentication check
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
	hasValidSignature := false

	for _, verification := range verifications {
		if verification.Err != nil {
			signatures = append(signatures, fmt.Sprintf("Invalid: %v", verification.Err))
		} else {
			signatures = append(signatures, fmt.Sprintf("Valid: %s", verification.Domain))
			hasValidSignature = true
		}
	}

	log.Debug().
		Bool("valid", hasValidSignature).
		Int("signature_count", len(verifications)).
		Strs("signatures", signatures).
		Msg("DKIM check completed")

	return &domain.DKIMResult{
		Valid:      hasValidSignature,
		Signatures: signatures,
		Raw:        fmt.Sprintf("DKIM verification found %d signatures", len(verifications)),
	}, nil
}
