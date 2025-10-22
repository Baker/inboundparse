package auth

import (
	"context"
	"fmt"
	"inboundparse/internal/domain"
	"net"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/zaccone/spf"
)

// spfChecker implements SPFChecker interface
type spfChecker struct{}

// NewSPFChecker creates a new SPF checker
func NewSPFChecker() SPFChecker {
	return &spfChecker{}
}

// CheckSPF performs SPF authentication check
func (s *spfChecker) CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string) (*domain.SPFResult, error) {
	if remoteIP == nil {
		log.Warn().Msg("SPF check: Failed to get remote IP")
		return &domain.SPFResult{
			Result: "temperror",
			Raw:    "Failed to get remote IP",
		}, nil
	}

	if domainName == "" {
		log.Debug().
			Str("from", from).
			Msg("SPF check: No domain found in sender address")
		return &domain.SPFResult{
			Result: "none",
			Raw:    "No domain found in sender address",
		}, nil
	}

	result, mechanism, err := spf.CheckHost(remoteIP, domainName, from)
	if err != nil {
		log.Warn().
			Err(err).
			Str("domain", domainName).
			Str("remote_ip", remoteIP.String()).
			Msg("SPF check error")
		return &domain.SPFResult{
			Result: "temperror",
			Raw:    fmt.Sprintf("SPF check error: %v", err),
		}, nil
	}

	log.Debug().
		Str("result", result.String()).
		Str("domain", domainName).
		Str("remote_ip", remoteIP.String()).
		Str("mechanism", mechanism).
		Msg("SPF check completed")

	return &domain.SPFResult{
		Result:    result.String(),
		Raw:       fmt.Sprintf("SPF result: %s for domain %s from IP %s", result.String(), domainName, remoteIP.String()),
		Mechanism: mechanism,
	}, nil
}

// ExtractDomainFromEmail extracts the domain part from an email address
func ExtractDomainFromEmail(email string) string {
	// Handle both raw email addresses and formatted addresses
	email = strings.Trim(email, "<>")

	// Remove display name if present (e.g., "John Doe <john@example.com>")
	if angleStart := strings.LastIndex(email, "<"); angleStart != -1 {
		if angleEnd := strings.LastIndex(email, ">"); angleEnd > angleStart {
			email = email[angleStart+1 : angleEnd]
		}
	}

	// Find @ symbol
	atIndex := strings.LastIndex(email, "@")
	if atIndex == -1 {
		return ""
	}

	domain := email[atIndex+1:]

	// Remove any trailing whitespace or special characters
	domain = strings.TrimSpace(domain)

	return domain
}
