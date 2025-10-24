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

// CheckSPF performs SPF authentication check following RFC 7208
func (s *spfChecker) CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string) (*domain.SPFResult, error) {
	if remoteIP == nil {
		log.Warn().Msg("SPF check: Failed to get remote IP")
		return &domain.SPFResult{
			Result:  "temperror",
			Raw:     "Failed to get remote IP",
			Problem: "No remote IP address available for SPF evaluation",
			Sender:  from,
		}, nil
	}

	if domainName == "" {
		log.Debug().
			Str("from", from).
			Msg("SPF check: No domain found in sender address")
		return &domain.SPFResult{
			Result:  "none",
			Raw:     "No domain found in sender address",
			Problem: "Unable to extract domain from MAIL FROM identity",
			Sender:  from,
		}, nil
	}

	// RFC 7208 Section 2.4: Check MAIL FROM identity
	result, mechanism, err := spf.CheckHost(remoteIP, domainName, from)
	if err != nil {
		log.Warn().
			Err(err).
			Str("domain", domainName).
			Str("remote_ip", remoteIP.String()).
			Str("identity", from).
			Msg("SPF check error")
		return &domain.SPFResult{
			Result:  "temperror",
			Raw:     fmt.Sprintf("SPF check error: %v", err),
			Problem: fmt.Sprintf("DNS lookup or processing error: %v", err),
			Sender:  from,
		}, nil
	}

	// Extract explanation if available (RFC 7208 Section 6.2)
	explanation := s.extractSPFExplanation(domainName, result)

	log.Debug().
		Str("result", result.String()).
		Str("domain", domainName).
		Str("remote_ip", remoteIP.String()).
		Str("mechanism", mechanism).
		Str("identity", from).
		Str("explanation", explanation).
		Msg("SPF check completed")

	return &domain.SPFResult{
		Result:      result.String(),
		Raw:         fmt.Sprintf("SPF result: %s for domain %s from IP %s", result.String(), domainName, remoteIP.String()),
		Mechanism:   mechanism,
		Explanation: explanation,
		Sender:      from,
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

// extractSPFExplanation attempts to extract explanation from SPF record (RFC 7208 Section 6.2)
func (s *spfChecker) extractSPFExplanation(domain string, result spf.Result) string {
	// For now, return empty string as the spf library doesn't expose explanation
	// In a full implementation, this would query the SPF record and extract the exp= tag
	// when the result is fail, softfail, or neutral
	resultStr := result.String()
	if resultStr == "fail" || resultStr == "softfail" || resultStr == "neutral" {
		log.Debug().
			Str("domain", domain).
			Str("result", resultStr).
			Msg("SPF explanation could be extracted from exp= tag in SPF record")
	}
	return ""
}
