package auth

import (
	"context"
	"fmt"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"strings"

	"github.com/emersion/go-msgauth/dmarc"
	"github.com/mnako/letters"
)

// dmarcChecker implements DMARCChecker interface
type dmarcChecker struct{}

// NewDMARCChecker creates a new DMARC checker
func NewDMARCChecker() DMARCChecker {
	return &dmarcChecker{}
}

// CheckDMARC performs DMARC authentication check with hierarchical domain lookup following RFC 7489
func (d *dmarcChecker) CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult, logger observability.Logger) (*domain.DMARCResult, error) {
	// Extract domain from From header (RFC5322.From) - this is what DMARC protects
	if len(headers.From) == 0 || headers.From[0] == nil || len(headers.From[0].Address) == 0 {
		logger.Debug().Msg("DMARC check: No From header found")
		return &domain.DMARCResult{
			Result: "none",
			Raw:    "No From header found",
		}, nil
	}
	fromHeader := headers.From[0].Address

	// RFC 7489: The domain in the RFC5322.From field is the primary identifier
	fromDomain := ExtractDomainFromEmail(fromHeader)
	if fromDomain == "" {
		logger.Debug().
			Str("from_header", fromHeader).
			Msg("DMARC check: No domain found in From header")
		return &domain.DMARCResult{
			Result: "none",
			Raw:    "No domain found in From header",
		}, nil
	}

	// Look up DMARC policy with domain hierarchy traversal
	record, actualDomain, err := d.lookupDMARCRecord(fromDomain)
	if err != nil {
		logger.Warn().
			Err(err).
			Str("domain", fromDomain).
			Msg("DMARC lookup error")
		return &domain.DMARCResult{
			Result: "none",
			Raw:    fmt.Sprintf("DMARC lookup error: %v", err),
			Error:  err.Error(),
		}, nil
	}

	if record == nil {
		logger.Debug().
			Str("domain", fromDomain).
			Msg("DMARC check: No record found")
		return &domain.DMARCResult{
			Result: "none",
			Raw:    fmt.Sprintf("No DMARC record found for domain %s or its parent domains", fromDomain),
		}, nil
	}

	// Use passed results or perform checks if not available
	if spfResult == nil {
		// This shouldn't happen in normal flow, but handle gracefully
		spfResult = &domain.SPFResult{Result: "none"}
	}
	if dkimResult == nil {
		// This shouldn't happen in normal flow, but handle gracefully
		dkimResult = &domain.DKIMResult{Valid: false}
	}

	// RFC 7489: SPF identifier alignment
	// Check if SPF passes and the MAIL FROM domain aligns with From header domain
	spfPass := spfResult.Result == "pass"
	// Fix bug: Use SPF envelope sender domain for alignment check, not result string
	spfDomain := ExtractDomainFromEmail(spfResult.Sender)
	spfAligned := d.checkDomainAlignment(spfDomain, fromDomain, string(record.SPFAlignment))

	// RFC 7489: DKIM identifier alignment
	// Check if any valid DKIM signature domain aligns with From header domain
	dkimPass := dkimResult.Valid
	dkimAligned := d.checkDKIMAlignment(dkimResult.Signatures, fromDomain, string(record.DKIMAlignment))

	// RFC 7489: DMARC policy evaluation
	// DMARC passes if either:
	// 1. SPF passes AND SPF identifier is aligned, OR
	// 2. DKIM passes AND at least one DKIM signature identifier is aligned
	var result string
	dmarcPass := (spfPass && spfAligned) || (dkimPass && dkimAligned)

	switch record.Policy {
	case dmarc.PolicyNone:
		// RFC 7489: Policy "none" means monitor only - always report result but don't reject
		if dmarcPass {
			result = "pass"
		} else {
			result = "fail"
		}
	case dmarc.PolicyQuarantine, dmarc.PolicyReject:
		// RFC 7489: For quarantine/reject policies, evaluate based on authentication results
		if dmarcPass {
			result = "pass"
		} else {
			result = "fail"
		}
	default:
		result = "none"
	}

	rawMsg := fmt.Sprintf("DMARC evaluation for domain %s (policy found at %s): policy=%s, SPF pass=%v aligned=%v, DKIM pass=%v aligned=%v, result=%s",
		fromDomain, actualDomain, string(record.Policy), spfPass, spfAligned, dkimPass, dkimAligned, result)

	logger.Debug().
		Str("result", result).
		Str("domain", fromDomain).
		Str("actual_domain", actualDomain).
		Str("policy", string(record.Policy)).
		Bool("spf_pass", spfPass).
		Bool("spf_aligned", spfAligned).
		Bool("dkim_pass", dkimPass).
		Bool("dkim_aligned", dkimAligned).
		Str("spf_domain", spfDomain).
		Msg("DMARC check completed")

	// Extract DKIM domain(s) for alignment
	dkimDomain := d.extractDKIMDomain(dkimResult.Signatures)

	// Handle percentage - use actual value from record or default to 100
	percentage := 100
	if record.Percent != nil {
		percentage = *record.Percent
	}

	// Convert failure options to string representation
	failureOptions := d.convertFailureOptionsToString(record.FailureOptions)

	return &domain.DMARCResult{
		Result:          result,
		Raw:             rawMsg,
		Policy:          string(record.Policy),
		Domain:          actualDomain,
		Percentage:      percentage,
		SubdomainPolicy: string(record.SubdomainPolicy),
		SPFAligned:      spfAligned,
		DKIMAligned:     dkimAligned,
		SPFDomain:       spfDomain,
		DKIMDomain:      dkimDomain,
		// RFC 7489 compliant additional fields
		SPFAlignment:   string(record.SPFAlignment),
		DKIMAlignment:  string(record.DKIMAlignment),
		FailureOptions: failureOptions,
		ReportURIs:     record.ReportURIAggregate,
		FailureURIs:    record.ReportURIFailure,
	}, nil
}

// lookupDMARCRecord performs hierarchical DMARC record lookup per RFC 7489
func (d *dmarcChecker) lookupDMARCRecord(domain string) (*dmarc.Record, string, error) {
	currentDomain := domain

	for {
		record, err := dmarc.Lookup(currentDomain)
		if err == nil && record != nil {
			return record, currentDomain, nil
		}
		// If the error is "dmarc: failed to lookup TXT record", continue as if not found
		if err != nil && strings.Contains(err.Error(), "dmarc: failed to lookup TXT record") {
			// continue down to parent domain
		} else if err != nil && !d.isDMARCNotFoundError(err) {
			// Early return for other errors (let outer logic handle)
			return nil, "", err
		}

		// RFC 7489: Move up the domain hierarchy
		nextDomain := d.getParentDomain(currentDomain)
		if nextDomain == "" || nextDomain == currentDomain {
			// Reached the top or can't go further
			break
		}
		currentDomain = nextDomain
	}

	return nil, "", nil
}

// getParentDomain returns the parent domain or empty string if at top level
func (d *dmarcChecker) getParentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		// Already at top level domain (e.g., "example.com")
		return ""
	}

	// Remove the leftmost subdomain
	return strings.Join(parts[1:], ".")
}

// isDMARCNotFoundError checks if the error indicates DMARC record not found
func (d *dmarcChecker) isDMARCNotFoundError(err error) bool {
	errorMsg := strings.ToLower(err.Error())
	return strings.Contains(errorMsg, "not found") ||
		strings.Contains(errorMsg, "no such host") ||
		strings.Contains(errorMsg, "nxdomain") ||
		strings.Contains(errorMsg, "no data")
}

// checkDomainAlignment checks if domains are aligned according to DMARC alignment mode per RFC 7489
func (d *dmarcChecker) checkDomainAlignment(authDomain, fromDomain string, alignment string) bool {
	// RFC 7489: Domain alignment verification
	if authDomain == "" || fromDomain == "" {
		return false
	}

	if alignment == string(dmarc.AlignmentStrict) || alignment == "s" {
		// RFC 7489: Strict alignment requires exact domain match (case insensitive)
		return strings.EqualFold(authDomain, fromDomain)
	}
	// RFC 7489: Relaxed alignment allows organizational domain match
	return d.isOrganizationalDomainMatch(authDomain, fromDomain)
}

// checkDKIMAlignment checks DKIM signature alignment per RFC 7489
func (d *dmarcChecker) checkDKIMAlignment(signatures []string, fromDomain string, alignment string) bool {
	// RFC 7489: At least one valid DKIM signature must be aligned
	for _, sig := range signatures {
		if strings.HasPrefix(sig, "Valid: ") {
			sigDomain := strings.TrimPrefix(sig, "Valid: ")
			if d.checkDomainAlignment(sigDomain, fromDomain, alignment) {
				return true
			}
		}
	}
	return false
}

// isOrganizationalDomainMatch checks if two domains belong to the same organization per RFC 7489
func (d *dmarcChecker) isOrganizationalDomainMatch(domain1, domain2 string) bool {
	// RFC 7489: Organizational domain matching for relaxed alignment
	// NOTE: Production implementation should use Public Suffix List (PSL)
	// This is a simplified implementation for basic organizational domain matching

	domain1 = strings.ToLower(domain1)
	domain2 = strings.ToLower(domain2)

	if domain1 == domain2 {
		return true
	}

	// Get organizational domains (simplified - should use PSL in production)
	orgDomain1 := d.getOrganizationalDomain(domain1)
	orgDomain2 := d.getOrganizationalDomain(domain2)

	return orgDomain1 == orgDomain2 && orgDomain1 != ""
}

// getOrganizationalDomain extracts the organizational domain
// NOTE: This is a simplified implementation. Production should use Public Suffix List
func (d *dmarcChecker) getOrganizationalDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}

	// Simple heuristic: take last two parts as organizational domain
	// In production, use Public Suffix List to determine the actual organizational domain
	return strings.Join(parts[len(parts)-2:], ".")
}

// extractDKIMDomain extracts domain(s) from DKIM signatures for alignment reporting
func (d *dmarcChecker) extractDKIMDomain(signatures []string) string {
	var domains []string
	for _, sig := range signatures {
		if strings.HasPrefix(sig, "Valid: ") {
			domain := strings.TrimPrefix(sig, "Valid: ")
			domains = append(domains, domain)
		}
	}
	// Return comma-separated list of domains
	return strings.Join(domains, ",")
}

// convertFailureOptionsToString converts DMARC failure options to string representation per RFC 7489
func (d *dmarcChecker) convertFailureOptionsToString(options dmarc.FailureOptions) string {
	var parts []string

	if options&dmarc.FailureAll != 0 {
		parts = append(parts, "0")
	}
	if options&dmarc.FailureAny != 0 {
		parts = append(parts, "1")
	}
	if options&dmarc.FailureDKIM != 0 {
		parts = append(parts, "d")
	}
	if options&dmarc.FailureSPF != 0 {
		parts = append(parts, "s")
	}

	if len(parts) == 0 {
		return "0" // Default to "0" (all) if no options specified
	}

	return strings.Join(parts, ":")
}
