package auth

import (
	"context"
	"fmt"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"strings"
	"time"

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
func (d *dmarcChecker) CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DMARCResult, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		metrics.TrackDMARCDuration(duration)
	}()

	// Extract and validate From domain
	fromDomain, result := d.extractFromDomain(headers, logger)
	if result != nil {
		return result, nil
	}

	// Look up DMARC policy with domain hierarchy traversal
	record, actualDomain, lookupDetails, err := d.lookupDMARCRecord(fromDomain)
	if err != nil {
		return d.handleLookupError(err, fromDomain, lookupDetails, logger, metrics), nil
	}

	if record == nil {
		return d.handleNoRecordFound(fromDomain, lookupDetails, logger), nil
	}

	// Ensure we have valid SPF and DKIM results
	spfResult, dkimResult = d.ensureValidResults(spfResult, dkimResult)

	// Check SPF and DKIM alignment
	spfPass, spfAligned, spfDomain := d.checkSPFAlignment(spfResult, fromDomain, record)
	dkimPass, dkimAligned, dkimDomain := d.checkDKIMAlignmentAndExtractDomain(dkimResult, fromDomain, record)

	// Determine which policy to apply and update lookup details
	policyToApply, _ := d.determinePolicyToApply(record, actualDomain, fromDomain, lookupDetails)

	// Evaluate DMARC policy
	dmarcResult := d.evaluateDMARCPolicy(policyToApply, spfPass, spfAligned, dkimPass, dkimAligned)

	// Create result message and log
	rawMsg := d.createResultMessage(fromDomain, actualDomain, record, spfPass, spfAligned, dkimPass, dkimAligned, dmarcResult)
	d.logDMARCCheck(logger, dmarcResult, fromDomain, actualDomain, record, spfPass, spfAligned, dkimPass, dkimAligned, spfDomain)

	// Build and return final result
	return d.buildDMARCResult(record, actualDomain, policyToApply, dmarcResult, rawMsg, spfAligned, dkimAligned, spfDomain, dkimDomain, lookupDetails, metrics), nil
}

// extractFromDomain extracts and validates the From domain from headers
func (d *dmarcChecker) extractFromDomain(headers letters.Headers, logger observability.Logger) (string, *domain.DMARCResult) {
	if len(headers.From) == 0 || headers.From[0] == nil || len(headers.From[0].Address) == 0 {
		logger.Debug().Msg("DMARC check: No From header found")
		return "", &domain.DMARCResult{
			Result: "none",
			Raw:    "No From header found",
		}
	}
	fromHeader := headers.From[0].Address

	// RFC 7489: The domain in the RFC5322.From field is the primary identifier
	fromDomain := ExtractDomainFromEmail(fromHeader)
	if fromDomain == "" {
		logger.Debug().
			Str("from_header", fromHeader).
			Msg("DMARC check: No domain found in From header")
		return "", &domain.DMARCResult{
			Result: "none",
			Raw:    "No domain found in From header",
		}
	}

	return fromDomain, nil
}

// handleLookupError handles DMARC lookup errors
func (d *dmarcChecker) handleLookupError(err error, fromDomain string, lookupDetails []domain.DMARCLookupDetail, logger observability.Logger, metrics observability.MetricsCollector) *domain.DMARCResult {
	// Determine error type for metrics
	errorType := "dns_error"
	if strings.Contains(err.Error(), "timeout") {
		errorType = "timeout_error"
	} else if strings.Contains(err.Error(), "parse") {
		errorType = "parse_error"
	}
	metrics.TrackAuthError("dmarc", errorType)

	logger.Warn().
		Err(err).
		Str("domain", fromDomain).
		Msg("DMARC lookup error")
	return &domain.DMARCResult{
		Result:  "none",
		Raw:     fmt.Sprintf("DMARC lookup error: %v", err),
		Error:   err.Error(),
		Details: lookupDetails,
	}
}

// handleNoRecordFound handles the case when no DMARC record is found
func (d *dmarcChecker) handleNoRecordFound(fromDomain string, lookupDetails []domain.DMARCLookupDetail, logger observability.Logger) *domain.DMARCResult {
	logger.Debug().
		Str("domain", fromDomain).
		Msg("DMARC check: No record found")
	return &domain.DMARCResult{
		Result:  "none",
		Raw:     fmt.Sprintf("No DMARC record found for domain %s or its parent domains", fromDomain),
		Details: lookupDetails,
	}
}

// ensureValidResults ensures SPF and DKIM results are valid
func (d *dmarcChecker) ensureValidResults(spfResult *domain.SPFResult, dkimResult *domain.DKIMResult) (*domain.SPFResult, *domain.DKIMResult) {
	if spfResult == nil {
		// This shouldn't happen in normal flow, but handle gracefully
		spfResult = &domain.SPFResult{Result: "none"}
	}
	if dkimResult == nil {
		// This shouldn't happen in normal flow, but handle gracefully
		dkimResult = &domain.DKIMResult{Valid: false}
	}
	return spfResult, dkimResult
}

// checkSPFAlignment checks SPF alignment and returns pass status, alignment, and domain
func (d *dmarcChecker) checkSPFAlignment(spfResult *domain.SPFResult, fromDomain string, record *dmarc.Record) (bool, bool, string) {
	// RFC 7489: SPF identifier alignment
	// Check if SPF passes and the MAIL FROM domain aligns with From header domain
	spfPass := spfResult.Result == "pass"
	// Fix bug: Use SPF envelope sender domain for alignment check, not result string
	spfDomain := ExtractDomainFromEmail(spfResult.Sender)
	spfAligned := d.checkDomainAlignment(spfDomain, fromDomain, string(record.SPFAlignment))
	return spfPass, spfAligned, spfDomain
}

// checkDKIMAlignmentAndExtractDomain checks DKIM alignment and returns pass status, alignment, and domain
func (d *dmarcChecker) checkDKIMAlignmentAndExtractDomain(dkimResult *domain.DKIMResult, fromDomain string, record *dmarc.Record) (bool, bool, string) {
	// RFC 7489: DKIM identifier alignment
	// Check if any valid DKIM signature domain aligns with From header domain
	dkimPass := dkimResult.Valid
	dkimAligned := d.checkDKIMAlignment(dkimResult.Signatures, fromDomain, string(record.DKIMAlignment))
	dkimDomain := d.extractDKIMDomain(dkimResult.Signatures)
	return dkimPass, dkimAligned, dkimDomain
}

// determinePolicyToApply determines which policy to apply based on domain inheritance
func (d *dmarcChecker) determinePolicyToApply(record *dmarc.Record, actualDomain, fromDomain string, lookupDetails []domain.DMARCLookupDetail) (dmarc.Policy, string) {
	// Determine which policy to apply based on domain inheritance
	// If record was found at a parent domain and original domain is a subdomain, use sp= if present
	policyToApply := record.Policy
	policyUsed := "p"

	// Check if we found the record at a parent domain (inherited)
	if actualDomain != fromDomain {
		// Record was inherited from parent domain
		// Use subdomain policy (sp=) if present, otherwise fall back to main policy (p=)
		if record.SubdomainPolicy != "" {
			policyToApply = record.SubdomainPolicy
			policyUsed = "sp"
		}
	}

	// Update lookup details to show which policy was used
	for i := range lookupDetails {
		if lookupDetails[i].Domain == actualDomain {
			lookupDetails[i].PolicyUsed = policyUsed
			break
		}
	}

	return policyToApply, policyUsed
}

// evaluateDMARCPolicy evaluates the DMARC policy and returns the result
func (d *dmarcChecker) evaluateDMARCPolicy(policyToApply dmarc.Policy, spfPass, spfAligned, dkimPass, dkimAligned bool) string {
	// RFC 7489: DMARC policy evaluation
	// DMARC passes if either:
	// 1. SPF passes AND SPF identifier is aligned, OR
	// 2. DKIM passes AND at least one DKIM signature identifier is aligned
	dmarcPass := (spfPass && spfAligned) || (dkimPass && dkimAligned)

	switch policyToApply {
	case dmarc.PolicyNone:
		// RFC 7489: Policy "none" means monitor only - always report result but don't reject
		if dmarcPass {
			return "pass"
		}
		return "fail"
	case dmarc.PolicyQuarantine, dmarc.PolicyReject:
		// RFC 7489: For quarantine/reject policies, evaluate based on authentication results
		if dmarcPass {
			return "pass"
		}
		return "fail"
	default:
		return "none"
	}
}

// createResultMessage creates the result message for logging
func (d *dmarcChecker) createResultMessage(fromDomain, actualDomain string, record *dmarc.Record, spfPass, spfAligned, dkimPass, dkimAligned bool, result string) string {
	return fmt.Sprintf("DMARC evaluation for domain %s (policy found at %s): policy=%s, SPF pass=%v aligned=%v, DKIM pass=%v aligned=%v, result=%s",
		fromDomain, actualDomain, string(record.Policy), spfPass, spfAligned, dkimPass, dkimAligned, result)
}

// logDMARCCheck logs the DMARC check results
func (d *dmarcChecker) logDMARCCheck(logger observability.Logger, result, fromDomain, actualDomain string, record *dmarc.Record, spfPass, spfAligned, dkimPass, dkimAligned bool, spfDomain string) {
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
}

// buildDMARCResult builds the final DMARC result
func (d *dmarcChecker) buildDMARCResult(record *dmarc.Record, actualDomain string, policyToApply dmarc.Policy, result, rawMsg string, spfAligned, dkimAligned bool, spfDomain, dkimDomain string, lookupDetails []domain.DMARCLookupDetail, metrics observability.MetricsCollector) *domain.DMARCResult {
	// Handle percentage - use actual value from record or default to 100
	percentage := 100
	if record.Percent != nil {
		percentage = *record.Percent
	}

	// Convert failure options to string representation
	failureOptions := d.convertFailureOptionsToString(record.FailureOptions)

	// Track result by domain
	metrics.TrackDMARCResultByDomain(actualDomain, result)

	return &domain.DMARCResult{
		Result:          result,
		Raw:             rawMsg,
		Policy:          string(policyToApply),
		Domain:          actualDomain,
		Percentage:      percentage,
		SubdomainPolicy: string(record.SubdomainPolicy),
		SPFAligned:      spfAligned,
		DKIMAligned:     dkimAligned,
		SPFDomain:       spfDomain,
		DKIMDomain:      dkimDomain,
		Details:         lookupDetails,
		// RFC 7489 compliant additional fields
		SPFAlignment:   string(record.SPFAlignment),
		DKIMAlignment:  string(record.DKIMAlignment),
		FailureOptions: failureOptions,
		ReportURIs:     record.ReportURIAggregate,
		FailureURIs:    record.ReportURIFailure,
	}
}

// lookupDMARCRecord performs hierarchical DMARC record lookup per RFC 7489
func (d *dmarcChecker) lookupDMARCRecord(domainName string) (*dmarc.Record, string, []domain.DMARCLookupDetail, error) {
	currentDomain := domainName
	var details []domain.DMARCLookupDetail

	for {
		record, err := dmarc.Lookup(currentDomain)

		// Create lookup detail for this attempt
		detail := domain.DMARCLookupDetail{
			Domain: currentDomain,
		}

		if err == nil && record != nil {
			// Found a record
			detail.RecordFound = true
			details = append(details, detail)
			return record, currentDomain, details, nil
		}

		// Record not found or error occurred
		detail.RecordFound = false
		if err != nil {
			detail.Error = err.Error()
		}
		details = append(details, detail)

		// If the error is "dmarc: failed to lookup TXT record", continue as if not found
		if err != nil && strings.Contains(err.Error(), "dmarc: failed to lookup TXT record") {
			// continue down to parent domain
		} else if err != nil && !d.isDMARCNotFoundError(err) {
			// Early return for other errors (let outer logic handle)
			return nil, "", details, err
		}

		// RFC 7489: Move up the domain hierarchy
		nextDomain := d.getParentDomain(currentDomain)
		if nextDomain == "" || nextDomain == currentDomain {
			// Reached the top or can't go further
			break
		}
		currentDomain = nextDomain
	}

	return nil, "", details, nil
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
