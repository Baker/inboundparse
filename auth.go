package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/mnako/letters"
	"github.com/zaccone/spf"
)

// Test hooks for external auth lookups; overridden in tests
var (
	dkimVerifyFn   = dkim.Verify
	dmarcLookupFn  = dmarc.Lookup
	spfCheckHostFn = spf.CheckHost
)

// checkSPF performs SPF authentication check
func (mp *MessageProcessor) checkSPF() *SPFResult {
	remoteIP := mp.getRemoteIP()
	if remoteIP == nil {
		return &SPFResult{
			Result: "temperror",
			Raw:    "Failed to get remote IP",
		}
	}

	// Extract domain from MAIL FROM (envelope sender)
	domain := mp.extractDomainFromEmail(mp.from)
	if domain == "" {
		return &SPFResult{
			Result: "none",
			Raw:    "No domain found in sender address",
		}
	}

	result, mechanism, err := spfCheckHostFn(remoteIP, domain, mp.from)
	if err != nil {
		return &SPFResult{
			Result: "temperror",
			Raw:    fmt.Sprintf("SPF check error: %v", err),
		}
	}

	return &SPFResult{
		Result:    result.String(),
		Raw:       fmt.Sprintf("SPF result: %s for domain %s from IP %s", result.String(), domain, remoteIP.String()),
		Mechanism: mechanism,
	}
}

// checkDKIM performs DKIM authentication check
func (mp *MessageProcessor) checkDKIM(rawMessage string) *DKIMResult {
	verifications, err := dkimVerifyFn(strings.NewReader(rawMessage))
	if err != nil {
		return &DKIMResult{
			Valid: false,
			Raw:   fmt.Sprintf("DKIM verification error: %v", err),
			Error: err.Error(),
		}
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

	return &DKIMResult{
		Valid:      hasValidSignature,
		Signatures: signatures,
		Raw:        fmt.Sprintf("DKIM verification found %d signatures", len(verifications)),
	}
}

// checkDMARC performs DMARC authentication check with hierarchical domain lookup following RFC 7489
func (mp *MessageProcessor) checkDMARC(rawMessage string, headers letters.Headers, spfResult *SPFResult, dkimResult *DKIMResult) *DMARCResult {
	// Extract domain from From header (RFC5322.From) - this is what DMARC protects
	if len(headers.From) == 0 || headers.From[0] == nil || len(headers.From[0].Address) == 0 {
		return &DMARCResult{
			Result: "none",
			Raw:    "No From header found",
		}
	}
	fromHeader := headers.From[0].Address

	// RFC 7489: The domain in the RFC5322.From field is the primary identifier
	fromDomain := mp.extractDomainFromEmail(fromHeader)
	if fromDomain == "" {
		return &DMARCResult{
			Result: "none",
			Raw:    "No domain found in From header",
		}
	}

	// Look up DMARC policy with domain hierarchy traversal
	record, actualDomain, err := mp.lookupDMARCRecord(fromDomain)
	if err != nil {
		return &DMARCResult{
			Result: "none",
			Raw:    fmt.Sprintf("DMARC lookup error: %v", err),
			Error:  err.Error(),
		}
	}

	if record == nil {
		return &DMARCResult{
			Result: "none",
			Raw:    fmt.Sprintf("No DMARC record found for domain %s or its parent domains", fromDomain),
		}
	}

	// Use passed results or perform checks if not available
	if spfResult == nil {
		spfResult = mp.checkSPF()
	}
	if dkimResult == nil {
		dkimResult = mp.checkDKIM(rawMessage)
	}

	// RFC 7489: SPF identifier alignment
	// Check if SPF passes and the MAIL FROM domain aligns with From header domain
	spfPass := spfResult.Result == "pass"
	spfDomain := mp.extractDomainFromEmail(mp.from) // MAIL FROM domain
	spfAligned := mp.checkDomainAlignment(spfDomain, fromDomain, string(record.SPFAlignment))

	// RFC 7489: DKIM identifier alignment
	// Check if any valid DKIM signature domain aligns with From header domain
	dkimPass := dkimResult.Valid
	dkimAligned := mp.checkDKIMAlignment(dkimResult.Signatures, fromDomain, string(record.DKIMAlignment))

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

	return &DMARCResult{
		Result: result,
		Raw:    rawMsg,
		Policy: string(record.Policy),
	}
}

// lookupDMARCRecord performs hierarchical DMARC record lookup per RFC 7489
func (mp *MessageProcessor) lookupDMARCRecord(domain string) (*dmarc.Record, string, error) {
	currentDomain := domain

	for {
		record, err := dmarcLookupFn(currentDomain)
		if err == nil && record != nil {
			return record, currentDomain, nil
		}

		// If there was an error other than "not found", return it
		if err != nil && !mp.isDMARCNotFoundError(err) {
			return nil, "", err
		}

		// RFC 7489: Move up the domain hierarchy
		nextDomain := mp.getParentDomain(currentDomain)
		if nextDomain == "" || nextDomain == currentDomain {
			// Reached the top or can't go further
			break
		}
		currentDomain = nextDomain
	}

	return nil, "", nil
}

// getParentDomain returns the parent domain or empty string if at top level
func (mp *MessageProcessor) getParentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		// Already at top level domain (e.g., "example.com")
		return ""
	}

	// Remove the leftmost subdomain
	return strings.Join(parts[1:], ".")
}

// isDMARCNotFoundError checks if the error indicates DMARC record not found
func (mp *MessageProcessor) isDMARCNotFoundError(err error) bool {
	errorMsg := strings.ToLower(err.Error())
	return strings.Contains(errorMsg, "not found") ||
		strings.Contains(errorMsg, "no such host") ||
		strings.Contains(errorMsg, "nxdomain") ||
		strings.Contains(errorMsg, "no data")
}

// checkDomainAlignment checks if domains are aligned according to DMARC alignment mode per RFC 7489
func (mp *MessageProcessor) checkDomainAlignment(authDomain, fromDomain string, alignment string) bool {
	// RFC 7489: Domain alignment verification
	if authDomain == "" || fromDomain == "" {
		return false
	}

	if alignment == string(dmarc.AlignmentStrict) || alignment == "s" {
		// RFC 7489: Strict alignment requires exact domain match (case insensitive)
		return strings.EqualFold(authDomain, fromDomain)
	}
	// RFC 7489: Relaxed alignment allows organizational domain match
	return mp.isOrganizationalDomainMatch(authDomain, fromDomain)
}

// checkDKIMAlignment checks DKIM signature alignment per RFC 7489
func (mp *MessageProcessor) checkDKIMAlignment(signatures []string, fromDomain string, alignment string) bool {
	// RFC 7489: At least one valid DKIM signature must be aligned
	for _, sig := range signatures {
		if strings.HasPrefix(sig, "Valid: ") {
			sigDomain := strings.TrimPrefix(sig, "Valid: ")
			if mp.checkDomainAlignment(sigDomain, fromDomain, alignment) {
				return true
			}
		}
	}
	return false
}

// isOrganizationalDomainMatch checks if two domains belong to the same organization per RFC 7489
func (mp *MessageProcessor) isOrganizationalDomainMatch(domain1, domain2 string) bool {
	// RFC 7489: Organizational domain matching for relaxed alignment
	// NOTE: Production implementation should use Public Suffix List (PSL)
	// This is a simplified implementation for basic organizational domain matching

	domain1 = strings.ToLower(domain1)
	domain2 = strings.ToLower(domain2)

	if domain1 == domain2 {
		return true
	}

	// Get organizational domains (simplified - should use PSL in production)
	orgDomain1 := mp.getOrganizationalDomain(domain1)
	orgDomain2 := mp.getOrganizationalDomain(domain2)

	return orgDomain1 == orgDomain2 && orgDomain1 != ""
}

// getOrganizationalDomain extracts the organizational domain
// NOTE: This is a simplified implementation. Production should use Public Suffix List
func (mp *MessageProcessor) getOrganizationalDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}

	// Simple heuristic: take last two parts as organizational domain
	// In production, use Public Suffix List to determine the actual organizational domain
	return strings.Join(parts[len(parts)-2:], ".")
}

// getRemoteIP extracts the remote IP address from the connection
func (mp *MessageProcessor) getRemoteIP() net.IP {
	if mp.testRemoteIP != nil {
		return mp.testRemoteIP
	}
	if mp.conn != nil && mp.conn.Conn() != nil {
		addr := mp.conn.Conn().RemoteAddr()
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			return tcpAddr.IP
		}
	}
	return nil
}

// extractDomainFromEmail extracts the domain part from an email address
func (mp *MessageProcessor) extractDomainFromEmail(email string) string {
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
