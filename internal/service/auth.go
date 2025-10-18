package service

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/zaccone/spf"
)

// authService implements the AuthService interface
type authService struct {
	enableSPF   bool
	enableDKIM  bool
	enableDMARC bool
}

// NewAuthService creates a new authentication service
func NewAuthService(enableSPF, enableDKIM, enableDMARC bool) AuthService {
	return &authService{
		enableSPF:   enableSPF,
		enableDKIM:  enableDKIM,
		enableDMARC: enableDMARC,
	}
}

// PerformAuthenticationChecks performs SPF, DKIM, and DMARC authentication checks (RFC 7208, 6376, 7489)
func (a *authService) PerformAuthenticationChecks(ctx context.Context, message []byte, remoteIP net.IP, heloName string, mailFrom string) (*AuthResult, error) {
	result := &AuthResult{}

	// Perform SPF check (RFC 7208)
	if a.enableSPF {
		spfResult := a.checkSPF(message, remoteIP, heloName, mailFrom)
		result.SPF = spfResult
	}

	// Perform DKIM check (RFC 6376)
	if a.enableDKIM {
		dkimResult := a.checkDKIM(message)
		result.DKIM = dkimResult
	}

	// Perform DMARC check (RFC 7489)
	// DMARC requires SPF or DKIM results for alignment checking
	if a.enableDMARC && (a.enableSPF || a.enableDKIM) {
		dmarcResult := a.checkDMARC(message, result.SPF, result.DKIM, mailFrom)
		result.DMARC = dmarcResult
	}

	return result, nil
}

// checkSPF performs SPF validation (RFC 7208)
func (a *authService) checkSPF(message []byte, remoteIP net.IP, heloName string, mailFrom string) *SPFResult {
	// RFC 7208 §2.3: Check MAIL FROM (envelope sender) first
	// RFC 7208 §2.4: Fall back to HELO/EHLO domain if MAIL FROM is empty

	var checkDomain string
	var sender string

	// Extract local part and domain from mailFrom
	if mailFrom != "" {
		// Parse envelope sender
		if idx := strings.LastIndex(mailFrom, "@"); idx != -1 {
			checkDomain = mailFrom[idx+1:]
			sender = mailFrom
		} else if mailFrom == "<>" || mailFrom == "" {
			// Null sender, use HELO domain per RFC 7208 §2.4
			checkDomain = heloName
			sender = "postmaster@" + heloName
		}
	}

	// If still no domain, use HELO domain
	if checkDomain == "" && heloName != "" {
		checkDomain = heloName
		sender = "postmaster@" + heloName
	}

	// If no domain available, return none
	if checkDomain == "" {
		return &SPFResult{
			Result: "none",
			Error:  "no domain available for SPF check",
		}
	}

	// Perform SPF check using the library
	result, explanation, err := spf.CheckHost(remoteIP, checkDomain, sender)
	if err != nil {
		return &SPFResult{
			Result: "temperror",
			Domain: checkDomain,
			Error:  err.Error(),
		}
	}

	// Map result to RFC 7208 §2.6 values
	spfResultStr := strings.ToLower(result.String())

	return &SPFResult{
		Result:      spfResultStr,
		Domain:      checkDomain,
		Explanation: explanation,
	}
}

// checkDKIM performs DKIM validation (RFC 6376)
func (a *authService) checkDKIM(message []byte) *DKIMResult {
	// RFC 6376 §6.1: Verify all DKIM signatures in the message
	// Return "pass" if ANY signature validates successfully

	// Use VerifyWithOptions to validate DKIM signatures with max 2 verifications
	options := &dkim.VerifyOptions{
		MaxVerifications: 2, // Limit to 2 signature verifications as specified in plan
	}

	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(message), options)
	if err != nil {
		return &DKIMResult{
			Result: "temperror",
			Error:  err.Error(),
		}
	}

	// No signatures found
	if len(verifications) == 0 {
		return &DKIMResult{
			Result: "none",
			Body:   "no DKIM signatures found",
		}
	}

	// Process all signatures
	signatures := make([]DKIMSignature, 0, len(verifications))
	hasPass := false

	for _, v := range verifications {
		sigResult := "fail"
		sigError := ""

		if v.Err == nil {
			sigResult = "pass"
			hasPass = true
		} else {
			sigError = v.Err.Error()
		}

		// Extract signature details
		// Note: go-msgauth provides Domain and Identifier, but not Selector separately
		// The Identifier contains the full AUID (e.g., user@domain)
		sig := DKIMSignature{
			Domain: v.Domain,
			Result: sigResult,
			Error:  sigError,
		}

		// Add canonicalization info if HeaderKeys is available (indicates signature was parsed)
		if len(v.HeaderKeys) > 0 {
			sig.Canonicalization = fmt.Sprintf("signed headers: %d", len(v.HeaderKeys))
		}

		signatures = append(signatures, sig)
	}

	// Determine overall result per RFC 6376 §6.1
	overallResult := "fail"
	body := "all signatures failed verification"
	if hasPass {
		overallResult = "pass"
		body = "at least one signature passed verification"
	}

	return &DKIMResult{
		Result:     overallResult,
		Signatures: signatures,
		Body:       body,
	}
}

// checkDMARC performs DMARC validation (RFC 7489)
func (a *authService) checkDMARC(message []byte, spfResult *SPFResult, dkimResult *DKIMResult, mailFrom string) *DMARCResult {
	// Extract RFC5322.From domain from message header
	fromDomain, err := a.extractDomainFromMessage(message)
	if err != nil {
		return &DMARCResult{
			Result: "none",
			Error:  "failed to extract domain from header From",
		}
	}

	// Look up DMARC record
	record, err := dmarc.Lookup(fromDomain)
	if err != nil {
		return &DMARCResult{
			Result: "temperror",
			Error:  fmt.Sprintf("DMARC lookup failed: %v", err),
		}
	}

	if record == nil {
		return &DMARCResult{
			Result: "none",
			Error:  "no DMARC record found",
		}
	}

	// RFC 7489 §3.1: Check identifier alignment
	spfAligned := false
	dkimAligned := false

	// SPF alignment check (RFC 7489 §3.1.1)
	if spfResult != nil && spfResult.Result == "pass" {
		spfAligned = a.checkAlignment(mailFrom, fromDomain, record.SPFAlignment)
	}

	// DKIM alignment check (RFC 7489 §3.1.2)
	if dkimResult != nil && dkimResult.Result == "pass" {
		// Check if any passing DKIM signature aligns with RFC5322.From
		for _, sig := range dkimResult.Signatures {
			if sig.Result == "pass" {
				if a.checkAlignment(sig.Domain, fromDomain, record.DKIMAlignment) {
					dkimAligned = true
					break
				}
			}
		}
	}

	// RFC 7489 §6.6.2: Evaluate DMARC policy
	// At least one identifier must align for DMARC to pass
	dmarcResult := "fail"
	if spfAligned || dkimAligned {
		dmarcResult = "pass"
	}

	// Build alignment status strings
	spfAlignmentStr := "fail"
	if spfAligned {
		spfAlignmentStr = fmt.Sprintf("pass (%s)", record.SPFAlignment)
	} else if spfResult != nil {
		spfAlignmentStr = fmt.Sprintf("fail (%s)", record.SPFAlignment)
	}

	dkimAlignmentStr := "fail"
	if dkimAligned {
		dkimAlignmentStr = fmt.Sprintf("pass (%s)", record.DKIMAlignment)
	} else if dkimResult != nil {
		dkimAlignmentStr = fmt.Sprintf("fail (%s)", record.DKIMAlignment)
	}

	// Extract policy details
	percentage := 100
	if record.Percent != nil {
		percentage = *record.Percent
	}

	subdomainPolicy := string(record.Policy) // Default to main policy
	if record.SubdomainPolicy != "" {
		subdomainPolicy = string(record.SubdomainPolicy)
	}

	return &DMARCResult{
		Result:          dmarcResult,
		Policy:          string(record.Policy),
		SubdomainPolicy: subdomainPolicy,
		Percentage:      percentage,
		SPFAlignment:    spfAlignmentStr,
		DKIMAlignment:   dkimAlignmentStr,
	}
}

// checkAlignment checks if two domains align according to DMARC alignment mode (RFC 7489 §3.1)
func (a *authService) checkAlignment(identifierDomain, fromDomain string, mode dmarc.AlignmentMode) bool {
	// Extract domain from identifier if it contains @
	if idx := strings.LastIndex(identifierDomain, "@"); idx != -1 {
		identifierDomain = identifierDomain[idx+1:]
	}

	// Normalize domains to lowercase
	identifierDomain = strings.ToLower(strings.TrimSpace(identifierDomain))
	fromDomain = strings.ToLower(strings.TrimSpace(fromDomain))

	// Strict alignment: exact match
	if mode == dmarc.AlignmentStrict {
		return identifierDomain == fromDomain
	}

	// Relaxed alignment (default): organizational domain match
	// For simplicity, we check if they're the same or if one is a subdomain of the other
	if identifierDomain == fromDomain {
		return true
	}

	// Check if identifierDomain is a subdomain of fromDomain or vice versa
	// Extract organizational domain (simple implementation)
	idOrgDomain := a.getOrganizationalDomain(identifierDomain)
	fromOrgDomain := a.getOrganizationalDomain(fromDomain)

	return idOrgDomain == fromOrgDomain
}

// getOrganizationalDomain extracts the organizational domain (simplified)
// For a full implementation, use the Public Suffix List
func (a *authService) getOrganizationalDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	// Return last two labels (simple heuristic)
	return strings.Join(parts[len(parts)-2:], ".")
}

// extractDomainFromMessage extracts the sender domain from an email message
func (a *authService) extractDomainFromMessage(message []byte) (string, error) {
	// This is a simplified implementation
	// In a real implementation, you'd properly parse the email headers
	lines := strings.Split(string(message), "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "from:") {
			email := strings.TrimSpace(strings.TrimPrefix(line, "From:"))

			// Handle display name format: "Display Name <email@domain.com>"
			if strings.Contains(email, "<") && strings.Contains(email, ">") {
				start := strings.Index(email, "<")
				end := strings.Index(email, ">")
				if start != -1 && end != -1 && end > start {
					email = email[start+1 : end]
				}
			}

			// Extract domain from email
			if idx := strings.LastIndex(email, "@"); idx != -1 {
				domain := email[idx+1:]
				// Remove any trailing characters like '>'
				domain = strings.TrimRight(domain, ">")
				return domain, nil
			}
		}
	}
	return "", fmt.Errorf("no From header found")
}
