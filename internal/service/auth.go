package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/zaccone/spf"
	"go.uber.org/zap"
)

// authService implements the AuthService interface
type authService struct {
	enableSPF   bool
	enableDKIM  bool
	enableDMARC bool
	logger      LoggerService
}

// NewAuthService creates a new authentication service
func NewAuthService(enableSPF, enableDKIM, enableDMARC bool, logger LoggerService) AuthService {
	return &authService{
		enableSPF:   enableSPF,
		enableDKIM:  enableDKIM,
		enableDMARC: enableDMARC,
		logger:      logger,
	}
}

// PerformAuthenticationChecks performs SPF, DKIM, and DMARC authentication checks
func (a *authService) PerformAuthenticationChecks(ctx context.Context, message []byte, remoteIP net.IP) (*AuthResult, error) {
	result := &AuthResult{}

	if a.logger != nil {
		a.logger.Info(ctx, "starting authentication checks",
			zap.String("remote_ip", remoteIP.String()),
			zap.Bool("spf_enabled", a.enableSPF),
			zap.Bool("dkim_enabled", a.enableDKIM),
			zap.Bool("dmarc_enabled", a.enableDMARC),
		)
	}

	// Extract email domains for validation
	fromDomain, err := a.extractDomainFromMessage(message)
	if err != nil && a.logger != nil {
		a.logger.Warn(ctx, "failed to extract domain from message", zap.Error(err))
	}

	// Perform SPF check
	if a.enableSPF && remoteIP != nil {
		result.SPF = a.checkSPF(ctx, message, remoteIP, fromDomain)
	}

	// Perform DKIM check
	if a.enableDKIM {
		result.DKIM = a.checkDKIM(ctx, message)
	}

	// Perform DMARC check
	if a.enableDMARC {
		result.DMARC = a.checkDMARC(ctx, message, fromDomain, result.SPF, result.DKIM)
	}

	if a.logger != nil {
		a.logger.Info(ctx, "authentication checks completed",
			zap.Bool("spf_performed", result.SPF != nil),
			zap.Bool("dkim_performed", result.DKIM != nil),
			zap.Bool("dmarc_performed", result.DMARC != nil),
		)
	}

	return result, nil
}

// checkSPF performs SPF validation per RFC 7208
func (a *authService) checkSPF(ctx context.Context, message []byte, remoteIP net.IP, fromDomain string) *SPFResult {
	result := &SPFResult{
		SenderDomain: fromDomain,
	}

	if fromDomain == "" {
		result.Result = "none"
		result.Error = "no sender domain found"
		if a.logger != nil {
			a.logger.Warn(ctx, "SPF check skipped: no sender domain", zap.String("remote_ip", remoteIP.String()))
		}
		return result
	}

	if a.logger != nil {
		a.logger.Debug(ctx, "performing SPF check",
			zap.String("domain", fromDomain),
			zap.String("remote_ip", remoteIP.String()),
		)
	}

	// Perform SPF check using RFC 7208 compliant library
	spfResult, explanation, err := spf.CheckHost(remoteIP, fromDomain, "")
	if err != nil {
		result.Result = "temperror"
		result.Error = fmt.Sprintf("SPF check failed: %v", err)
		if a.logger != nil {
			a.logger.Error(ctx, "SPF check error",
				zap.String("domain", fromDomain),
				zap.String("remote_ip", remoteIP.String()),
				zap.Error(err),
			)
		}
		return result
	}

	// Map SPF result to standard RFC 7208 result codes
	result.Result = strings.ToLower(spfResult.String())
	result.Explanation = explanation

	// Try to get the SPF record for additional context
	// Note: the zaccone/spf library doesn't expose the raw record directly
	// but we can indicate the mechanism that matched based on the result
	switch result.Result {
	case "pass":
		result.Mechanism = "matched"
	case "fail":
		result.Mechanism = "fail"
	case "softfail":
		result.Mechanism = "softfail"
	case "neutral":
		result.Mechanism = "neutral"
	}

	if a.logger != nil {
		a.logger.Info(ctx, "SPF check completed",
			zap.String("domain", fromDomain),
			zap.String("remote_ip", remoteIP.String()),
			zap.String("result", result.Result),
			zap.String("explanation", result.Explanation),
		)
	}

	return result
}

// checkDKIM performs DKIM validation per RFC 6376
func (a *authService) checkDKIM(ctx context.Context, message []byte) *DKIMResult {
	result := &DKIMResult{
		Signatures: make([]*DKIMSignature, 0),
		Result:     "none",
	}

	if a.logger != nil {
		a.logger.Debug(ctx, "performing DKIM verification")
	}

	// Parse and verify all DKIM signatures in the message
	verifications, err := dkim.Verify(bytes.NewReader(message))
	if err != nil {
		// If we can't even parse the message, return error
		if err == io.EOF || strings.Contains(err.Error(), "no signatures") {
			result.Result = "none"
			result.Error = "no DKIM signatures found"
		} else {
			result.Result = "temperror"
			result.Error = fmt.Sprintf("DKIM verification failed: %v", err)
		}

		if a.logger != nil {
			a.logger.Warn(ctx, "DKIM verification error", zap.Error(err))
		}
		return result
	}

	// Process each signature verification result
	hasValidSignature := false
	for _, v := range verifications {
		sig := &DKIMSignature{
			Domain:   v.Domain,
			Identity: v.Identifier,
			Result:   "fail", // Default to fail
		}

		// Set timestamps if available
		if !v.Time.IsZero() {
			sig.Timestamp = v.Time.Unix()
		}
		if !v.Expiration.IsZero() {
			sig.Expiration = v.Expiration.Unix()
		}

		// Set headers signed
		if len(v.HeaderKeys) > 0 {
			sig.HeadersSigned = v.HeaderKeys
		}

		// Determine result
		if v.Err == nil {
			sig.Result = "pass"
			hasValidSignature = true
		} else {
			sig.Result = "fail"
			sig.Error = v.Err.Error()
		}

		// Add canonicalization as default - actual value would need header parsing
		sig.Canonicalization = "simple/simple" // Default per RFC 6376

		// Add signature to results
		result.Signatures = append(result.Signatures, sig)

		if a.logger != nil {
			a.logger.Info(ctx, "DKIM signature verified",
				zap.String("domain", sig.Domain),
				zap.String("identity", sig.Identity),
				zap.String("result", sig.Result),
				zap.String("error", sig.Error),
				zap.Strings("headers_signed", sig.HeadersSigned),
			)
		}
	}

	// Set overall result based on RFC 6376: pass if at least one signature is valid
	switch {
	case hasValidSignature:
		result.Result = "pass"
	case len(result.Signatures) > 0:
		result.Result = "fail"
	default:
		result.Result = "none"
	}

	if a.logger != nil {
		a.logger.Info(ctx, "DKIM verification completed",
			zap.Int("signatures_found", len(result.Signatures)),
			zap.String("overall_result", result.Result),
		)
	}

	return result
}

// checkDMARC performs DMARC validation per RFC 7489
func (a *authService) checkDMARC(ctx context.Context, message []byte, fromDomain string, spfResult *SPFResult, dkimResult *DKIMResult) *DMARCResult {
	result := &DMARCResult{
		Domain:      fromDomain,
		Result:      "none",
		SPFAligned:  false,
		DKIMAligned: false,
	}

	if fromDomain == "" {
		result.Error = "no sender domain found"
		if a.logger != nil {
			a.logger.Warn(ctx, "DMARC check skipped: no sender domain")
		}
		return result
	}

	if a.logger != nil {
		a.logger.Debug(ctx, "performing DMARC check", zap.String("domain", fromDomain))
	}

	// Look up DMARC record per RFC 7489 section 6.6
	record, err := dmarc.Lookup(fromDomain)
	if err != nil {
		result.Result = "temperror"
		result.Error = fmt.Sprintf("DMARC lookup failed: %v", err)
		if a.logger != nil {
			a.logger.Error(ctx, "DMARC lookup error",
				zap.String("domain", fromDomain),
				zap.Error(err),
			)
		}
		return result
	}

	if record == nil {
		result.Result = "none"
		if a.logger != nil {
			a.logger.Info(ctx, "no DMARC record found", zap.String("domain", fromDomain))
		}
		return result
	}

	// Parse DMARC record details
	a.parseDMARCRecordDetails(record, result)

	// Check alignments per RFC 7489 section 3.1
	a.checkAlignments(fromDomain, spfResult, dkimResult, result)

	// Determine DMARC result per RFC 7489 section 6.7
	// DMARC passes if either SPF or DKIM is aligned and passes
	if result.SPFAligned || result.DKIMAligned {
		result.Result = "pass"
	} else {
		result.Result = "fail"
	}

	if a.logger != nil {
		a.logger.Info(ctx, "DMARC check completed",
			zap.String("domain", fromDomain),
			zap.String("result", result.Result),
			zap.String("policy", result.Policy),
			zap.Bool("spf_aligned", result.SPFAligned),
			zap.Bool("dkim_aligned", result.DKIMAligned),
			zap.String("alignment_mode_spf", result.AlignmentModeSPF),
			zap.String("alignment_mode_dkim", result.AlignmentModeDKIM),
		)
	}

	return result
}

// parseDMARCRecordDetails extracts policy, alignment modes, and report URIs from DMARC record
func (a *authService) parseDMARCRecordDetails(record *dmarc.Record, result *DMARCResult) {
	// Parse DMARC policy
	result.Policy = string(record.Policy)
	if record.SubdomainPolicy != "" {
		result.SubdomainPolicy = string(record.SubdomainPolicy)
	}

	// Parse percentage (default 100 per RFC 7489)
	if record.Percent != nil {
		result.Percentage = *record.Percent
	} else {
		result.Percentage = 100
	}

	// Parse alignment modes (default relaxed per RFC 7489)
	if record.DKIMAlignment != "" {
		result.AlignmentModeDKIM = string(record.DKIMAlignment)
	} else {
		result.AlignmentModeDKIM = "relaxed"
	}
	if record.SPFAlignment != "" {
		result.AlignmentModeSPF = string(record.SPFAlignment)
	} else {
		result.AlignmentModeSPF = "relaxed"
	}

	// Parse report URIs
	if len(record.ReportURIAggregate) > 0 {
		result.ReportURIAggregate = record.ReportURIAggregate
	}
	if len(record.ReportURIFailure) > 0 {
		result.ReportURIForensic = record.ReportURIFailure
	}
}

// checkAlignments checks SPF and DKIM alignment per RFC 7489 section 3.1
func (a *authService) checkAlignments(fromDomain string, spfResult *SPFResult, dkimResult *DKIMResult, result *DMARCResult) {
	// Check SPF alignment
	if spfResult != nil && spfResult.Result == "pass" {
		result.SPFAligned = a.checkDomainAlignment(fromDomain, spfResult.SenderDomain, result.AlignmentModeSPF)
	}

	// Check DKIM alignment
	if dkimResult != nil && dkimResult.Result == "pass" {
		// DKIM passes if at least one valid signature has aligned domain
		for _, sig := range dkimResult.Signatures {
			if sig.Result == "pass" && a.checkDomainAlignment(fromDomain, sig.Domain, result.AlignmentModeDKIM) {
				result.DKIMAligned = true
				break
			}
		}
	}
}

// checkDomainAlignment checks if two domains are aligned per RFC 7489 section 3.1
func (a *authService) checkDomainAlignment(headerFrom, authenticatedDomain, mode string) bool {
	headerFrom = strings.ToLower(strings.TrimSpace(headerFrom))
	authenticatedDomain = strings.ToLower(strings.TrimSpace(authenticatedDomain))

	if mode == "strict" {
		// Strict mode: exact match
		return headerFrom == authenticatedDomain
	}

	// Relaxed mode: organizational domain match
	// Extract organizational domain (simplified - in production use publicsuffix library)
	headerOrg := a.getOrganizationalDomain(headerFrom)
	authOrg := a.getOrganizationalDomain(authenticatedDomain)

	return headerOrg == authOrg
}

// getOrganizationalDomain extracts the organizational domain
// This is a simplified implementation. In production, use golang.org/x/net/publicsuffix
func (a *authService) getOrganizationalDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	// Return last two labels (simplified)
	return strings.Join(parts[len(parts)-2:], ".")
}

// extractDomainFromMessage extracts the sender domain from an email message
func (a *authService) extractDomainFromMessage(message []byte) (string, error) {
	// Parse the email headers to extract From header per RFC 5322
	lines := strings.Split(string(message), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Stop at end of headers
		if line == "" {
			break
		}

		if strings.HasPrefix(strings.ToLower(line), "from:") {
			email := strings.TrimSpace(strings.TrimPrefix(line, "From:"))
			email = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(email), "from:"))

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
				// Remove any trailing characters
				domain = strings.TrimRight(domain, ">")
				domain = strings.TrimSpace(domain)
				return domain, nil
			}
		}
	}
	return "", fmt.Errorf("no From header found")
}
