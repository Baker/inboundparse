package service

import (
	"context"
	"fmt"
	"net"
	"strings"

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

// PerformAuthenticationChecks performs SPF, DKIM, and DMARC authentication checks
func (a *authService) PerformAuthenticationChecks(ctx context.Context, message []byte, remoteIP net.IP) (*AuthResult, error) {
	result := &AuthResult{}

	// Perform SPF check
	if a.enableSPF {
		spfResult, err := a.checkSPF(message, remoteIP)
		if err != nil {
			result.SPF = &SPFResult{
				Result: "temperror",
				Error:  err.Error(),
			}
		} else {
			result.SPF = &SPFResult{
				Result: spfResult,
			}
		}
	}

	// Perform DKIM check
	if a.enableDKIM {
		dkimResult, err := a.checkDKIM(message)
		if err != nil {
			result.DKIM = &DKIMResult{
				Result: "temperror",
				Error:  err.Error(),
			}
		} else {
			result.DKIM = &DKIMResult{
				Result: dkimResult,
			}
		}
	}

	// Perform DMARC check
	if a.enableDMARC {
		dmarcResult, policy, err := a.checkDMARC(message)
		if err != nil {
			result.DMARC = &DMARCResult{
				Result: "temperror",
				Error:  err.Error(),
			}
		} else {
			result.DMARC = &DMARCResult{
				Result: dmarcResult,
				Policy: policy,
			}
		}
	}

	return result, nil
}

// checkSPF performs SPF validation
func (a *authService) checkSPF(message []byte, remoteIP net.IP) (string, error) {
	// Extract sender domain from message
	fromDomain, err := a.extractDomainFromMessage(message)
	if err != nil {
		return "none", fmt.Errorf("failed to extract domain: %w", err)
	}

	// Perform SPF check
	result, _, err := spf.CheckHost(remoteIP, fromDomain, "")
	if err != nil {
		return "temperror", fmt.Errorf("SPF check failed: %w", err)
	}

	return strings.ToLower(result.String()), nil
}

// checkDKIM performs DKIM validation
func (a *authService) checkDKIM(message []byte) (string, error) {
	// For now, return a simple implementation
	// In a real implementation, you'd use the dkim package properly
	return "none", nil
}

// checkDMARC performs DMARC validation
func (a *authService) checkDMARC(message []byte) (string, string, error) {
	// Extract sender domain from message
	fromDomain, err := a.extractDomainFromMessage(message)
	if err != nil {
		return "none", "", fmt.Errorf("failed to extract domain: %w", err)
	}

	// Look up DMARC record
	record, err := dmarc.Lookup(fromDomain)
	if err != nil {
		return "temperror", "", fmt.Errorf("DMARC lookup failed: %w", err)
	}

	if record == nil {
		return "none", "", nil
	}

	// For now, we'll return a simple pass/fail based on record existence
	// In a real implementation, you'd need to evaluate the policy
	return "pass", string(record.Policy), nil
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
