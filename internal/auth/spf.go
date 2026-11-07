package auth

import (
	"context"
	"fmt"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"net"
	"strings"
	"time"

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
func (s *spfChecker) CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.SPFResult, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		metrics.TrackSPFDuration(duration)
	}()
	if remoteIP == nil {
		logger.Warn().Msg("SPF check: Failed to get remote IP")
		return &domain.SPFResult{
			Result:    "temperror",
			Raw:       "Failed to get remote IP",
			Problem:   "No remote IP address available for SPF evaluation",
			Sender:    from,
			IpAddress: remoteIP.String(),
		}, nil
	}

	if domainName == "" {
		logger.Debug().
			Str("from", from).
			Msg("SPF check: No domain found in sender address")
		return &domain.SPFResult{
			Result:    "none",
			Raw:       "No domain found in sender address",
			Problem:   "Unable to extract domain from MAIL FROM identity",
			Sender:    from,
			IpAddress: remoteIP.String(),
		}, nil
	}

	// RFC 7208 Section 2.4: Check MAIL FROM identity.
	// CheckHost does not take a context. Run it aside so a canceled
	// MESSAGE_PROCESSING_TIMEOUT can return without waiting on DNS.
	type spfLookup struct {
		result    spf.Result
		mechanism string
		err       error
	}
	lookup, ok := callWithContext(ctx, func() spfLookup {
		result, mechanism, err := spf.CheckHost(remoteIP, domainName, from)
		return spfLookup{result: result, mechanism: mechanism, err: err}
	})
	if !ok {
		metrics.TrackAuthError("spf", "timeout_error")
		logger.Warn().
			Err(ctx.Err()).
			Str("domain", domainName).
			Str("remote_ip", remoteIP.String()).
			Str("identity", from).
			Msg("SPF check canceled")
		return &domain.SPFResult{
			Result:    "temperror",
			Raw:       fmt.Sprintf("SPF check error: %v", ctx.Err()),
			Problem:   fmt.Sprintf("DNS lookup or processing error: %v", ctx.Err()),
			Sender:    from,
			IpAddress: remoteIP.String(),
		}, nil
	}
	result, mechanism, err := lookup.result, lookup.mechanism, lookup.err
	if err != nil {
		// Determine error type for metrics
		errorType := "dns_error"
		if strings.Contains(err.Error(), "timeout") {
			errorType = "timeout_error"
		} else if strings.Contains(err.Error(), "parse") {
			errorType = "parse_error"
		}
		metrics.TrackAuthError("spf", errorType)

		logger.Warn().
			Err(err).
			Str("domain", domainName).
			Str("remote_ip", remoteIP.String()).
			Str("identity", from).
			Msg("SPF check error")
		return &domain.SPFResult{
			Result:    spfResultOnError(result, err),
			Raw:       fmt.Sprintf("SPF check error: %v", err),
			Problem:   fmt.Sprintf("DNS lookup or processing error: %v", err),
			Sender:    from,
			IpAddress: remoteIP.String(),
		}, nil
	}

	// Extract explanation if available (RFC 7208 Section 6.2)
	explanation := s.extractSPFExplanation(domainName, result)

	logger.Debug().
		Str("result", result.String()).
		Str("domain", domainName).
		Str("remote_ip", remoteIP.String()).
		Str("mechanism", mechanism).
		Str("identity", from).
		Str("explanation", explanation).
		Msg("SPF check completed")

	// Track result by domain
	metrics.TrackSPFResultByDomain(domainName, result.String())

	return &domain.SPFResult{
		Result:      result.String(),
		Raw:         fmt.Sprintf("SPF result: %s for domain %s from IP %s", result.String(), domainName, remoteIP.String()),
		Mechanism:   mechanism,
		Explanation: explanation,
		Sender:      from,
		IpAddress:   remoteIP.String(),
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

// spfResultOnError maps a CheckHost result that arrived with a non-nil error.
// None, Permerror, and Temperror keep the library result (RFC 7208: no record
// or NXDOMAIN is none, a permanent evaluation error is permerror, and only a
// transient failure is temperror). A zero or unknown result falls back to the
// error text.
func spfResultOnError(result spf.Result, err error) string {
	switch result {
	case spf.None, spf.Neutral, spf.Pass, spf.Fail, spf.Softfail, spf.Temperror, spf.Permerror:
		return result.String()
	default:
		if err != nil && strings.Contains(err.Error(), "permanent") {
			return "permerror"
		}
		return "temperror"
	}
}
