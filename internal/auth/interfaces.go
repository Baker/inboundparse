package auth

import (
	"context"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"net"

	"github.com/croessner/dkim2"
	"github.com/mnako/letters"
)

// SPFChecker interface for SPF validation
type SPFChecker interface {
	CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.SPFResult, error)
}

// DKIMChecker interface for DKIM validation
type DKIMChecker interface {
	CheckDKIM(ctx context.Context, rawMessage string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DKIMResult, error)
}

// DKIM2Checker verifies inbound DKIM2 signatures. It does not sign.
type DKIM2Checker interface {
	CheckDKIM2(ctx context.Context, rawMessage string, from string, to []string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DKIM2Result, error)
}

// DMARCChecker interface for DMARC validation
type DMARCChecker interface {
	CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DMARCResult, error)
}

// AuthChecker combines all authentication checkers
type AuthChecker interface {
	SPFChecker
	DKIMChecker
	DKIM2Checker
	DMARCChecker
}

// AuthConfig holds authentication configuration.
// DKIM2Verifier is the process-wide verifier. Production builds it from DNS.
// Tests pass a verifier backed by a stub public-key provider.
type AuthConfig struct {
	EnableSPF     bool
	EnableDKIM    bool
	EnableDKIM2   bool
	EnableDMARC   bool
	DKIM2Verifier *dkim2.Verifier
}

// NewAuthChecker creates a new authentication checker with all enabled checkers
func NewAuthChecker(config AuthConfig) AuthChecker {
	return &authChecker{
		config: config,
		spf:    NewSPFChecker(),
		dkim:   NewDKIMChecker(),
		dkim2:  NewDKIM2Checker(config.DKIM2Verifier),
		dmarc:  NewDMARCChecker(),
	}
}

// authChecker implements AuthChecker interface
type authChecker struct {
	config AuthConfig
	spf    SPFChecker
	dkim   DKIMChecker
	dkim2  DKIM2Checker
	dmarc  DMARCChecker
}

// CheckSPF performs SPF authentication check
func (a *authChecker) CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.SPFResult, error) {
	if !a.config.EnableSPF {
		return nil, nil
	}
	return a.spf.CheckSPF(ctx, remoteIP, domainName, from, logger, metrics)
}

// CheckDKIM performs DKIM authentication check
func (a *authChecker) CheckDKIM(ctx context.Context, rawMessage string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DKIMResult, error) {
	if !a.config.EnableDKIM {
		return nil, nil
	}
	return a.dkim.CheckDKIM(ctx, rawMessage, logger, metrics)
}

// CheckDKIM2 performs DKIM2 verification. DMARC does not consume this result.
func (a *authChecker) CheckDKIM2(ctx context.Context, rawMessage string, from string, to []string, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DKIM2Result, error) {
	if !a.config.EnableDKIM2 {
		return nil, nil
	}
	return a.dkim2.CheckDKIM2(ctx, rawMessage, from, to, logger, metrics)
}

// CheckDMARC performs DMARC authentication check
func (a *authChecker) CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DMARCResult, error) {
	if !a.config.EnableDMARC {
		return nil, nil
	}
	return a.dmarc.CheckDMARC(ctx, rawMessage, headers, spfResult, dkimResult, logger, metrics)
}
