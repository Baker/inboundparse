package auth

import (
	"context"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"net"

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

// DMARCChecker interface for DMARC validation
type DMARCChecker interface {
	CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DMARCResult, error)
}

// AuthChecker combines all authentication checkers
type AuthChecker interface {
	SPFChecker
	DKIMChecker
	DMARCChecker
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	EnableSPF   bool
	EnableDKIM  bool
	EnableDMARC bool
}

// NewAuthChecker creates a new authentication checker with all enabled checkers
func NewAuthChecker(config AuthConfig) AuthChecker {
	return &authChecker{
		config: config,
		spf:    NewSPFChecker(),
		dkim:   NewDKIMChecker(),
		dmarc:  NewDMARCChecker(),
	}
}

// authChecker implements AuthChecker interface
type authChecker struct {
	config AuthConfig
	spf    SPFChecker
	dkim   DKIMChecker
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

// CheckDMARC performs DMARC authentication check
func (a *authChecker) CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult, logger observability.Logger, metrics observability.MetricsCollector) (*domain.DMARCResult, error) {
	if !a.config.EnableDMARC {
		return nil, nil
	}
	return a.dmarc.CheckDMARC(ctx, rawMessage, headers, spfResult, dkimResult, logger, metrics)
}
