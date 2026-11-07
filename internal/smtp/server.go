package smtp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"inboundparse/internal/config"
	"inboundparse/internal/observability"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/pires/go-proxyproto"
	"golang.org/x/sync/errgroup"
)

// ServerConfig holds SMTP server configuration
type ServerConfig struct {
	ListenAddr        string
	ListenAddrTLS     string
	ServerName        string
	MaxMessageSize    int64
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	CertFile          string
	KeyFile           string
	MaxRecipients     int
	TrustedProxyCIDRs []string
}

// SMTPServer manages SMTP servers
type SMTPServer struct {
	config            ServerConfig
	server            *smtp.Server
	tlsServer         *smtp.Server
	logger            observability.Logger
	trustedProxyCIDRs []*net.IPNet
	wg                sync.WaitGroup
	closeOnce         sync.Once
	lnMu              sync.Mutex
	lns               []net.Listener
	closing           bool
	closeErr          error
}

// NewSMTPServer creates a new SMTP server
func NewSMTPServer(
	config ServerConfig,
	backend *Backend,
	logger observability.Logger,
) (*SMTPServer, error) {
	// Parse trusted proxy CIDRs at startup to catch configuration errors early
	var trustedProxyCIDRs []*net.IPNet
	for _, cidr := range config.TrustedProxyCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", cidr, err)
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, ipNet)
	}

	var tlsServer *smtp.Server

	server := smtp.NewServer(backend)
	server.Addr = config.ListenAddr
	server.Domain = config.ServerName
	server.MaxMessageBytes = config.MaxMessageSize
	// go-smtp counts recipients on the connection and does not clear that
	// count when MAIL starts a new transaction. Session.Rcpt enforces
	// config.MaxRecipients on the transaction slice instead.
	server.MaxRecipients = 0
	server.AllowInsecureAuth = false // Disallow AUTH before TLS
	server.ReadTimeout = config.ReadTimeout
	server.WriteTimeout = config.WriteTimeout

	// Optionally enable TLS
	if config.CertFile != "" && config.KeyFile != "" {
		logger.Debug().
			Str("cert_file", config.CertFile).
			Str("key_file", config.KeyFile).
			Msg("Loading TLS certificate")
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsServer = smtp.NewServer(backend)
		tlsServer.Addr = config.ListenAddrTLS
		tlsServer.Domain = config.ServerName
		tlsServer.WriteTimeout = config.WriteTimeout
		tlsServer.ReadTimeout = config.ReadTimeout
		tlsServer.MaxMessageBytes = config.MaxMessageSize
		tlsServer.MaxRecipients = 0
		tlsServer.AllowInsecureAuth = false
		tlsServer.TLSConfig = &tls.Config{
			ServerName:   config.ServerName,
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		server.TLSConfig = tlsServer.TLSConfig
	}

	return &SMTPServer{
		config:            config,
		server:            server,
		tlsServer:         tlsServer,
		logger:            logger,
		trustedProxyCIDRs: trustedProxyCIDRs,
	}, nil
}

// Start starts the SMTP server.
// With TLS configured, the plain and TLS listeners run together. If either
// returns, both are closed and Start returns the first real error.
func (s *SMTPServer) Start() error {
	if s.tlsServer != nil {
		return s.startPlainAndTLS()
	}
	s.logger.Info().
		Str("address", s.config.ListenAddr).
		Msg("Starting plain SMTP server")
	return serveResult(s.listenAndServeWithProxy(s.server, s.config.ListenAddr))
}

// startPlainAndTLS serves the plain and implicit-TLS listeners until one
// of them returns, then closes both so a failed bind cannot leave the
// sibling accepting connections.
func (s *SMTPServer) startPlainAndTLS() error {
	g := new(errgroup.Group)
	s.wg.Add(2)

	g.Go(func() error {
		defer s.wg.Done()
		defer func() { _ = s.closeServers() }()
		s.logger.Info().
			Str("address", s.config.ListenAddr).
			Msg("Starting plain SMTP server")
		err := serveResult(s.listenAndServeWithProxy(s.server, s.config.ListenAddr))
		if err != nil {
			s.logger.Error().
				Err(err).
				Msg("Plain SMTP server stopped with error")
		}
		return err
	})
	g.Go(func() error {
		defer s.wg.Done()
		defer func() { _ = s.closeServers() }()
		s.logger.Info().
			Str("address", s.config.ListenAddrTLS).
			Msg("Starting TLS SMTP server")
		err := serveResult(s.listenAndServeWithProxy(s.tlsServer, s.config.ListenAddrTLS))
		if err != nil {
			s.logger.Error().
				Err(err).
				Msg("TLS SMTP server stopped with error")
		}
		return err
	})
	return g.Wait()
}

// listenAndServeWithProxy starts the SMTP server with PROXY protocol support
func (s *SMTPServer) listenAndServeWithProxy(server *smtp.Server, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	proxyListener := &proxyproto.Listener{
		Listener: ln,
		// go-proxyproto v0.12 treats 0 as DefaultReadHeaderTimeout (10s).
		// Conn.Write waits that long before the SMTP 220 when the client
		// sends no PROXY header.
		ReadHeaderTimeout: 200 * time.Millisecond,
		ConnPolicy: func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			if len(s.trustedProxyCIDRs) == 0 {
				// No trusted proxies configured — ignore PROXY headers so clients
				// cannot spoof source IPs (SPF/DMARC rely on the real TCP peer).
				return proxyproto.IGNORE, nil
			}
			upstream := opts.Upstream
			if upstream == nil {
				return proxyproto.IGNORE, nil
			}
			host, _, err := net.SplitHostPort(upstream.String())
			if err != nil {
				return proxyproto.IGNORE, nil
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return proxyproto.IGNORE, nil
			}
			for _, cidr := range s.trustedProxyCIDRs {
				if cidr.Contains(ip) {
					return proxyproto.USE, nil
				}
			}
			return proxyproto.IGNORE, nil
		},
	}

	if err := s.registerListener(proxyListener); err != nil {
		_ = proxyListener.Close()
		return err
	}
	defer func() { _ = proxyListener.Close() }()
	return server.Serve(proxyListener)
}

// registerListener records ln so closeServers can release it even when
// smtp.Server.Serve has not registered the listener yet.
func (s *SMTPServer) registerListener(ln net.Listener) error {
	s.lnMu.Lock()
	defer s.lnMu.Unlock()
	if s.closing {
		return net.ErrClosed
	}
	s.lns = append(s.lns, ln)
	return nil
}

// closeServers closes both SMTP servers and any listeners still held here.
// Already-closed errors are ignored. Concurrent calls share one close.
func (s *SMTPServer) closeServers() error {
	s.closeOnce.Do(func() {
		s.lnMu.Lock()
		s.closing = true
		lns := make([]net.Listener, len(s.lns))
		copy(lns, s.lns)
		s.lnMu.Unlock()

		s.closeErr = joinCloseErr(nil, closeSMTPServer(s.server))
		s.closeErr = joinCloseErr(s.closeErr, closeSMTPServer(s.tlsServer))
		for _, ln := range lns {
			s.closeErr = joinCloseErr(s.closeErr, ln.Close())
		}
	})
	return s.closeErr
}

func closeSMTPServer(server *smtp.Server) error {
	if server == nil {
		return nil
	}
	return server.Close()
}

// serveResult drops errors that only mean the server was closed so a sibling
// shutdown does not hide the first real failure.
func serveResult(err error) error {
	if ignorableCloseErr(err) {
		return nil
	}
	return err
}

func joinCloseErr(dst, err error) error {
	if ignorableCloseErr(err) {
		return dst
	}
	return errors.Join(dst, err)
}

func ignorableCloseErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, smtp.ErrServerClosed) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "already closed") || strings.Contains(msg, "use of closed network connection")
}

// Stop stops the SMTP server and waits for all goroutines to finish
func (s *SMTPServer) Stop() error {
	err := s.closeServers()
	s.wg.Wait()
	return err
}

// NewSMTPServerFromConfig creates a new SMTP server from application config
func NewSMTPServerFromConfig(
	appConfig *config.Config,
	backend *Backend,
	logger observability.Logger,
) (*SMTPServer, error) {
	serverConfig := ServerConfig{
		ListenAddr:        appConfig.ListenAddr,
		ListenAddrTLS:     appConfig.ListenAddrTLS,
		ServerName:        appConfig.ServerName,
		MaxMessageSize:    appConfig.MaxMessageSize,
		ReadTimeout:       appConfig.ReadTimeout,
		WriteTimeout:      appConfig.WriteTimeout,
		CertFile:          appConfig.CertFile,
		KeyFile:           appConfig.KeyFile,
		MaxRecipients:     100, // Default value
		TrustedProxyCIDRs: appConfig.TrustedProxyCIDRs,
	}

	return NewSMTPServer(serverConfig, backend, logger)
}
