// Command genfixture writes the committed DKIM2 test messages.
// It is not part of inbound verification. Run it from the module root:
//
//	go run ./internal/auth/testdata/genfixture
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/croessner/dkim2"
)

const fixtureSeed = "inboundparse-dkim2-ed25519-test-key"

func fixtureClock() time.Time {
	return time.Unix(1_700_000_000, 0).UTC()
}

func main() {
	dir := flag.String("dir", "internal/auth/testdata", "directory for the committed fixtures")
	flag.Parse()

	raw := []byte("From: alice@example.test\r\nTo: bob@example.net\r\nSubject: inboundparse dkim2 fixture\r\n\r\nHello DKIM2.\r\n")
	ordinary, err := sign(raw, []byte("<alice@example.test>"), false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign ordinary: %v\n", err)
		os.Exit(1)
	}
	nullSender, err := sign(raw, []byte("<>"), true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign null sender: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*dir, "dkim2_ed25519.eml"), ordinary, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write ordinary: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*dir, "dkim2_null_sender.eml"), nullSender, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write null sender: %v\n", err)
		os.Exit(1)
	}
}

func sign(raw, reverse []byte, nullSender bool) ([]byte, error) {
	seed := sha256.Sum256([]byte(fixtureSeed))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	provider := &fixtureSigner{private: private, public: public}

	signer, err := dkim2.NewSigner(
		provider,
		dkim2.NewRequestRouteAuthority(),
		provider,
		provider,
		dkim2.WithSigningClock(fixtureClock),
		dkim2.WithoutSignerSubdomainFromAuthorization(),
	)
	if err != nil {
		return nil, err
	}

	handle, err := dkim2.NewPrivateKeyHandle([]byte("ed-key"))
	if err != nil {
		return nil, err
	}
	credential, err := dkim2.NewEd25519SigningCredential("ed", public, handle)
	if err != nil {
		return nil, err
	}
	profile, err := dkim2.NewEd25519SigningProfile("example.test", credential)
	if err != nil {
		return nil, err
	}

	forwards := [][]byte{[]byte("<bob@example.net>")}
	source, err := dkim2.NewSigningSource(raw)
	if err != nil {
		return nil, err
	}
	entry, err := dkim2.NewOriginatorRouteEntry(source, reverse, forwards, dkim2.RouteDisclosureSingle, []byte("local-route"))
	if err != nil {
		return nil, err
	}
	fanout, err := dkim2.NewRouteFanoutRequest([]dkim2.RouteEntry{entry})
	if err != nil {
		return nil, err
	}
	plan, tickets, err := signer.PlanRouteFanout(context.Background(), fanout)
	if err != nil || !plan.Valid() || len(tickets) != 1 {
		return nil, fmt.Errorf("plan route: valid=%t tickets=%d err=%v", plan.Valid(), len(tickets), err)
	}

	var request dkim2.OriginatorSigningRequest
	if nullSender {
		request = dkim2.NewHeaderFromNullSenderSigningRequest(raw, forwards, tickets[0], profile, dkim2.SigningMetadata{}, dkim2.SigningTransportFinalNetworkPreDotStuffing)
	} else {
		request = dkim2.NewOriginatorSigningRequest(raw, reverse, forwards, tickets[0], profile, dkim2.SigningMetadata{}, dkim2.SigningTransportFinalNetworkPreDotStuffing)
	}
	result, recovery, err := signer.SignOriginator(context.Background(), request)
	if err != nil || recovery.Valid() || !result.Valid() {
		return nil, fmt.Errorf("sign: valid=%t recovery=%t err=%v", result.Valid(), recovery.Valid(), err)
	}
	signed, ok := result.Unrestricted()
	if !ok || !signed.Valid() {
		return nil, fmt.Errorf("signed output is restricted")
	}
	return signed.Bytes(), nil
}

type fixtureSigner struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func (s *fixtureSigner) LookupPublicKey(_ context.Context, query dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	if query.Algorithm() != dkim2.AlgorithmEd25519SHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundEd25519PublicKey(s.public), nil
}

func (s *fixtureSigner) SignDigest(_ context.Context, _ dkim2.PrivateKeyHandle, request dkim2.PrivateKeySignRequest) (dkim2.PrivateKeySignResult, error) {
	if request.Algorithm() != dkim2.AlgorithmEd25519SHA256 {
		return dkim2.PrivateKeySignResult{}, fmt.Errorf("unexpected algorithm %s", request.Algorithm())
	}
	return dkim2.NewPrivateKeySignResult(ed25519.Sign(s.private, request.MessageRepresentative())), nil
}

func (s *fixtureSigner) Authorize(_ context.Context, query dkim2.SigningAuthorizationQuery) (dkim2.SigningAuthorizationResult, error) {
	return dkim2.AuthorizeSigning(query), nil
}
