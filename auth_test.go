package main

import (
    "errors"
    "io"
    "net"
    "net/mail"
    "testing"

    "github.com/emersion/go-msgauth/dkim"
    "github.com/emersion/go-msgauth/dmarc"
    "github.com/mnako/letters"
    "github.com/zaccone/spf"
)

type fakeVerification struct{
	Domain string
	Err error
}

func TestExtractDomainFromEmail(t *testing.T){
	mp := &MessageProcessor{}
	cases := []struct{in, want string}{
		{"user@example.com", "example.com"},
		{"<user@example.com>", "example.com"},
		{"John <user@example.com>", "example.com"},
		{"no-at", ""},
	}
	for _, c := range cases {
		if got := mp.extractDomainFromEmail(c.in); got != c.want {
			t.Fatalf("extractDomainFromEmail(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestGetParentDomain(t *testing.T){
	mp := &MessageProcessor{}
	if got := mp.getParentDomain("a.b.example.com"); got != "b.example.com" { t.Fatalf("got %q", got) }
	if got := mp.getParentDomain("example.com"); got != "" { t.Fatalf("got %q", got) }
}

func TestOrganizationalDomainMatch(t *testing.T){
	mp := &MessageProcessor{}
	if !mp.isOrganizationalDomainMatch("a.example.com","b.example.com") { t.Fatal("expected match") }
	if mp.isOrganizationalDomainMatch("a.example.co.uk","b.example.com") { t.Fatal("unexpected match") }
}

func TestDomainAlignment(t *testing.T){
	mp := &MessageProcessor{}
	if !mp.checkDomainAlignment("example.com","example.com","s") { t.Fatal("strict equal should match") }
	if mp.checkDomainAlignment("a.example.com","example.com","s") { t.Fatal("strict should not match subdomain") }
	if !mp.checkDomainAlignment("a.example.com","b.example.com","r") { t.Fatal("relaxed org match") }
}

func TestSPFSuccess(t *testing.T){
	defer func(){ spfCheckHostFn = spf.CheckHost }()
	spfCheckHostFn = func(ip net.IP, domain, sender string)(spf.Result,string,error){
		return spf.Pass, "mx", nil
	}
	mp := &MessageProcessor{ from: "sender@example.com", testRemoteIP: net.IPv4(1,2,3,4), config: &ServerConfig{EnableSPF:true} }
	r := mp.checkSPF()
	if r.Result != "pass" { t.Fatalf("want pass got %v", r.Result) }
}

func TestSPFNoIP(t *testing.T){
	mp := &MessageProcessor{ from: "sender@example.com", config: &ServerConfig{EnableSPF:true} }
	r := mp.checkSPF()
	if r.Result != "temperror" { t.Fatalf("want temperror got %v", r.Result) }
}

func TestDKIMValidAndInvalid(t *testing.T){
    defer func(){ dkimVerifyFn = dkim.Verify }()
    dkimVerifyFn = func(r io.Reader)([]*dkim.Verification, error){
        return []*dkim.Verification{{Domain:"example.com", Err:nil},{Domain:"bad.example", Err:errors.New("bad")}}, nil
    }
	mp := &MessageProcessor{}
	res := mp.checkDKIM("raw")
	if !res.Valid { t.Fatal("expected valid due to one good signature") }
	if len(res.Signatures) != 2 { t.Fatalf("expected 2 signatures, got %d", len(res.Signatures)) }
}

func TestDMARCTraversalAndAlignment(t *testing.T){
	defer func(){ dmarcLookupFn = dmarc.Lookup; dkimVerifyFn = dkim.Verify; spfCheckHostFn = spf.CheckHost }()
    dmarcLookupFn = func(domain string)(*dmarc.Record, error){
		if domain == "sub.example.com" { return nil, errors.New("not found") }
		if domain == "example.com" {
			rec := &dmarc.Record{ Policy: dmarc.PolicyReject, SPFAlignment: dmarc.AlignmentRelaxed, DKIMAlignment: dmarc.AlignmentRelaxed }
			return rec, nil
		}
		return nil, errors.New("not found")
	}
	spfCheckHostFn = func(ip net.IP, domain, sender string)(spf.Result,string,error){ return spf.Pass, "mx", nil }
    dkimVerifyFn = func(r io.Reader)([]*dkim.Verification, error){
        return []*dkim.Verification{{Domain:"example.com", Err:nil}}, nil
	}
	mp := &MessageProcessor{ from: "sender@example.com", testRemoteIP: net.IPv4(1,2,3,4), config: &ServerConfig{EnableSPF:true, EnableDKIM:true, EnableDMARC:true} }
    headers := letters.Headers{ From: []*mail.Address{{Address:"user@sub.example.com", Name:"User"}} }
	res := mp.checkDMARC("raw", headers, nil, nil)
	if res.Result != "pass" { t.Fatalf("want pass got %v", res.Result) }
}

func TestDMARCNoFrom(t *testing.T){
	mp := &MessageProcessor{ config: &ServerConfig{EnableDMARC:true} }
    res := mp.checkDMARC("raw", letters.Headers{}, nil, nil)
	if res.Result != "none" { t.Fatalf("want none got %v", res.Result) }
}
