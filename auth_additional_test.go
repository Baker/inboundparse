package main

import (
	"errors"
	"testing"
)

func TestDMARCNotFoundErrorHeuristics(t *testing.T){
	mp := &MessageProcessor{}
	for _, s := range []string{"not found","No such host","NXDOMAIN","no data"} {
		if !mp.isDMARCNotFoundError(errors.New(s)) { t.Fatalf("expected true for %q", s) }
	}
	if mp.isDMARCNotFoundError(errors.New("timeout")) { t.Fatal("unexpected true") }
}

func TestGetOrganizationalDomain(t *testing.T){
	mp := &MessageProcessor{}
	if mp.getOrganizationalDomain("a.b.example.com") != "example.com" { t.Fatal("bad org domain") }
	if mp.getOrganizationalDomain("localhost") != "localhost" { t.Fatal("single label") }
}

func TestCheckDKIMAlignment(t *testing.T){
	mp := &MessageProcessor{}
	sigs := []string{"Valid: example.com","Invalid: err"}
	if !mp.checkDKIMAlignment(sigs, "sub.example.com", "r") { t.Fatal("expected relaxed alignment true") }
	if mp.checkDKIMAlignment(sigs, "other.com", "s") { t.Fatal("strict should fail") }
}
