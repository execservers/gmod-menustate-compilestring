package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func TestPinsForChains(t *testing.T) {
	leaf := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("leaf")}
	intermediate := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("intermediate")}
	root := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("root")}
	pins, err := pinsForChains([][]*x509.Certificate{
		{leaf, intermediate, root},
		{leaf, intermediate, root}, // A repeated trust path should not duplicate pins.
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 2 {
		t.Fatalf("expected leaf and intermediate, got %d pins", len(pins))
	}
	for i, value := range []string{"leaf", "intermediate"} {
		sum := sha256.Sum256([]byte(value))
		want := base64.StdEncoding.EncodeToString(sum[:])
		if pins[i] != want {
			t.Fatalf("pin[%d] = %q, want %q", i, pins[i], want)
		}
	}
}

func TestPinsForChainsRequiresVerification(t *testing.T) {
	if _, err := pinsForChains(nil); err == nil {
		t.Fatal("expected error for an unverified TLS connection")
	}
}

func TestRequiredHosts(t *testing.T) {
	if len(requiredHosts) != 4 {
		t.Fatalf("expected 4 required hosts, got %d", len(requiredHosts))
	}
}
