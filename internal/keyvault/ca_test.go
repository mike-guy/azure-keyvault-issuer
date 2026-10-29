package keyvault

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

// localSigners returns a signer factory for a local key, as Stage 4's issuer
// tests will use, and reports the contexts it was called with.
func localSigners(key crypto.Signer, seen *[]context.Context) func(context.Context) crypto.Signer {
	return func(ctx context.Context) crypto.Signer {
		*seen = append(*seen, ctx)

		return key
	}
}

func TestNewCA(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, keyP256)

	var seen []context.Context

	ca, err := NewCA([]*x509.Certificate{pki.ca, pki.intermediate, pki.root}, localSigners(pki.caKey, &seen))
	if err != nil {
		t.Fatalf("NewCA() error = %v", err)
	}

	// Signer passes each request's context to the factory.
	ctx := context.WithValue(t.Context(), ctxKey{}, "request-1")
	if _, err := issueLeaf(ctx, t, ca, 0); err != nil {
		t.Fatalf("issuing leaf with a local key: %v", err)
	}

	if len(seen) != 1 || seen[0].Value(ctxKey{}) != "request-1" {
		t.Errorf("signer factory saw contexts %v, want the request's", seen)
	}

	// Chain returns a copy, so the cached CA cannot be changed through it.
	chain := ca.Chain()
	chain[0] = pki.root

	if !ca.Certificate().Equal(pki.ca) || !ca.Chain()[0].Equal(pki.ca) {
		t.Error("changing the slice from Chain() changed the CA")
	}
}

// TestCANotAfter checks that NotAfter is the earliest expiry anywhere in the
// chain, not just the CA certificate's.
func TestCANotAfter(t *testing.T) {
	t.Parallel()

	now := time.Now().Truncate(time.Second)

	tests := []struct {
		name                    string
		intNotAfter, caNotAfter time.Time
		want                    time.Time
	}{
		{"CA expires first", now.Add(365 * 24 * time.Hour), now.Add(30 * 24 * time.Hour), now.Add(30 * 24 * time.Hour)},
		{"intermediate expires first", now.Add(10 * 24 * time.Hour), now.Add(30 * 24 * time.Hour), now.Add(10 * 24 * time.Hour)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rootKey, intKey, caKey := testKey(t, keyP384), testKey(t, keyP256), testKey(t, keyP256)
			root := newCert(t, certSpec{cn: "Test Root", notAfter: now.Add(10 * 365 * 24 * time.Hour)}, rootKey.Public(), nil, rootKey)
			intermediate := newCert(t, certSpec{cn: "Test Intermediate", notAfter: tt.intNotAfter}, intKey.Public(), root, rootKey)
			ca := newCert(t, certSpec{cn: "Test Key Vault CA", notAfter: tt.caNotAfter}, caKey.Public(), intermediate, intKey)

			got, err := NewCA([]*x509.Certificate{ca, intermediate, root}, func(context.Context) crypto.Signer { return caKey })
			if err != nil {
				t.Fatalf("NewCA() error = %v", err)
			}

			if !got.NotAfter().Equal(tt.want) {
				t.Errorf("NotAfter() = %s, want %s", got.NotAfter(), tt.want)
			}
		})
	}
}

// TestNewCARejectsChainOutsideValidity checks the validity of the rest of the
// chain. Each chain links correctly, so only the dates can be at fault.
func TestNewCARejectsChainOutsideValidity(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name                string
		notBefore, notAfter time.Time
	}{
		{"expired intermediate", now.Add(-48 * time.Hour), now.Add(-time.Hour)},
		{"intermediate not yet valid", now.Add(time.Hour), now.Add(48 * time.Hour)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rootKey, intKey, caKey := testKey(t, keyP384), testKey(t, keyP256), testKey(t, keyP256)
			root := newCert(t, certSpec{cn: "Test Root"}, rootKey.Public(), nil, rootKey)
			intermediate := newCert(t, certSpec{cn: "Test Intermediate", notBefore: tt.notBefore, notAfter: tt.notAfter},
				intKey.Public(), root, rootKey)
			ca := newCert(t, certSpec{cn: "Test Key Vault CA"}, caKey.Public(), intermediate, intKey)

			_, err := NewCA([]*x509.Certificate{ca, intermediate, root}, func(context.Context) crypto.Signer { return caKey })
			if !errors.Is(err, ErrInvalidChain) || !strings.Contains(err.Error(), "not currently valid") {
				t.Errorf("NewCA() error = %v, want %v for an out-of-date certificate", err, ErrInvalidChain)
			}
		})
	}
}

func TestNewCARejects(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, keyP256)
	signers := func(context.Context) crypto.Signer { return pki.caKey }

	tests := []struct {
		name      string
		chain     []*x509.Certificate
		newSigner func(context.Context) crypto.Signer
		wantErr   error
	}{
		{"empty chain", nil, signers, ErrInvalidCA},
		{"nil certificate", []*x509.Certificate{nil}, signers, ErrInvalidCA},
		{"nil link", []*x509.Certificate{pki.ca, nil}, signers, ErrInvalidChain},
		{"not a CA", []*x509.Certificate{newCert(t, certSpec{cn: "leaf", notCA: true}, pki.caKey.Public(), nil, pki.caKey)}, signers, ErrInvalidCA},
		{"broken link", []*x509.Certificate{pki.ca, pki.root}, signers, ErrInvalidChain},
		{"no signer", []*x509.Certificate{pki.ca}, nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca, err := NewCA(tt.chain, tt.newSigner)
			if err == nil || ca != nil {
				t.Fatalf("NewCA() = %v, %v; want an error", ca, err)
			}

			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("NewCA() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
