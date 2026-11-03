package issuer

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// TestApplyPathLen checks the path length rule: a CA whose limit is N may
// issue CAs with a limit of at most N - 1.
func TestApplyPathLen(t *testing.T) {
	t.Parallel()

	// Parsed certificates report no limit as -1, and an explicit 0 with
	// MaxPathLenZero.
	parent := func(n int) *x509.Certificate {
		return &x509.Certificate{IsCA: true, MaxPathLen: n, MaxPathLenZero: n == 0}
	}

	// cert-manager's templates report no limit as 0 without MaxPathLenZero.
	unlimited := func() *x509.Certificate { return &x509.Certificate{IsCA: true} }
	limited := func(n int) *x509.Certificate {
		return &x509.Certificate{IsCA: true, MaxPathLen: n, MaxPathLenZero: n == 0}
	}

	tests := []struct {
		name     string
		parent   *x509.Certificate
		tmpl     *x509.Certificate
		wantErr  bool
		wantLen  int
		wantZero bool
	}{
		{"not a CA", parent(0), &x509.Certificate{}, false, 0, false},
		{"parent has no limit, child asks for none", parent(-1), unlimited(), false, 0, false},
		{"parent has no limit, child asks for 5", parent(-1), limited(5), false, 5, false},
		{"parent 0", parent(0), unlimited(), true, 0, false},
		{"parent 0, child asks for 0", parent(0), limited(0), true, 0, true},
		{"parent 1, child asks for none", parent(1), unlimited(), false, 0, true},
		{"parent 2, child asks for none", parent(2), unlimited(), false, 1, false},
		{"parent 2, child asks for -1", parent(2), &x509.Certificate{IsCA: true, MaxPathLen: -1}, false, 1, false},
		{"parent 2, child asks for 0", parent(2), limited(0), false, 0, true},
		{"parent 2, child asks for 1", parent(2), limited(1), false, 1, false},
		{"parent 2, child asks for 5", parent(2), limited(5), true, 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := applyPathLen(tt.tmpl, tt.parent)
			if got := err != nil; got != tt.wantErr {
				t.Fatalf("applyPathLen() error = %v, want error %t", err, tt.wantErr)
			}

			if err != nil && !errors.Is(err, ErrPathLenExceeded) {
				t.Errorf("applyPathLen() error = %v, want %v", err, ErrPathLenExceeded)
			}

			if tt.tmpl.MaxPathLen != tt.wantLen || tt.tmpl.MaxPathLenZero != tt.wantZero {
				t.Errorf("MaxPathLen, MaxPathLenZero = %d, %t; want %d, %t",
					tt.tmpl.MaxPathLen, tt.tmpl.MaxPathLenZero, tt.wantLen, tt.wantZero)
			}
		})
	}
}

func TestClampNotAfter(t *testing.T) {
	t.Parallel()

	const maxDuration = 90 * 24 * time.Hour

	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	farCA := notBefore.Add(10 * 365 * 24 * time.Hour)

	tests := []struct {
		name        string
		notAfter    time.Time
		caNotAfter  time.Time
		want        time.Time
		wantClamped bool
	}{
		{"under maxDuration", notBefore.Add(time.Hour), farCA, notBefore.Add(time.Hour), false},
		{"exactly maxDuration", notBefore.Add(maxDuration), farCA, notBefore.Add(maxDuration), false},
		{"over maxDuration", notBefore.Add(maxDuration + time.Second), farCA, notBefore.Add(maxDuration), true},
		{"CA expires first", notBefore.Add(maxDuration), notBefore.Add(time.Hour), notBefore.Add(time.Hour), true},
		{"both limits, CA tighter", notBefore.Add(2 * maxDuration), notBefore.Add(maxDuration / 2), notBefore.Add(maxDuration / 2), true},
		{"exactly the CA's expiry", notBefore.Add(time.Hour), notBefore.Add(time.Hour), notBefore.Add(time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tmpl := &x509.Certificate{NotBefore: notBefore, NotAfter: tt.notAfter}

			requested, clamped := clampNotAfter(tmpl, maxDuration, tt.caNotAfter)
			if clamped != tt.wantClamped {
				t.Errorf("clamped = %t, want %t", clamped, tt.wantClamped)
			}

			if !requested.Equal(tt.notAfter) {
				t.Errorf("requested = %s, want the original %s", requested, tt.notAfter)
			}

			if !tmpl.NotAfter.Equal(tt.want) {
				t.Errorf("NotAfter = %s, want %s", tmpl.NotAfter, tt.want)
			}
		})
	}
}
