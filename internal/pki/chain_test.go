package pki

import (
	"crypto/x509"
	"testing"
)

func TestSubCAPathLen(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ca      *x509.Certificate
		chain   []*x509.Certificate
		wantLen int
		wantOK  bool
	}{
		{
			name:    "nothing constrained issues a CA that may only issue end certificates",
			ca:      pathLenCert(-1, false),
			chain:   nil,
			wantLen: 0,
			wantOK:  true,
		},
		{
			name:    "a path length of 0 without the zero flag is unconstrained",
			ca:      pathLenCert(0, false),
			chain:   []*x509.Certificate{pathLenCert(0, false)},
			wantLen: 0,
			wantOK:  true,
		},
		{
			name:    "an unconstrained chain above an unconstrained ca stays unconstrained",
			ca:      pathLenCert(-1, false),
			chain:   []*x509.Certificate{pathLenCert(-1, false), pathLenCert(-1, false)},
			wantLen: 0,
			wantOK:  true,
		},
		{
			name:    "ca with a path length of 1 leaves room for end certificates only",
			ca:      pathLenCert(1, false),
			chain:   nil,
			wantLen: 0,
			wantOK:  true,
		},
		{
			name:    "ca with a path length of 3 leaves 2 below the new ca",
			ca:      pathLenCert(3, false),
			chain:   nil,
			wantLen: 2,
			wantOK:  true,
		},
		{
			name:    "ca with an explicit path length of 0 has no room for the new ca",
			ca:      pathLenCert(0, true),
			chain:   nil,
			wantLen: 0,
			wantOK:  false,
		},
		{
			name:    "a constrained issuer one level up that fits",
			ca:      pathLenCert(-1, false),
			chain:   []*x509.Certificate{pathLenCert(2, false)},
			wantLen: 0,
			wantOK:  true,
		},
		{
			name:    "a constrained issuer one level up with room to spare",
			ca:      pathLenCert(-1, false),
			chain:   []*x509.Certificate{pathLenCert(3, false)},
			wantLen: 1,
			wantOK:  true,
		},
		{
			name:    "a constrained issuer one level up that is one too small",
			ca:      pathLenCert(-1, false),
			chain:   []*x509.Certificate{pathLenCert(1, false)},
			wantLen: 0,
			wantOK:  false,
		},
		{
			name:    "an explicit zero further up is exhausted by the ca beneath it",
			ca:      pathLenCert(-1, false),
			chain:   []*x509.Certificate{pathLenCert(-1, false), pathLenCert(0, true)},
			wantLen: 0,
			wantOK:  false,
		},
		{
			name:    "the distance to the constraint counts every level in between",
			ca:      pathLenCert(-1, false),
			chain:   []*x509.Certificate{pathLenCert(-1, false), pathLenCert(-1, false), pathLenCert(4, false)},
			wantLen: 0,
			wantOK:  true,
		},
		{
			name:    "a constraint too far up for the levels in between fails",
			ca:      pathLenCert(-1, false),
			chain:   []*x509.Certificate{pathLenCert(-1, false), pathLenCert(-1, false), pathLenCert(3, false)},
			wantLen: 0,
			wantOK:  false,
		},
		{
			name:    "the tightest constraint wins when it is the ca",
			ca:      pathLenCert(2, false),
			chain:   []*x509.Certificate{pathLenCert(9, false)},
			wantLen: 1,
			wantOK:  true,
		},
		{
			name:    "the tightest constraint wins when it is further up",
			ca:      pathLenCert(9, false),
			chain:   []*x509.Certificate{pathLenCert(3, false)},
			wantLen: 1,
			wantOK:  true,
		},
		{
			name:    "one constraint with no room fails even when another has plenty",
			ca:      pathLenCert(9, false),
			chain:   []*x509.Certificate{pathLenCert(0, true)},
			wantLen: 0,
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotLen, gotOK := subCAPathLen(tt.ca, tt.chain)
			if gotLen != tt.wantLen || gotOK != tt.wantOK {
				t.Errorf("subCAPathLen() = (%d, %t), want (%d, %t)", gotLen, gotOK, tt.wantLen, tt.wantOK)
			}
		})
	}
}

// TestSubCAPathLenLeavesInputsUnmodified checks that building the list of
// certificates to walk does not write into the caller's chain.
func TestSubCAPathLenLeavesInputsUnmodified(t *testing.T) {
	t.Parallel()

	ca := pathLenCert(5, false)
	root := pathLenCert(3, false)
	chain := make([]*x509.Certificate, 1, 2)
	chain[0] = root

	subCAPathLen(ca, chain)

	if got := chain[:2][1]; got != nil {
		t.Errorf("subCAPathLen() wrote %v into the spare capacity of chain, want nil", got)
	}

	if chain[0] != root {
		t.Errorf("subCAPathLen() changed chain[0]")
	}
}
