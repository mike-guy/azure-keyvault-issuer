package vault

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
	"time"
)

// chainCase is one input to validateAndOrderChain and what it should return.
type chainCase struct {
	ca         *x509.Certificate
	candidates []*x509.Certificate
	wantChain  []*x509.Certificate
	wantUnused []*x509.Certificate
	wantErr    error
	wantMsg    string // substring expected in the error message
}

// checkChain runs validateAndOrderChain on tc and asserts the outcome.
func checkChain(t *testing.T, tc chainCase) {
	t.Helper()

	// validateAndOrderChain must not reorder or modify the caller's slice.
	before := append([]*x509.Certificate(nil), tc.candidates...)

	chain, unused, err := validateAndOrderChain(tc.ca, tc.candidates, chainTestNow)

	if !sameCerts(tc.candidates, before) {
		t.Errorf("validateAndOrderChain() modified the candidates slice")
	}

	if !errors.Is(err, tc.wantErr) {
		t.Fatalf("validateAndOrderChain() error = %v, want %v", err, tc.wantErr)
	}

	if err != nil && !strings.Contains(err.Error(), tc.wantMsg) {
		t.Errorf("validateAndOrderChain() error = %q, want it to contain %q", err, tc.wantMsg)
	}

	if !sameCerts(chain, tc.wantChain) {
		t.Errorf("validateAndOrderChain() chain = %s, want %s", subjects(chain), subjects(tc.wantChain))
	}

	if !sameCerts(unused, tc.wantUnused) {
		t.Errorf("validateAndOrderChain() unused = %s, want %s", subjects(unused), subjects(tc.wantUnused))
	}
}

func TestValidateAndOrderChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(t *testing.T) chainCase
	}{
		{
			name: "root directly above the ca is the chain",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				ca := issue(t, newCertSpec("ca"), root)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{root.cert},
					wantChain:  []*x509.Certificate{root.cert},
					wantUnused: nil,
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
		{
			name: "the ca in the candidates is ignored",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				ca := issue(t, newCertSpec("ca"), root)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{ca.cert, root.cert},
					wantChain:  []*x509.Certificate{root.cert},
					wantUnused: nil,
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
		{
			name: "candidates in any order come back nearest issuer first",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				inter1 := issue(t, newCertSpec("inter1"), root)
				inter2 := issue(t, newCertSpec("inter2"), inter1)
				ca := issue(t, newCertSpec("ca"), inter2)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{root.cert, inter1.cert, ca.cert, inter2.cert},
					wantChain:  []*x509.Certificate{inter2.cert, inter1.cert, root.cert},
					wantUnused: nil,
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
		{
			name: "chain may end below a root that is not in the candidates",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				inter := issue(t, newCertSpec("inter"), root)
				ca := issue(t, newCertSpec("ca"), inter)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{inter.cert},
					wantChain:  []*x509.Certificate{inter.cert},
					wantUnused: nil,
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
		{
			name: "unrelated candidates are returned as unused in their original order",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				ca := issue(t, newCertSpec("ca"), root)
				otherA := issue(t, newCertSpec("other-a"), nil)
				otherB := issue(t, newCertSpec("other-b"), nil)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{otherA.cert, root.cert, otherB.cert},
					wantChain:  []*x509.Certificate{root.cert},
					wantUnused: []*x509.Certificate{otherA.cert, otherB.cert},
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
		{
			name: "an expired unused candidate does not fail",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				ca := issue(t, newCertSpec("ca"), root)

				expiredSpec := newCertSpec("expired-other")
				expiredSpec.notBefore = chainTestNow.Add(-48 * time.Hour)
				expiredSpec.notAfter = chainTestNow.Add(-24 * time.Hour)
				expired := issue(t, expiredSpec, nil)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{root.cert, expired.cert},
					wantChain:  []*x509.Certificate{root.cert},
					wantUnused: []*x509.Certificate{expired.cert},
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
		{
			name: "same subject but a different key does not link",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				impostor := issue(t, newCertSpec("root"), nil)
				ca := issue(t, newCertSpec("ca"), root)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{impostor.cert, root.cert},
					wantChain:  []*x509.Certificate{root.cert},
					wantUnused: []*x509.Certificate{impostor.cert},
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
		{
			name: "a signer that is not a ca is unused",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				ca := issue(t, newCertSpec("ca"), root)

				notCASpec := newCertSpec("not-a-ca")
				notCASpec.isCA = false
				notCA := issue(t, notCASpec, nil)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{notCA.cert, root.cert},
					wantChain:  []*x509.Certificate{root.cert},
					wantUnused: []*x509.Certificate{notCA.cert},
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
		{
			name: "only a signer that is not a ca fails",
			build: func(t *testing.T) chainCase {
				signerSpec := newCertSpec("signer")
				signerSpec.isCA = false
				signer := issue(t, signerSpec, nil)

				// x509.CreateCertificate does not enforce that the issuer is a CA,
				// so the ca can carry a real signature from a non-CA.
				ca := issue(t, newCertSpec("ca"), signer)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{signer.cert},
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "no certificates that chain above",
				}
			},
		},
		{
			name: "a signer without basic constraints fails",
			build: func(t *testing.T) chainCase {
				signerSpec := newCertSpec("signer")
				signerSpec.isCA = false
				signerSpec.basicConstraintsValid = false
				signer := issue(t, signerSpec, nil)
				ca := issue(t, newCertSpec("ca"), signer)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{signer.cert},
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "no certificates that chain above",
				}
			},
		},
		{
			name: "no candidates fails",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				ca := issue(t, newCertSpec("ca"), root)

				return chainCase{
					ca:         ca.cert,
					candidates: nil,
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "no certificates that chain above",
				}
			},
		},
		{
			name: "only the ca itself fails",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				ca := issue(t, newCertSpec("ca"), root)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{ca.cert},
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "no certificates that chain above",
				}
			},
		},
		{
			name: "only unrelated candidates fails",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				ca := issue(t, newCertSpec("ca"), root)
				other := issue(t, newCertSpec("other"), nil)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{ca.cert, other.cert},
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "no certificates that chain above",
				}
			},
		},
		{
			name: "a self-signed ca has nothing above it and fails",
			build: func(t *testing.T) chainCase {
				ca := issue(t, newCertSpec("ca"), nil)
				other := issue(t, newCertSpec("other"), nil)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{ca.cert, other.cert},
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "no certificates that chain above",
				}
			},
		},
		{
			name: "a linked certificate that has expired fails",
			build: func(t *testing.T) chainCase {
				rootSpec := newCertSpec("root")
				rootSpec.notBefore = chainTestNow.Add(-48 * time.Hour)
				rootSpec.notAfter = chainTestNow.Add(-time.Hour)
				root := issue(t, rootSpec, nil)
				ca := issue(t, newCertSpec("ca"), root)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{root.cert},
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "expired",
				}
			},
		},
		{
			name: "a linked certificate that is not yet valid fails",
			build: func(t *testing.T) chainCase {
				rootSpec := newCertSpec("root")
				rootSpec.notBefore = chainTestNow.Add(time.Hour)
				rootSpec.notAfter = chainTestNow.Add(48 * time.Hour)
				root := issue(t, rootSpec, nil)
				ca := issue(t, newCertSpec("ca"), root)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{root.cert},
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "not valid until",
				}
			},
		},
		{
			name: "an expired intermediate fails even with a valid root above it",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)

				interSpec := newCertSpec("inter")
				interSpec.notBefore = chainTestNow.Add(-48 * time.Hour)
				interSpec.notAfter = chainTestNow.Add(-time.Hour)
				inter := issue(t, interSpec, root)
				ca := issue(t, newCertSpec("ca"), inter)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{root.cert, inter.cert},
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "expired",
				}
			},
		},
		{
			name: "a path length that fits the chain passes",
			build: func(t *testing.T) chainCase {
				rootSpec := newCertSpec("root")
				rootSpec.maxPathLen = 2
				root := issue(t, rootSpec, nil)
				inter := issue(t, newCertSpec("inter"), root)
				ca := issue(t, newCertSpec("ca"), inter)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{root.cert, inter.cert},
					wantChain:  []*x509.Certificate{inter.cert, root.cert},
					wantUnused: nil,
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
		{
			name: "a path length one too small fails",
			build: func(t *testing.T) chainCase {
				rootSpec := newCertSpec("root")
				rootSpec.maxPathLen = 1
				root := issue(t, rootSpec, nil)
				inter := issue(t, newCertSpec("inter"), root)
				ca := issue(t, newCertSpec("ca"), inter)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{root.cert, inter.cert},
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "allows 1 CA(s) beneath it but the chain has 2",
				}
			},
		},
		{
			name: "a path length of zero with the ca beneath it fails",
			build: func(t *testing.T) chainCase {
				rootSpec := newCertSpec("root")
				rootSpec.maxPathLen = 0
				rootSpec.maxPathLenZero = true
				root := issue(t, rootSpec, nil)
				ca := issue(t, newCertSpec("ca"), root)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{root.cert},
					wantChain:  nil,
					wantUnused: nil,
					wantErr:    ErrCertificateUnusable,
					wantMsg:    "allows 0 CA(s) beneath it but the chain has 1",
				}
			},
		},
		{
			name: "an unconstrained path length never fails",
			build: func(t *testing.T) chainCase {
				root := issue(t, newCertSpec("root"), nil)
				inter1 := issue(t, newCertSpec("inter1"), root)
				inter2 := issue(t, newCertSpec("inter2"), inter1)
				inter3 := issue(t, newCertSpec("inter3"), inter2)
				ca := issue(t, newCertSpec("ca"), inter3)

				return chainCase{
					ca:         ca.cert,
					candidates: []*x509.Certificate{root.cert, inter1.cert, inter2.cert, inter3.cert},
					wantChain:  []*x509.Certificate{inter3.cert, inter2.cert, inter1.cert, root.cert},
					wantUnused: nil,
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
		{
			name: "a cycle of issuers terminates",
			build: func(t *testing.T) chainCase {
				spec := newCertSpec("")
				xKey := spec.key.generate(t)
				yKey := spec.key.generate(t)
				caKey := spec.key.generate(t)

				xName := &x509.Certificate{Subject: pkix.Name{CommonName: "x"}, PublicKey: xKey.Public()}
				yName := &x509.Certificate{Subject: pkix.Name{CommonName: "y"}, PublicKey: yKey.Public()}

				// x is issued by y and y is issued by x, so neither is ever self-signed.
				x := createTestCert(t, newCertSpec("x"), xKey, yName, yKey)
				y := createTestCert(t, newCertSpec("y"), yKey, xName, xKey)
				ca := createTestCert(t, newCertSpec("ca"), caKey, xName, xKey)

				return chainCase{
					ca:         ca,
					candidates: []*x509.Certificate{y, x},
					wantChain:  []*x509.Certificate{x, y},
					wantUnused: nil,
					wantErr:    nil,
					wantMsg:    "",
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkChain(t, tt.build(t))
		})
	}
}

// TestValidateAndOrderChainKeyTypes checks that certificates link whatever
// key types signed them, including when the types differ along the chain.
func TestValidateAndOrderChainKeyTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rootKey   keyType
		interKey  keyType
		caKey     keyType
		wantChain []string // common names, nearest issuer first
	}{
		{name: "rsa throughout", rootKey: keyRSA2048, interKey: keyRSA2048, caKey: keyRSA2048, wantChain: []string{"inter", "root"}},
		{name: "ecdsa p256 throughout", rootKey: keyECDSAP256, interKey: keyECDSAP256, caKey: keyECDSAP256, wantChain: []string{"inter", "root"}},
		{name: "ecdsa p384 throughout", rootKey: keyECDSAP384, interKey: keyECDSAP384, caKey: keyECDSAP384, wantChain: []string{"inter", "root"}},
		{name: "ecdsa p521 throughout", rootKey: keyECDSAP521, interKey: keyECDSAP521, caKey: keyECDSAP521, wantChain: []string{"inter", "root"}},
		{name: "rsa root signing an ecdsa chain", rootKey: keyRSA2048, interKey: keyECDSAP256, caKey: keyECDSAP384, wantChain: []string{"inter", "root"}},
		{name: "ecdsa root signing an rsa chain", rootKey: keyECDSAP521, interKey: keyRSA2048, caKey: keyRSA2048, wantChain: []string{"inter", "root"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rootSpec := newCertSpec("root")
			rootSpec.key = tt.rootKey
			root := issue(t, rootSpec, nil)

			interSpec := newCertSpec("inter")
			interSpec.key = tt.interKey
			inter := issue(t, interSpec, root)

			caSpec := newCertSpec("ca")
			caSpec.key = tt.caKey
			ca := issue(t, caSpec, inter)

			chain, unused, err := validateAndOrderChain(ca.cert, []*x509.Certificate{root.cert, inter.cert}, chainTestNow)
			if err != nil {
				t.Fatalf("validateAndOrderChain() error = %v, want nil", err)
			}

			if len(unused) != 0 {
				t.Errorf("validateAndOrderChain() unused = %s, want none", subjects(unused))
			}

			if got, want := subjects(chain), "["+strings.Join(tt.wantChain, " ")+"]"; got != want {
				t.Errorf("validateAndOrderChain() chain = %s, want %s", got, want)
			}
		})
	}
}
