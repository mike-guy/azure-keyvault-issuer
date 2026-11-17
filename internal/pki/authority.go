package pki

import (
	"crypto"
	"crypto/x509"
)

// Authority is a CA that can sign. Chain returns the certificates above the
// CA's own, nearest first.
type Authority interface {
	crypto.Signer
	Certificate() *x509.Certificate
	Chain() []*x509.Certificate
}
