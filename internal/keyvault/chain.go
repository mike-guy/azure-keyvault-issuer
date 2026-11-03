package keyvault

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// maxChainLength bounds the work done on a chain read from Key Vault. Real
// PKIs are far shorter.
const maxChainLength = 10

// pemContentType is the secret content type of a PEM certificate. The other
// type Key Vault uses, application/x-pkcs12, is refused.
const pemContentType = "application/x-pem-file"

// parseChain parses the PEM chain stored in a certificate's backing secret,
// using the standard pem.Decode loop.
//
// For an exportable certificate that secret also holds the CA private key.
// The caller prevents that by refusing exportable certificates before reading
// the secret. An older version may still have been created exportable before
// the policy was tightened, so a private key block fails with ErrUnsafeSecret.
// That tells the operator to fix the certificate, rather than leaving the
// issuer to fetch the key on every check. The block is never parsed, logged or
// put in an error.
func parseChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, fmt.Errorf("%w: the secret contains a private key", ErrUnsafeSecret)
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: unexpected PEM block of type %q", ErrInvalidChain, block.Type)
		}

		if len(certs) == maxChainLength {
			return nil, fmt.Errorf("%w: more than %d certificates", ErrInvalidChain, maxChainLength)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parsing certificate %d: %w", ErrInvalidChain, len(certs), err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificates", ErrInvalidChain)
	}

	return certs, nil
}
