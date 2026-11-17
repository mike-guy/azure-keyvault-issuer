package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// pemTypeCSR is the PEM block type for a certificate signing request.
const pemTypeCSR = "CERTIFICATE REQUEST"

// pemBeginPrefix is how every PEM block starts.
const pemBeginPrefix = "-----BEGIN "

// CertSigningRequest is a request to sign. PEMData is the PEM encoded CSR,
// Duration the requested lifetime (zero for the default) and IsCA whether the
// certificate is to be a CA. KeyUsage and ExtKeyUsage are converted from the
// CertificateRequest's usages by the caller. When they are empty, or are exactly
// cert-manager's default for a Certificate that sets none, the certificate gets
// server auth as well.
type CertSigningRequest struct {
	PEMData     []byte
	Duration    time.Duration
	IsCA        bool
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
}

// validateAndParse returns the CSR in c, or an error wrapping ErrInvalidRequest
// unless the PEM data is exactly one certificate request with a valid
// signature.
func (c CertSigningRequest) validateAndParse() (*x509.CertificateRequest, error) {
	if len(c.PEMData) == 0 {
		return nil, fmt.Errorf("%w: certificate signing request has empty PEM data", ErrInvalidRequest)
	}

	block, remaining := pem.Decode(c.PEMData)
	if block == nil {
		return nil, fmt.Errorf("%w: PEM data contains no blocks", ErrInvalidRequest)
	}

	// pem.Decode skips anything before the first block, so check there is none.
	if !bytes.HasPrefix(bytes.TrimSpace(c.PEMData), []byte(pemBeginPrefix)) {
		return nil, fmt.Errorf("%w: unexpected data before the certificate request", ErrInvalidRequest)
	}

	if block.Type != pemTypeCSR {
		return nil, fmt.Errorf("%w: unexpected PEM type %q, want %q", ErrInvalidRequest, block.Type, pemTypeCSR)
	}

	trimmed := bytes.TrimSpace(remaining)
	if len(trimmed) > 0 {
		return nil, fmt.Errorf("%w: unexpected additional PEM data after the certificate request", ErrInvalidRequest)
	}

	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing certificate request: %w", ErrInvalidRequest, err)
	}

	if err := parsed.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: certificate request signature is invalid: %w", ErrInvalidRequest, err)
	}

	return parsed, nil
}
