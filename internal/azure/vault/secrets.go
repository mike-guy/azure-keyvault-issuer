package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// secretFetcher is the part of the azsecrets client that this package uses, so
// tests need no network.
type secretFetcher interface {
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

// contentTypePEM is the content type of the backing secret that we ask Key Vault
// for, and the only one we accept back. The certificate's policy sets the format
// the secret is stored in, and Key Vault converts it to PEM when asked.
const contentTypePEM = string(azsecrets.ContentTypePEM)

// secretInfo holds the plain values we need from a secret response.
type secretInfo struct {
	value       string
	contentType string
}

// secretContents is what was found in a certificate's backing secret. skipped
// holds the types of any PEM blocks that were not certificates, and privateKey
// says whether one of them was a private key, which is never used.
type secretContents struct {
	certs      []*x509.Certificate
	skipped    []string
	privateKey bool
}

// secretInfoFrom copies out the fields we rely on, so nothing after this touches
// SDK pointers. A response missing them is malformed rather than a problem with
// the certificate, so these errors are deliberately not ErrCertificateUnusable.
func secretInfoFrom(resp azsecrets.GetSecretResponse) (secretInfo, error) {
	if resp.Value == nil {
		return secretInfo{}, errors.New("vault returned no value on secret response")
	}

	if resp.ContentType == nil {
		return secretInfo{}, errors.New("vault returned no content type on secret response")
	}

	return secretInfo{
		value:       *resp.Value,
		contentType: *resp.ContentType,
	}, nil
}

// extractCerts returns the certificates in the backing secret, in the order
// found. Any content type but PEM means Key Vault ignored the request to
// convert it, and is refused rather than guessed at.
func extractCerts(info secretInfo) (secretContents, error) {
	if info.contentType != contentTypePEM {
		return secretContents{}, fmt.Errorf("%w: backing secret has content type %q although %q was requested, so Key Vault did not convert it",
			ErrCertificateUnusable, info.contentType, contentTypePEM)
	}

	contents, err := extractPEMCerts(info.value)
	if err != nil {
		return secretContents{}, err
	}

	if len(contents.certs) == 0 {
		return secretContents{}, fmt.Errorf("%w: no certificates found in backing secret", ErrCertificateUnusable)
	}

	return contents, nil
}

// extractPEMCerts parses every CERTIFICATE block in value, in the order found,
// and returns the types of any other blocks as skipped.
func extractPEMCerts(value string) (secretContents, error) {
	var contents secretContents

	remaining := []byte(value)

	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}

		// An exportable key comes back in the secret. It is skipped, but noted.
		if block.Type != "CERTIFICATE" {
			contents.skipped = append(contents.skipped, block.Type)

			if strings.HasSuffix(block.Type, "PRIVATE KEY") {
				contents.privateKey = true
			}

			continue
		}

		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return secretContents{}, fmt.Errorf("%w: parsing certificate in backing secret: %w", ErrCertificateUnusable, err)
		}
		contents.certs = append(contents.certs, c)
	}

	return contents, nil
}
