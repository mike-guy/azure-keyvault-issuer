package keyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/mike-guy/azure-keyvault-issuer/internal/azure"
)

// remoteSigner is a crypto.Signer whose key stays in Key Vault. It signs with
// exactly one key version, the one named by the CA certificate's key ID, so a
// rotation can never pair a certificate with the wrong key.
//
// A remoteSigner serves a single request; CA.Signer makes a new one each time.
type remoteSigner struct {
	// ctx is the context of the request this signer serves. Go's rule is not
	// to store a context in a struct, and this is the one deliberate
	// exception:
	//
	//   - crypto.Signer.Sign takes no context, yet it makes a Key Vault call
	//     that must stop when the request is cancelled or times out.
	//   - x509.CreateCertificate, called through cert-manager's pki package,
	//     builds Sign's rand and opts arguments itself, so the context cannot
	//     travel in those.
	//   - Signing the certificate ourselves, to avoid crypto.Signer, would
	//     mean hand-rolling x509 encoding.
	//   - context.Background would make a hung Key Vault call impossible to
	//     cancel.
	//
	// The exception is contained: remoteSigner is unexported, only CA.Signer
	// creates it, it lives for one signing operation, and the long-lived CA
	// and CAFetcher never hold a context. The containedctx linter rejects any
	// other stored context.
	ctx context.Context //nolint:containedctx // crypto.Signer has no context parameter; the signer is per-request.

	client *azkeys.Client
	key    objectID
	public crypto.PublicKey
}

// remoteSigners returns the factory a CA uses to make a remoteSigner for each
// request's context, signing with key through client. public is the CA
// certificate's public key.
func remoteSigners(client *azkeys.Client, key objectID, public crypto.PublicKey) func(context.Context) crypto.Signer {
	return func(ctx context.Context) crypto.Signer {
		return &remoteSigner{ctx: ctx, client: client, key: key, public: public}
	}
}

// Public returns the CA certificate's public key. Using it rather than asking
// Key Vault means no keys/get permission is needed, and
// x509.CreateCertificate's check of each signature against it catches a key
// that does not match the certificate.
func (s *remoteSigner) Public() crypto.PublicKey {
	return s.public
}

// Sign signs digest with Key Vault's sign operation. rand is unused: Key
// Vault supplies its own randomness.
func (s *remoteSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	alg, err := signatureAlgorithm(s.public, opts)
	if err != nil {
		return nil, err
	}

	if len(digest) != opts.HashFunc().Size() {
		return nil, fmt.Errorf("%w: digest is %d bytes, want %d for %s", ErrSignerOptions, len(digest), opts.HashFunc().Size(), opts.HashFunc())
	}

	resp, err := s.client.Sign(s.ctx, s.key.Name, s.key.Version, azkeys.SignParameters{Algorithm: &alg, Value: digest}, nil)
	if err != nil {
		return nil, fmt.Errorf("signing with Key Vault key %s/%s: %w", s.key.Name, s.key.Version, azure.Shorten(err))
	}

	if pub, ok := s.public.(*ecdsa.PublicKey); ok {
		return joseToDER(resp.Result, curveByteSize(pub.Curve))
	}

	return resp.Result, nil
}

// signatureAlgorithm maps the CA key and the requested hash onto a Key Vault
// algorithm. Any RSA key size can use any of the three hashes. An EC key must
// use the hash that matches its curve, as Key Vault requires; Go's x509 and
// cert-manager both choose that hash, so a mismatch is refused rather than
// remapped.
func signatureAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (azkeys.SignatureAlgorithm, error) {
	if opts == nil {
		return "", fmt.Errorf("%w: no hash given", ErrSignerOptions)
	}

	if _, ok := opts.(*rsa.PSSOptions); ok {
		return "", fmt.Errorf("%w: RSA-PSS is not supported", ErrSignerOptions)
	}

	hash := opts.HashFunc()

	switch k := pub.(type) {
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA256:
			return azkeys.SignatureAlgorithmRS256, nil
		case crypto.SHA384:
			return azkeys.SignatureAlgorithmRS384, nil
		case crypto.SHA512:
			return azkeys.SignatureAlgorithmRS512, nil
		default:
			return "", fmt.Errorf("%w: hash %s with an RSA key", ErrSignerOptions, hash)
		}
	case *ecdsa.PublicKey:
		var want crypto.Hash

		var alg azkeys.SignatureAlgorithm

		switch k.Curve {
		case elliptic.P256():
			want, alg = crypto.SHA256, azkeys.SignatureAlgorithmES256
		case elliptic.P384():
			want, alg = crypto.SHA384, azkeys.SignatureAlgorithmES384
		case elliptic.P521():
			want, alg = crypto.SHA512, azkeys.SignatureAlgorithmES512
		default:
			return "", fmt.Errorf("%w: EC %s", ErrUnsupportedKey, k.Curve.Params().Name)
		}

		if hash != want {
			return "", fmt.Errorf("%w: hash %s with an EC %s key, which needs %s", ErrSignerOptions, hash, k.Curve.Params().Name, want)
		}

		return alg, nil
	default:
		return "", fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
}

// curveByteSize is the length of r and of s in a JOSE ECDSA signature: 32
// bytes for P-256, 48 for P-384 and 66 for P-521.
func curveByteSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

// joseToDER converts a JOSE ECDSA signature, r and s each padded to size
// bytes and concatenated, into the ASN.1 DER form Go's x509 package expects.
func joseToDER(sig []byte, size int) ([]byte, error) {
	if len(sig) != 2*size {
		return nil, fmt.Errorf("converting ECDSA signature: got %d bytes, want %d", len(sig), 2*size)
	}

	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])

	if r.Sign() == 0 || s.Sign() == 0 {
		return nil, errors.New("converting ECDSA signature: r or s is zero")
	}

	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, fmt.Errorf("converting ECDSA signature: %w", err)
	}

	return der, nil
}
