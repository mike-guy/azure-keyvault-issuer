package vault

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
)

// keySigner is the part of the azkeys client that Sign uses, so tests need no
// network.
type keySigner interface {
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

// ecdsaSignature is the ASN.1 structure of an ECDSA signature.
type ecdsaSignature struct {
	R, S *big.Int
}

// ecdsaAlgorithm is the Key Vault algorithm for an ECDSA curve, and the only
// hash it accepts, as Key Vault requires the hash size to match the curve.
type ecdsaAlgorithm struct {
	algorithm azkeys.SignatureAlgorithm
	hash      crypto.Hash
}

// rsaAlgorithm is the Key Vault algorithms for an RSA key signing with one
// hash, for PKCS#1 v1.5 and for PSS.
type rsaAlgorithm struct {
	pkcs1 azkeys.SignatureAlgorithm
	pss   azkeys.SignatureAlgorithm
}

// Public implements crypto.Signer, returning the CA certificate's public key.
func (a *CertificateAuthority) Public() crypto.PublicKey {
	return a.publicKey
}

// Sign implements crypto.Signer by asking the Key Vault key to sign digest. rand
// is unused, as the vault supplies its own randomness. opts must carry the hash
// that produced digest, and for RSA may be *rsa.PSSOptions to select PSS rather
// than PKCS#1 v1.5. Vault failures are passed through classify.
func (a *CertificateAuthority) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	alg, err := a.determineKeyVaultSignAlgorithm(opts)
	if err != nil {
		return nil, err
	}

	hashFunc := opts.HashFunc()

	if hashFunc.Size() != len(digest) {
		return nil, errors.New("provided hash function size does not match digest")
	}

	signParam := azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest,
	}
	signOpts := &azkeys.SignOptions{}
	sig, err := a.keysigner.Sign(a.ctx, a.certAndKeyName, a.certAndKeyVersion, signParam, signOpts)
	if err != nil {
		return nil, fmt.Errorf("signing digest with vault key: %w", classify(err))
	}

	result := sig.Result
	if len(result) == 0 {
		return nil, errors.New("vault returned an empty signature")
	}

	// Key Vault returns ECDSA as r || s, but crypto.Signer wants ASN.1 DER.
	signature = result
	if pub, ok := a.publicKey.(*ecdsa.PublicKey); ok {
		signature, err = processECDSAResult(pub.Curve, result)
		if err != nil {
			return nil, err
		}
	}

	// So a wrong key version or a corrupt response fails here rather than as a
	// bad certificate.
	if err := verifySignature(a.publicKey, opts, digest, signature); err != nil {
		return nil, err
	}

	return signature, nil
}

// verifySignature checks that signature is a valid signature of digest by pub,
// in the scheme Sign asked the vault for.
func verifySignature(pub crypto.PublicKey, opts crypto.SignerOpts, digest []byte, signature []byte) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		var err error
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			err = rsa.VerifyPSS(key, opts.HashFunc(), digest, signature, pss)
		} else {
			err = rsa.VerifyPKCS1v15(key, opts.HashFunc(), digest, signature)
		}

		if err != nil {
			return fmt.Errorf("%w: vault returned a signature that does not verify against the CA public key: %w", ErrCertificateUnusable, err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return fmt.Errorf("%w: vault returned a signature that does not verify against the CA public key", ErrCertificateUnusable)
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}

	return nil
}

// ecdsaAlgorithms and rsaAlgorithms define which keys this package can sign
// with. checkKeySupported reads them when the CA is loaded, and
// determineKeyVaultSignAlgorithm on every signature.
var (
	ecdsaAlgorithms = map[elliptic.Curve]ecdsaAlgorithm{
		elliptic.P256(): {algorithm: azkeys.SignatureAlgorithmES256, hash: crypto.SHA256},
		elliptic.P384(): {algorithm: azkeys.SignatureAlgorithmES384, hash: crypto.SHA384},
		elliptic.P521(): {algorithm: azkeys.SignatureAlgorithmES512, hash: crypto.SHA512},
	}

	rsaAlgorithms = map[crypto.Hash]rsaAlgorithm{
		crypto.SHA256: {pkcs1: azkeys.SignatureAlgorithmRS256, pss: azkeys.SignatureAlgorithmPS256},
		crypto.SHA384: {pkcs1: azkeys.SignatureAlgorithmRS384, pss: azkeys.SignatureAlgorithmPS384},
		crypto.SHA512: {pkcs1: azkeys.SignatureAlgorithmRS512, pss: azkeys.SignatureAlgorithmPS512},
	}
)

// checkKeySupported rejects a key Sign cannot sign with when the CA is loaded,
// rather than on every request. Any RSA key is accepted, as the hash is only
// known at signing time.
func checkKeySupported(pub crypto.PublicKey) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return nil
	case *ecdsa.PublicKey:
		if _, ok := ecdsaAlgorithms[key.Curve]; !ok {
			return fmt.Errorf("%w: unsupported ECDSA curve %s", ErrCertificateUnusable, key.Curve.Params().Name)
		}

		return nil
	default:
		return fmt.Errorf("%w: unsupported public key type %T", ErrCertificateUnusable, pub)
	}
}

// determineKeyVaultSignAlgorithm maps the key and hash to a Key Vault
// algorithm.
func (a *CertificateAuthority) determineKeyVaultSignAlgorithm(opts crypto.SignerOpts) (azkeys.SignatureAlgorithm, error) {
	if opts == nil {
		return "", errors.New("signer options must not be nil")
	}
	hashFunc := opts.HashFunc()

	switch pub := a.publicKey.(type) {
	case *rsa.PublicKey:
		algorithm, ok := rsaAlgorithms[hashFunc]
		if !ok {
			return "", fmt.Errorf("unsupported hash for RSA: %s", hashFunc.String())
		}

		pss, isPSS := opts.(*rsa.PSSOptions)
		if !isPSS {
			return algorithm.pkcs1, nil
		}

		// Key Vault always uses a salt as long as the hash, so any other length
		// would give a signature that fails verification.
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash && pss.SaltLength != hashFunc.Size() {
			return "", fmt.Errorf("RSA-PSS salt length must equal the hash size, got %d", pss.SaltLength)
		}

		return algorithm.pss, nil

	case *ecdsa.PublicKey:
		algorithm, ok := ecdsaAlgorithms[pub.Curve]
		if !ok {
			return "", fmt.Errorf("unsupported ECDSA curve: %s", pub.Curve.Params().Name)
		}

		if hashFunc != algorithm.hash {
			return "", fmt.Errorf("ECDSA %s requires %s, got %s", pub.Curve.Params().Name, algorithm.hash.String(), hashFunc.String())
		}

		return algorithm.algorithm, nil

	default:
		return "", fmt.Errorf("unsupported public key type: %T", a.publicKey)
	}
}

// processECDSAResult converts an ECDSA signature from Key Vault, r || s, into
// ASN.1 DER. It fails unless the signature is two halves of the curve's byte
// size, such as 66 bytes each for P-521.
func processECDSAResult(curve elliptic.Curve, sig []byte) ([]byte, error) {
	half := (curve.Params().BitSize + 7) / 8
	if len(sig) != 2*half {
		return nil, fmt.Errorf("vault returned an ECDSA signature of %d bytes, want %d", len(sig), 2*half)
	}

	rBytes := sig[:half]
	sBytes := sig[half:]

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	derSignature, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("encoding ECDSA signature as ASN.1: %w", err)
	}

	return derSignature, nil
}
