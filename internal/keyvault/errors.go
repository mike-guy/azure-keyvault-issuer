package keyvault

import "errors"

// Errors returned, wrapped with context, by this package. Errors from Azure
// itself are wrapped with azure.Shorten, so their text is one line;
// azure.StatusCode tells them apart.
var (
	// ErrCADisabled reports a CA certificate version that is disabled.
	ErrCADisabled = errors.New("CA certificate version is disabled")

	// ErrCANotIssued reports a CA certificate version with no issued
	// certificate yet, such as one waiting for its signed certificate to be
	// merged.
	ErrCANotIssued = errors.New("CA certificate version has no issued certificate")

	// ErrInvalidCA reports a certificate that cannot act as a CA.
	ErrInvalidCA = errors.New("invalid CA certificate")

	// ErrUnsupportedKey reports a CA key type or size this issuer does not
	// support.
	ErrUnsupportedKey = errors.New("unsupported CA key")

	// ErrUnsafeSecret reports a certificate's backing secret that is not safe
	// to read for its chain, because it could contain the private key.
	ErrUnsafeSecret = errors.New("unsafe certificate secret")

	// ErrInvalidChain reports a CA chain that is malformed or does not link up.
	ErrInvalidChain = errors.New("invalid CA chain")

	// ErrInvalidCASource reports a certificate name or version that
	// breaks the CRD's rules. A bad vault URL is reported with
	// ErrInvalidVaultURL instead.
	ErrInvalidCASource = errors.New("invalid CA source")

	// ErrSignerOptions reports signer options that the CA key cannot honour,
	// such as RSA-PSS or a hash that does not match the curve.
	ErrSignerOptions = errors.New("unsupported signer options")
)
