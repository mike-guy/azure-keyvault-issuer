// Package vault loads a certificate authority from Azure Key Vault and exposes
// it as a crypto.Signer, so requests can be signed without the private key
// leaving the vault.
//
// NewCertificateAuthority takes a Config naming the vault and certificate. It
// resolves one version of the CA certificate, loads the chain above it from the
// certificate's backing secret when Config.ChainInSecret is set, and returns a
// CertificateAuthority bound to that version.
//
// # Backing secret
//
// The secret is only read for the chain. It is always requested as PEM, whatever
// format the certificate's policy stores it in, and a response in any other
// format is refused as ErrCertificateUnusable. The chain is ordered here rather
// than trusted to the secret's order.
//
// # Private keys
//
// The key should be non-exportable. An exportable key is allowed, but warned
// about, from the certificate's policy and from the backing secret when it is
// read. The policy belongs to the certificate, not a version, so with a pinned
// version it may not describe that version; the secret is the only per-version
// evidence. No warning is not evidence that the key is safe.
//
// # Errors
//
// Every classified error carries "vault:" in its message.
//
//   - ErrInvalidConfig is permanent until the issuer changes.
//   - ErrNotFound, ErrAccessDenied and ErrCertificateUnusable are fixed in the
//     vault, so callers should retry slowly. ErrCertificateUnusable includes a
//     signature that does not verify against the certificate, which Sign checks.
//   - Anything else, such as throttling or a network failure, is unclassified
//     and safe to retry with backoff, unless it is a programmer error such as a
//     nil credential.
//
// See docs/errors-and-logging.md for the conventions shared by every package.
//
// # Logging
//
// This package never logs an error it returns. It logs flow at V(1), and uses
// Info only for oddities the user should act on, each starting with "warning:"
// as logr has no warning level.
package vault
