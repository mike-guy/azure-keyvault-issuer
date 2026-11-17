// Package pki signs certificate requests with a certificate authority, within
// a policy that limits what is issued.
//
// NewSigner takes an Authority and a Policy. Sign validates a
// CertSigningRequest, builds the certificate, has the Authority sign it and
// returns the leaf, the issuer and the chain above it as PEM. An Authority is a
// crypto.Signer that also knows its certificate and chain, so this package does
// not depend on Azure.
//
// Only the subject and subject alternative names come from the CSR. The
// lifetime, usages and whether a CA is wanted come from the CertSigningRequest,
// and the serial number, validity start and basic constraints are always set
// here.
//
// A request is refused as an ErrInvalidRequest unless:
//   - its names are permitted by Policy.AllowedDomains, if set;
//   - its extended key usages are in Policy.AllowedExtKeyUsages;
//   - its names satisfy any name constraints in the Authority's certificate and
//     the chain above it;
//   - it is not for a CA, or Policy.AllowCA is set, the path length constraints
//     leave room and the subject differs from the Authority's certificate and
//     the chain above it.
//
// A lifetime is clamped rather than refused, first to Policy.MaxDuration and
// then to the earliest expiry in the Authority's certificate and chain.
// SignedCertificate reports both clamps, and the CA's expiry on every result,
// and leaves it to the caller to make them visible.
//
// # Errors
//
// Every classified error carries "pki:" in its message.
//
//   - ErrInvalidRequest is permanent until the request changes.
//   - ErrInvalidConfig is permanent until the policy changes.
//   - ErrAuthorityUnusable is fixed in the vault, so callers should retry
//     slowly.
//   - Anything else, including errors from the Authority's Sign, is
//     unclassified and safe to retry with backoff.
//
// See docs/errors-and-logging.md for the conventions shared by every package.
//
// # Logging
//
// Sign takes a context only for its logger. At V(1) the package logs each
// decision that changes what the requester asked for, and never an error it
// returns.
package pki
