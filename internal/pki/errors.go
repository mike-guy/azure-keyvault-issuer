package pki

import "errors"

// ErrInvalidRequest means the request cannot be honoured: it is malformed, asks
// for something that makes no sense, or is forbidden by the policy or by the
// authority's constraints. Retrying cannot succeed, so callers should treat it
// as permanent. The message names the offending input.
var ErrInvalidRequest = errors.New("pki: invalid request")

// ErrInvalidConfig means the Policy given to NewSigner is wrong, and stays so
// until the issuer changes. The message names the offending field.
var ErrInvalidConfig = errors.New("pki: invalid configuration")

// ErrAuthorityUnusable means a certificate in the authority's chain has
// expired. The fix is in the vault, so nothing announces it and callers should
// retry slowly.
var ErrAuthorityUnusable = errors.New("pki: authority cannot be used to sign")

// An error that wraps none of the sentinels above, such as a failed random read
// or one from the Authority's Sign, is safe to retry with backoff, unless it is
// a programmer error such as a nil Authority.
