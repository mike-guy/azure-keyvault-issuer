package credential

import "errors"

// ErrInvalidConfig means the issuer's auth configuration, or the content of a
// Secret it references, is wrong. It stays so until the user changes something.
// An edit to the issuer triggers a reconcile but an edit to a Secret does not,
// so callers must not treat every error wrapping this as permanent. The message
// names the offending field.
var ErrInvalidConfig = errors.New("credential: invalid configuration")

// ErrAmbientIdentityUnavailable means the controller pod has no usable workload
// identity, such as a missing AZURE_CLIENT_ID, AZURE_TENANT_ID or
// AZURE_FEDERATED_TOKEN_FILE. The controller's deployment is wrong, not the
// issuer, which is why it is distinct from ErrInvalidConfig.
var ErrAmbientIdentityUnavailable = errors.New("credential: ambient workload identity unavailable")

// ErrSecretNotFound means a Secret, or a key within it, that the issuer
// references does not exist. It is fixed in the cluster without changing the
// issuer, so callers should retry slowly.
//
// A secretFetcher must return an error wrapping this when the Secret is
// missing. The builder passes it through, and returns it itself for a missing
// key.
var ErrSecretNotFound = errors.New("credential: secret not found")

// An error that wraps none of the sentinels above, such as a failed Secret read
// or token request, is safe to retry with backoff, unless it is a programmer
// error such as a nil dependency or an unknown issuer type.
