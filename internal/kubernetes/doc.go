// Package kubernetes implements the Kubernetes side of credential.Builder: a
// SecretFetcher that reads Secrets and a TokenRequester that mints
// ServiceAccount tokens.
//
// Both are thin adapters over controller-runtime. The interfaces they satisfy
// are defined, unexported, in internal/azure/credential, so this package
// imports credential only for its error sentinels.
//
// NewSecretFetcher should be given the manager's API reader
// (mgr.GetAPIReader()), not its cached client, which would start an informer
// over every Secret in the cluster. Each read is a single GET, so the
// controller needs only the "get" verb, and a rotated Secret is seen at once.
//
// Neither adapter sets a timeout. The deadline is on the context the caller
// passes in, which controllers.KeyVaultSigner sets for every Check and Sign.
//
// # RBAC
//
// The controller needs "get" on secrets, and "create" on serviceaccounts/token,
// in every namespace an issuer may live in.
//
// # Errors
//
// SecretFetcher wraps credential.ErrSecretNotFound when a Secret does not exist.
// Every other error, including Forbidden and failed token requests, is wrapped
// with the object it concerns but unclassified, and is safe to retry with
// backoff. A missing ServiceAccount is deliberately unclassified, as the Azure
// SDK flattens the error from its assertion callback into a message, so a
// sentinel would not survive. See docs/errors-and-logging.md for the
// conventions shared by every package.
//
// # Logging
//
// Both methods log through the logger in their context. CreateToken logs at
// V(1) the lifetime the API server granted, which it may choose differently
// from the one asked for. SecretFetcher logs nothing, as credential logs the
// fetch. Secret data and tokens are never logged or put in an error message.
package kubernetes
