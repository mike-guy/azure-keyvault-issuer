// Package credential builds azcore.TokenCredential values from the auth
// configuration of an AzureKeyVaultIssuer or AzureKeyVaultClusterIssuer.
//
// A Builder is created once with NewBuilder, given a secretFetcher to read
// Kubernetes Secrets and a tokenRequester to mint ServiceAccount tokens. Each
// reconcile then calls Builder.BuildTokenFetcher with the issuer's scope, Auth
// block and namespace.
//
// # Auth methods
//
// Exactly one method may be set on an Auth block:
//
//   - workloadIdentity exchanges a Kubernetes ServiceAccount token for an Entra
//     access token through a federated identity credential.
//   - clientSecret authenticates an app registration with a secret read from a
//     Kubernetes Secret.
//   - clientCertificate authenticates an app registration with the tls.crt and
//     tls.key keys of a Kubernetes Secret.
//
// A ClusterIssuer may omit the Auth block to use the controller's own ambient
// workload identity. A namespaced Issuer must supply one, so it can never adopt
// the controller's identity. Secrets and ServiceAccounts are always resolved in
// the namespace passed to BuildTokenFetcher.
//
// # Errors
//
// Every classified error carries "credential:" in its message.
//
//   - ErrInvalidConfig needs the issuer or a referenced Secret to change. It is
//     still retried slowly rather than failed, as an edit to a Secret triggers
//     no reconcile.
//   - ErrAmbientIdentityUnavailable and ErrSecretNotFound are fixed outside the
//     issuer, so callers should retry slowly.
//   - Anything else, such as a failed token request, is unclassified and safe to
//     retry with backoff, unless it is a programmer error such as a nil
//     dependency.
//
// The Secret reader must return an error wrapping ErrSecretNotFound when a
// Secret is missing, and the builder does the same for a missing key. See
// docs/errors-and-logging.md for the conventions shared by every package.
//
// # Logging
//
// This package never logs an error it returns. It logs flow at V(1), through the
// logger BuildTokenFetcher puts in the context.
//
// # Credential lifetime
//
// A credential is built for each Check and Sign and must not be held across
// reconciles, as it would pin the Secret values it was built from and hide a
// rotation or revocation. The SDK calls its callbacks with a context that has no
// logger, so the client assertion callback restores the one from the reconcile
// that built the credential.
package credential
