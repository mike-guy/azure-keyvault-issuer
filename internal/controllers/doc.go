// Package controllers connects cert-manager's issuer-lib to the credential,
// vault and pki packages.
//
// issuer-lib's CombinedController runs the reconcilers: it watches the issuer
// kinds and CertificateRequests, checks approval and issuerRef, patches status
// and conditions, and retries. This package supplies the two callbacks it
// needs, signer.Check and signer.Sign, as methods on KeyVaultSigner, and
// SetupWithManager registers them.
//
//	issuer reconcile             -> KeyVaultSigner.Check -> Ready condition
//	CertificateRequest reconcile -> KeyVaultSigner.Sign  -> certificate in status
//
// Check and Sign each build the credential and load the CA from Key Vault
// afresh, within the reconcile timeout. See docs/design-notes.md for why.
//
// # Issuer kinds
//
// resolveIssuer is the only place that distinguishes an AzureKeyVaultIssuer
// from an AzureKeyVaultClusterIssuer. A ClusterIssuer reads its Secrets and
// ServiceAccount from the cluster resource namespace, and may limit the
// namespaces that use it with spec.allowedNamespaces, which Sign enforces. With
// no list every namespace may use it, as with cert-manager's own
// ClusterIssuers, and nothing warns about that.
//
// # Errors
//
// issuer-lib reads the type of the error that Check and Sign return:
//
//	signer.PermanentError  the request fails (Check: the issuer is not Ready)
//	                       and nothing is retried until something changes
//	signer.PendingError    Sign only: retried after a fixed interval, however
//	                       long the request has been waiting
//	signer.IssuerError     Sign only: the issuer broke after Check passed, so its
//	                       Ready condition is re-evaluated and the request waits
//	any other error        retried with exponential backoff until
//	                       MaxRetryDuration, then the request fails
//
// Errors map onto these through the classes in docs/errors-and-logging.md. A
// permanent or retry slowly failure to build the signer inside Sign is wrapped
// in IssuerError, so that the issuer reports it and the request waits instead
// of failing for a problem that is not its own. Throttling and other backoff
// errors are not, so that one request backing off does not mark the issuer not
// Ready. A request fails only for its own faults, such as a CSR that the policy
// forbids or a namespace that the ClusterIssuer does not allow.
//
// # Logging and events
//
// This package returns errors and logs nothing itself. It records an event only
// for what succeeded with a caveat, such as a certificate cut short by the CA's
// expiry. See docs/errors-and-logging.md.
package controllers
