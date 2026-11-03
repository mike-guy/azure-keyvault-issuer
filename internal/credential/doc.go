// Package credential supplies the Azure credential each issuer uses to call
// Key Vault.
//
// A Provider turns an issuer's spec.auth into an azcore.TokenCredential:
//
//   - With no auth method, the issuer uses the controller's own (ambient)
//     workload identity, if the ambient policy permits it for that kind of
//     issuer. Following cert-manager, ClusterIssuers are permitted by default
//     and namespaced Issuers are not.
//   - With workloadIdentity, the controller requests a short-lived token for
//     the named ServiceAccount through the TokenRequest API and exchanges it
//     with Microsoft Entra. The ServiceAccount is in the issuer's namespace,
//     or in the cluster resource namespace for a ClusterIssuer. Which
//     ServiceAccounts the controller may mint tokens for is controlled by
//     Kubernetes RBAC alone, as in cert-manager's own issuers.
//   - With clientCertificate or clientSecret, the controller authenticates as
//     an Entra application with a certificate or client secret held in a
//     named Secret, in the same namespace a ServiceAccount reference would
//     use. These are fallbacks for clusters that cannot federate. The Secret
//     is read on every token request, as cert-manager's issuers read theirs
//     each time they are used, and the credential is rebuilt only when the
//     Secret has changed, so updating the Secret in place rotates it at once.
//     Which Secrets the controller may read is controlled by Kubernetes RBAC
//     alone.
//
// This is the only package that touches azidentity.
package credential
