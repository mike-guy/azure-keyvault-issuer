# Configuring an issuer

There are two kinds, in the group `azure-keyvault-issuer.mike-guy.github.io/v1alpha1`:

* `AzureKeyVaultIssuer` is namespaced.
* `AzureKeyVaultClusterIssuer` is cluster scoped. It may omit `auth`, and can limit which namespaces use it with `allowedNamespaces`.

Both share the same spec. See [examples.md](examples.md) for complete manifests.

| Field | Meaning |
|---|---|
| `vaultURL` | The vault, such as `https://my-ca.vault.azure.net/`. Azure public cloud only. |
| `certificateName` | The Key Vault certificate that signs. |
| `certificateVersion` | Pins a version. Optional. |
| `chainInSecret` | Return the intermediates held in the certificate's backing secret. Defaults to `false`. |
| `auth` | How to authenticate to Azure. See [Authentication](#authentication). |
| `policy` | What the issuer may sign. See [Policy](#policy). |
| `allowedNamespaces` | ClusterIssuer only. The namespaces that may use it. |

`kubectl explain azurekeyvaultissuer.spec` shows the full schema.

## The Key Vault certificate

The certificate must:

* be enabled and within its validity period, as must every certificate in the chain above it;
* be a CA, and have the certificate-signing key usage if it has a key usage extension;
* have an RSA key, or an ECDSA key on P-256, P-384 or P-521.

With no `certificateVersion`, the current version is resolved on each call and everything is bound to it. The issuer fails if that version is disabled or not yet issued, and never falls back to an older one. Set `certificateVersion` to pin a version.

The identity needs these permissions on the vault:

| Permission | Azure RBAC role that includes it | When |
|---|---|---|
| Get certificates | Key Vault Certificate User | Always |
| Sign with keys | Key Vault Crypto User | Always |
| Get secrets | Key Vault Secrets User | Only with `chainInSecret: true` |

Roles are scoped to the vault, or to the one certificate, key and secret if you want it tighter. A vault that uses access policies instead needs `get` on certificates, `sign` on keys and, for `chainInSecret`, `get` on secrets.

### Keep the key non-exportable

The CA's private key should never leave the vault. A non-exportable key can only be used inside Key Vault, so even a full compromise of the cluster and the controller's identity gives an attacker signing rights for as long as they hold access, but not the key itself.

A certificate created in the vault has a non-exportable key by default. The way to get a CA-signed certificate and its chain there, keeping the key non-exportable, is:

1. Create the certificate in the vault with the `Unknown` issuer, so Key Vault generates the key and a CSR.
2. Sign the CSR with your parent CA.
3. Merge the signed certificate, and its chain, back into the pending certificate.

Importing a certificate together with its key makes the key exportable unless the import policy says otherwise.

An exportable key is permitted (it is your choice!), but the issuer will warn about it in the log and with a `CAKeyExportable` Warning event on the issuer (see `kubectl describe`). The warning:

* is on by default, and turned off with `--warn-on-exportable-ca-key=false`;
* never affects issuance;
* is judged from the certificate's policy, and, when `chainInSecret` is true, from whether the backing secret holds the key;
* may not describe a pinned `certificateVersion`, as the policy belongs to the certificate and not to a version;
* is skipped, with a log line, if the policy cannot be read.

### Chains

Set `chainInSecret: true` when the Key Vault CA sits below one or more intermediate CAs, and you want them returned with each certificate. Without this, clients will likely not be able to build a full chain for verification, as it is often the case that only root certificates are distributed.

The intermediates must be in the certificate's backing secret, which is where merging a chain puts them. The root is not needed, as consumers already trust it, but is accepted if present. The certificates must form a single chain upwards from the Key Vault CA. The issuer orders them itself and does not trust the secret's order. It asks Key Vault for the secret as PEM whatever format the certificate's policy stores it in, so the policy's content type does not matter.

## Authentication

An `auth` block selects exactly one method. Prefer them in this order:

| Method | How it authenticates |
|---|---|
| `workloadIdentity` | Exchanges a token for a named ServiceAccount through [workload identity federation](https://azure.github.io/azure-workload-identity/docs/). |
| `clientCertificate` | Authenticates an Entra application with a certificate and RSA key from a Kubernetes Secret. |
| `clientSecret` | Authenticates an Entra application with a client secret from a Kubernetes Secret. A last resort. |

A ClusterIssuer may omit `auth`, and then uses the controller pod's own ambient workload identity, whose tenant comes from `AZURE_TENANT_ID` in the pod's environment. A namespaced Issuer must always set it, so it can never adopt the controller's identity. Every method needs a `tenantID`, which has no default.

For `workloadIdentity`, the controller requests a token for the ServiceAccount itself, with the audience `api://AzureADTokenExchange`. The Entra application or managed identity needs a federated credential whose issuer is your cluster's OIDC issuer URL and whose subject is `system:serviceaccount:<namespace>:<name>`.

A client certificate is read from the `tls.crt` and `tls.key` keys of one Secret, as in a `kubernetes.io/tls` Secret. The key names are not configurable, and the key must be an unencrypted RSA key. A client secret takes a Secret name and a key. A Secret is read whole, in one request, so a certificate and its key cannot straddle a rotation, and updating one in place takes effect on the next call.

### Where Secrets and ServiceAccounts are found

An AzureKeyVaultIssuer uses its own namespace. An AzureKeyVaultClusterIssuer uses the cluster resource namespace, `--cluster-resource-namespace`, which defaults to the namespace the controller runs in. The spec names only a Secret or ServiceAccount, never a namespace, so whoever can create an issuer cannot make the controller read a Secret in another namespace.

## Policy

The policy limits what an issuer signs. Every field is optional.

| Field | Default | Meaning |
|---|---|---|
| `maxDuration` | `2160h` (90 days) | The longest lifetime. Longer requests are clamped, not refused. At least `1h`. |
| `allowedExtKeyUsages` | `server auth`, `client auth` | The extended key usages a request may ask for, named as in a Certificate's `usages`. Any other is refused, for a CA too. `any` permits every usage. |
| `allowedDomains` | none | Limits the DNS names that are signed. See below. |
| `allowCA` | `false` | Permits requests for CA certificates. Cannot be combined with `allowedDomains`. |

A Certificate that sets no `usages` is given only digital signature and key encipherment by cert-manager, with no extended usage. The issuer gives such a request `server auth`, so that must be in `allowedExtKeyUsages` for it to be signed. A request that names key usages but no extended key usage is refused, as a certificate without one is valid for any usage. So a Certificate that sets `usages` must also name the extended usages it needs.

### allowedDomains

Each entry is one of:

| Entry | Permits |
|---|---|
| `app.example.com` | Exactly that name. |
| `*.example.com` | One label below the domain, such as `app.example.com`. |
| `**.example.com` | Any number of labels below the domain. |

The bare domain is never implied, so list `example.com` as well to allow it. Matching ignores case.

When the list is set, every DNS name and the common name, if there is one, must match. The request must have a DNS name or a common name, and its subject may hold nothing else. Requests for IP addresses, email addresses and URIs are refused, as a list of domains cannot restrict them.

This is a guardrail for clusters that do not use [approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/), which can restrict names per requester and is the better tool where it is installed. On an AzureKeyVaultIssuer it only guards against mistakes, as whoever can edit the Issuer can edit the list.

### Restricting a ClusterIssuer to namespaces

A ClusterIssuer with no `allowedNamespaces` is open to every namespace: any approved CertificateRequest that refers to it is signed. That is a valid configuration, as it is for cert-manager's own ClusterIssuers. To restrict it, list exact namespace names in `allowedNamespaces` (no wildcards), or control which requests are approved with an approver such as approver-policy.

## What is issued

* **Subject and names** come from the CSR. Everything else is set by the issuer.
* **Serial number** is 128 random bits. `notBefore` is five minutes in the past, to allow for clock skew.
* **Lifetime** is the requested duration, or 90 days if there is none. It is clamped to `policy.maxDuration` and to the earliest expiry in the CA chain.
  * Clamping to `maxDuration` is reported as a `DurationClamped` event on the CertificateRequest.
  * Clamping to the CA chain means the CA needs renewing, so it is reported as a `CertificateClamped` Warning event on the issuer, as well as in the log.
* **Usages** come from the request, and extended key usages are limited by `policy.allowedExtKeyUsages`.
* **Name constraints** in the CA, or any certificate above it, are checked before Key Vault is asked to sign. A CA constrained to one domain refuses other names, instead of issuing certificates that clients reject.
* **The signature** is verified against the CA's public key before it is returned, so a vault key that does not match the certificate fails here rather than as a bad certificate.
* **CA certificates** are only issued when `policy.allowCA` is true. They are limited by the path length constraints of the CA and its chain, so if nothing in the chain sets a limit, the new CA can only issue end certificates. The new CA is limited to the policy's extended key usages, and its subject must differ from that of the CA, the chain above it, and the issuer of the topmost certificate the issuer knows. That is the root, even when `chainInSecret` does not load it.
