# Troubleshooting

Start with the issuer, then the request, then the controller's log.

## Where to look

**The issuer.** `akvi` and `akvci` are the short names for `AzureKeyVaultIssuer` and
`AzureKeyVaultClusterIssuer`. The `Ready` condition says whether the controller can
sign, and if not, why:

```sh
kubectl get akvci                       # Ready, Reason, Age
kubectl describe akvci internal-ca      # the full message, under Conditions
```

The message names each step that failed, so you can read it from the outside in:
`getting credential` (who the controller signs in as), `fetching CA` (reading the
certificate from Key Vault) or `making a test signature with CA` (asking Key Vault
to sign). The controller checks the issuer by signing a test value, so a missing
permission shows here, before any certificate is requested.

**The request.** A `CertificateRequest` carries its own conditions, and the events
say what the controller did:

```sh
kubectl describe certificaterequest <name>
```

**The controller.** It logs JSON, one line per event, with the issuer and request it
was handling:

```sh
kubectl logs -n <namespace> -l app.kubernetes.io/name=azure-keyvault-issuer
```

## What is retried

The controller retries what might pass on its own, and stops on what only an edit
can fix.

- **Retried**: throttling (HTTP 429), Key Vault or Entra being unavailable (5xx),
  timeouts, and anything that fails once the issuer has been Ready. This includes
  permission errors that have not propagated yet. An issuer that is not ready is
  checked again; it does not need to be recreated.
- **Not retried until the issuer is edited**: a spec that breaks the rules (`invalid
  issuer spec`). A `CertificateRequest` that asks for something the issuer's policy
  forbids fails for good, and the `Certificate` has to change.

A request that keeps failing with a retried error is failed for good once it is
older than `controller.maxRetryDuration` (five minutes by default), counted from
when it was created. Each attempt at Azure is limited to 30 seconds, so a
connection that never answers is retried rather than blocking the controller.

## The issuer is not ready

### Who the controller signs in as

| Message contains | Meaning and fix |
|---|---|
| `ambient credentials are not permitted for this kind of issuer` | A namespaced `AzureKeyVaultIssuer` set no `spec.auth`, so it would use the controller's own identity, which is only allowed for a `AzureKeyVaultClusterIssuer`. Give the issuer a `serviceAccountRef` ([Azure setup](azure-setup.md)). Only if you accept every team borrowing the controller's access, set `controller.issuerAmbientCredentials: true`. |
| `no ambient workload identity is configured for the controller` | An issuer with no `auth` needs the controller to have an identity. Set `workloadIdentity.clientID` and `workloadIdentity.tenantID` in the chart, or give the issuer a `serviceAccountRef`. |
| `no tenant ID set and no default tenant configured` | Set `auth.workloadIdentity.tenantID` on the issuer, or `workloadIdentity.tenantID` in the chart as the default. |
| `invalid auth` | The `auth` block is malformed: a client or tenant ID that is not a GUID, an empty Secret name or key, or more than one method set. |
| `invalid issuer spec` | The spec breaks a rule the CRD also checks, such as the shape of `vaultURL` (`https://<vault>.vault.azure.net`). Fix the field the message names. |
| `vault is not in the controller's allow-list for namespaced issuers` | The controller was started with `controller.allowedVaults`, and this vault is not in it. Add it, or use a `AzureKeyVaultClusterIssuer`. |
| `serviceaccounts "<name>" is forbidden` … `cannot create resource "serviceaccounts/token"` | The namespace has not allowed the controller to request a token for that ServiceAccount. Create the Role and RoleBinding in [Letting teams use their own identity](tenant-rbac.md), with the ServiceAccount's exact name. |

### The Secret for a client certificate or client secret

The controller reads the Secret only when it needs an Azure token, so these
appear inside the `fetching CA` step of the message. They are all retried: fix
the Secret or its Role, and the issuer becomes ready without being edited. The
message names the Secret and key, never their contents.

| Message contains | Meaning and fix |
|---|---|
| `reading Secret <namespace>/<name>` … `secrets "<name>" is forbidden` | The controller has not been granted `get` on that Secret. Create the Role in [Secrets for the fallback methods](tenant-rbac.md#secrets-for-the-fallback-methods), or list it in the chart's `tenantAccess[].secrets` or `clusterIssuer.secrets`. |
| `reading Secret <namespace>/<name>` … `not found` | No such Secret in that namespace. An Issuer reads its own namespace; a ClusterIssuer reads the cluster resource namespace (the controller's, unless `controller.clusterResourceNamespace` is set). |
| `invalid Secret: no key "<key>"`, `invalid Secret: key "<key>" is empty` | The client secret is not under the key `secretRef.key` names. |
| `invalid Secret: no tls.crt`, `invalid Secret: no tls.key` | A client certificate Secret needs both keys, as `kubectl create secret tls` writes them. |
| `invalid Secret: reading tls.crt and tls.key` | They are not PEM, the key is encrypted (it must not be), or the key does not match the certificate. The rest of the message says which. |
| `invalid Secret: tls.key is not an RSA key` | Microsoft Entra accepts only RSA keys for certificate sign-in. Make a new RSA key and certificate. |
| `invalid Secret: the certificate in tls.crt expired at` / `is not valid until` | The certificate is outside its validity period. Rotate it ([Azure setup](azure-setup.md#rotating)). |

### Microsoft Entra refuses the sign-in

These come back as `authentication failed: HTTP 400 … AADSTS<code>: …`. The code
says why Entra said no.

| Code | Usual cause |
|---|---|
| `AADSTS70021` (no matching federated identity record) | The federated credential's issuer, subject or audience does not match the token's. Check the issuer URL character for character (no trailing slash), the subject (`system:serviceaccount:<namespace>:<name>`, which is the exact ServiceAccount) and the audience (`api://AzureADTokenExchange`). Within a few minutes of creating the credential, it may just not have propagated yet. |
| `AADSTS700016` (application not found) | The client ID is wrong, or is from a different tenant than `tenantID`. |
| `AADSTS700024` (client assertion not within its valid time range) | The token has expired or is not valid yet. Check the clocks on the cluster's nodes. |
| `AADSTS7000215` (invalid client secret) | The client secret is wrong: check the value in the Secret, and that it belongs to this application. |
| `AADSTS7000222` (client secret expired) | Add a new secret to the application and update the Secret ([Azure setup](azure-setup.md#rotating)). |
| `AADSTS700027` (client assertion failed signature validation) | The certificate in the Secret is not registered with this application, or was removed. Add it with `az ad app credential reset --append --cert`. |

For a cluster outside AKS, an error that Entra could not fetch or verify the keys
means the discovery document or key set is not what the API server signs with: see
[Workload identity outside AKS](on-prem-workload-identity.md).

### Key Vault refuses the request

| Message contains | Meaning and fix |
|---|---|
| `Forbidden`, `ForbiddenByRbac`, `not authorized to perform action` | The identity lacks the role on the vault. It needs `Microsoft.KeyVault/vaults/certificates/read` and `keys/sign/action` ([Azure setup](azure-setup.md)). A new role assignment can take several minutes to apply, and the issuer retries. For `chainSource: Secret`, it also needs Key Vault Secrets User on the secret. |
| `ForbiddenByFirewall`, `Client address is not authorized` | The vault's firewall does not allow the controller's address. Allow it, or use a private endpoint the cluster can reach. |
| `getting certificate "<name>"` with `404` | No such certificate, or in another vault. Check `vaultURL`, `certificateName` and `certificateVersion`. |
| `HTTP 429` | Key Vault is throttling. The controller waits as asked and retries. Limits apply per vault, and a request costs a certificate read and a signature, so constant throttling means many certificates are being issued from one vault at once. |

If the issuer reaches Key Vault from a cluster with a NetworkPolicy, check that it
allows egress to `login.microsoftonline.com` and `<vault>.vault.azure.net`
([Network policy](network-policy.md)).

### The CA certificate is not usable

| Message contains | Meaning and fix |
|---|---|
| `CA certificate version has no issued certificate` | The certificate is still pending: its signed certificate has not been merged. Finish the [provisioning](ca-provisioning.md). During a rotation, pin `spec.certificateVersion` to the old version until the new one is merged. |
| `CA certificate version is disabled` | That version was disabled. Enable it, or pin a version that is enabled. |
| `invalid CA certificate` … `is not a CA (basic constraints)` | The certificate is `CA:FALSE`. Key Vault cannot make a CA by itself, so it has to be signed by a CA as a CA: see [CA provisioning](ca-provisioning.md). |
| `invalid CA certificate` … `lacks the certificate-signing key usage` | The signed certificate has no `keyCertSign`. Have it re-signed with that usage. |
| `invalid CA certificate` … `is not valid until` / `expired at` | The CA is outside its validity period. Rotate it. |
| `unsupported CA key` | Only RSA 2048, 3072 and 4096, and EC P-256, P-384 and P-521 are supported. |
| `unsafe certificate secret` | `chainSource: Secret` refuses a certificate whose key is exportable, whose secret is not PEM, or whose secret contains a private key. Make the certificate non-exportable with a PEM content type. |
| `invalid CA chain` | The chain in the secret is malformed, does not start with the CA certificate, or does not link up. Merge the full chain, leaf first ([CA provisioning](ca-provisioning.md)). |
| `making a test signature with CA` fails, after the CA loaded | Key Vault would not sign, or signed with a key that does not match the certificate. Look at the rest of the message: a `403` means the identity lacks `keys/sign/action` (see above). |
| A `CAExpiringSoon` warning event on the issuer | The issuer still works, but its CA chain expires within 30 days, and every certificate it issues is being shortened to end with it. Rotate the CA ([CA provisioning](ca-provisioning.md#rotation)). To alert on this, see [Metrics](metrics.md#alerting-on-ca-expiry). |

## A request is not signed

| What you see | Meaning and fix |
|---|---|
| The `CertificateRequest` stays pending, with no `Approved` condition | cert-manager has not approved it. cert-manager must be told to approve requests for our issuers: [Approving requests](approval.md). The controller never signs an unapproved request. |
| `Denied` | An approver denied it. The controller fails it. Look at the approver (approver-policy, say) for why. |
| `InvalidRequest` with `CANotAllowed`, `CA certificates (isCA: true) are not allowed` | The `Certificate` asks for a CA, and the issuer's `spec.policy.allowCA` is false (the default). Set it only on an issuer that should make CAs. |
| `InvalidRequest` with `PathLenExceeded`, `this CA's path length is 0, so it cannot issue CA certificates` | The Key Vault CA has a path length of 0 (as [CA provisioning](ca-provisioning.md) recommends), so any CA it issued would be rejected by every client. Issue CAs from a CA whose path length allows them, or not at all. |
| `InvalidRequest` with `PathLenExceeded`, `requested path length <n>, but this CA allows at most <m>` | The CSR asks for a deeper hierarchy than the Key Vault CA's path length allows. Ask for `<m>` or less. A `Certificate` asks for no limit, which is given the most the CA allows, so this only comes from a hand-written CSR. |
| An event `DurationClamped` | Not a failure: the certificate was issued with a shorter life than asked, because of `spec.policy.maxDuration` (90 days by default) or the expiry of the CA chain (the Key Vault CA, or a certificate above it that expires first). cert-manager renews it from its actual expiry. |
| The issued certificate has no root | By design. The root is distributed with [trust-manager](trust-manager.md). |

## The controller does not start

- It exits at start-up if cert-manager's CRDs are missing. Install cert-manager
  first.
- `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE` must be all
  set or all unset. The chart sets them; a partial set stops the controller at
  start-up with `ambient workload identity: … must all be set, or none`.
- With `useWebhook: true` the cluster must run AKS's workload identity webhook, which
  injects those variables. Without it, leave `useWebhook` false.

## Delays that are normal

- A new federated credential can take a few minutes to work (`AADSTS70021` until
  it does), and so can a new application certificate or client secret
  (`AADSTS700027` or `AADSTS7000215`).
- A new Azure role assignment can take several minutes to apply (a `403` until it
  does).

An issuer that is not ready is checked again on its own, so waiting a few minutes
usually clears these. If it does not clear, the message names what is wrong.
