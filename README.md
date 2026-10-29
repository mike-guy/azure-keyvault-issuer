# azure-keyvault-issuer

A [cert-manager](https://cert-manager.io/) external issuer that signs
certificates with a CA key held in Azure Key Vault. The private key never leaves
Key Vault: certificates are signed through Key Vault's `sign` operation.

> **Status:** v1alpha1, not yet released. The API may change between releases, and
> the release notes say when it does. Until the first release, install from a
> checkout (see [Install](#3-install-the-controller)).

- **Two issuer kinds:** a namespaced `AzureKeyVaultIssuer` and a cluster-scoped
  `AzureKeyVaultClusterIssuer`.
- **Keys:** RSA 2048, 3072 and 4096, and EC P-256, P-384 and P-521, in software or
  in an HSM (a Premium vault).
- **Secure by default:** workload identity with no stored secret, a controller
  that runs under the `restricted` Pod Security Standard and can use only the
  ServiceAccounts and Secrets you name, and certificate lifetimes capped by policy.
- **Any cluster:** AKS, other clouds and on-premises, with a client certificate or
  secret as fallbacks where workload identity cannot be used.
- **Signed releases:** the image and the chart carry a keyless cosign signature and
  build provenance ([SECURITY.md](SECURITY.md#verifying-a-release)).

Certificates from this issuer are for **private trust**: internal services, mTLS
and service meshes. Publicly trusted CAs do not issue subordinate CAs to ordinary
organisations, so for certificates browsers trust, use ACME. Only the Azure public
cloud is supported.

This project is an independent implementation. The only previous cert-manager
issuer for Key Vault, [gonicus/azure-keyvault-issuer](https://github.com/gonicus/azure-keyvault-issuer),
is prior art; no code, structure or naming is taken from it.

## Quick start

You need a cluster running Kubernetes 1.30 or later with
[cert-manager](https://cert-manager.io/docs/installation/) installed, Helm 4
(Helm 3 is not tested), and the Azure CLI. This path uses the controller's own
workload identity and an `AzureKeyVaultClusterIssuer`, the simplest setup. Teams
that want their own identity per namespace should read
[Letting teams use their own identity](docs/tenant-rbac.md) afterwards.

### 1. Make a CA in Key Vault

The issuer signs with a Key Vault *certificate* that is a CA, with a key that
cannot be exported. Key Vault cannot create one by itself: it makes the key and a
signing request, and your PKI signs it. [Provisioning the CA](docs/ca-provisioning.md)
covers the production flow, and ends with a one-off
[evaluation CA](docs/ca-provisioning.md#trying-it-out-an-evaluation-ca) for a first
try.

### 2. Create an Azure identity for the controller

The controller signs in as an Entra workload identity: a user-assigned managed
identity with a role that can only read the certificate and sign, and a federated
credential that trusts the controller's ServiceAccount (named after the release, so
`azure-keyvault-issuer` in the namespace used below). [Azure setup](docs/azure-setup.md)
has the commands. On a cluster that is not AKS, Entra must be able to reach the
cluster's OIDC issuer: see [workload identity outside AKS](docs/on-prem-workload-identity.md).

### 3. Install the controller

```sh
helm install azure-keyvault-issuer oci://ghcr.io/mike-guy/charts/azure-keyvault-issuer \
  --namespace azure-keyvault-issuer --create-namespace \
  --set workloadIdentity.clientID=<identity client ID> \
  --set workloadIdentity.tenantID=<tenant ID>
```

On AKS, add `--set workloadIdentity.useWebhook=true`, so AKS's workload identity
webhook supplies the token; elsewhere the chart projects it itself. The chart
installs the CRDs. From a checkout, replace the `oci://` reference with
`charts/azure-keyvault-issuer`. The controller and the chart are released
separately, so their versions differ; each chart release says which controller it
runs, by digest. Its values are in the
[chart README](charts/azure-keyvault-issuer/README.md).

There is no `kubectl apply` manifest, because the controller needs settings before it
can do anything. For plain YAML, for a GitOps tool that does not run Helm, render the
chart: `helm template <chart> -f values.yaml`.

### 4. Tell cert-manager to approve requests

cert-manager only hands a request to an issuer once it is approved, and by default it
approves only its own issuers. Add ours to the cert-manager chart's
`approveSignerNames`, keeping its two defaults:

```yaml
approveSignerNames:
  - issuers.cert-manager.io/*
  - clusterissuers.cert-manager.io/*
  - azurekeyvaultissuers.azure-keyvault-issuer.mike-guy.github.io/*
  - azurekeyvaultclusterissuers.azure-keyvault-issuer.mike-guy.github.io/*
```

Without this, certificates sit unapproved and never issue. For other approval
options, such as approver-policy, see [Approving requests](docs/approval.md).

### 5. Create an issuer

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultClusterIssuer
metadata:
  name: internal-ca
spec:
  vaultURL: https://my-ca-vault.vault.azure.net/
  certificateName: issuing-ca
```

```sh
kubectl get akvci internal-ca    # READY should be True
```

The issuer test-signs against Key Vault when it is created, so a missing permission or
a mismatched key shows here, before any certificate is requested.
[Troubleshooting](docs/troubleshooting.md) explains what each reason means.

### 6. Request a certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-service
spec:
  secretName: my-service-tls
  dnsNames: [my-service.default.svc]
  issuerRef:
    group: azure-keyvault-issuer.mike-guy.github.io
    kind: AzureKeyVaultClusterIssuer
    name: internal-ca
```

Set the `group`: without it, cert-manager assumes its own (`cert-manager.io`). The
Secret holds the certificate and the Key Vault CA (plus any intermediates with
`chainSource: Secret`), **not the root**, so clients must be given the root, for
example with [trust-manager](docs/trust-manager.md).
Certificates last 90 days unless the Certificate asks for less, and never outlive
the CA.

## How issuers sign in to Azure

Each issuer's `spec.auth` picks one method. In order of preference:

| Method | What it uses | Where it works |
|---|---|---|
| `workloadIdentity` | A short-lived token for a named ServiceAccount, exchanged with Microsoft Entra. No stored secret. | Any cluster whose OIDC issuer Entra can reach: AKS, or another cluster that publishes it. |
| No `auth` (ambient) | The controller's own workload identity. Allowed for ClusterIssuers only, by default. | As above. |
| `clientCertificate` | An Entra application's certificate and RSA key, from a named Secret. | Anywhere, including clusters that cannot federate. |
| `clientSecret` | An Entra application's client secret, from a named Secret. A last resort. | Anywhere. |

The controller can use a ServiceAccount or Secret only once you grant it that one
name. Updating a Secret in place rotates the credential straight away. See
[Azure setup](docs/azure-setup.md) and
[Letting teams use their own identity](docs/tenant-rbac.md).

## Documentation

| Guide | What it covers |
|---|---|
| [Provisioning the CA](docs/ca-provisioning.md) | Making the CA certificate in Key Vault, the chain, and rotation |
| [Azure setup](docs/azure-setup.md) | The vault, a least-privilege role, and the identity the controller signs in as, with the certificate and secret fallbacks |
| [Workload identity outside AKS](docs/on-prem-workload-identity.md) | What a cluster in another cloud or on-premises must publish for Entra to trust it |
| [Letting teams use their own identity](docs/tenant-rbac.md) | The RBAC that lets the controller use one named ServiceAccount or Secret at a time |
| [Approving requests](docs/approval.md) | cert-manager approval for these issuers |
| [Distributing trust](docs/trust-manager.md) | Getting the root to clients with trust-manager |
| [Metrics](docs/metrics.md) | Scraping them, alerting on CA expiry, and a certificate Prometheus can verify |
| [Network policy](docs/network-policy.md) | What the optional policy allows, and why it cannot filter by hostname |
| [Kubernetes CertificateSigningRequests](docs/certificatesigningrequests.md) | Signing them too (off by default) |
| [Troubleshooting](docs/troubleshooting.md) | Reading issuer and request conditions |

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) to build and test, and
[ARCHITECTURE.md](ARCHITECTURE.md) for the design. To report a vulnerability, see
[SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE).
