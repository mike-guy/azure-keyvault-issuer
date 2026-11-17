# azure-keyvault-issuer

An [external issuer](https://cert-manager.io/docs/contributing/external-issuers) for [cert-manager](https://cert-manager.io) that signs certificates with a CA held in Azure Key Vault.

The CA's private key should never leave the vault. The controller builds each certificate itself and asks Key Vault to sign the digest. It is built on cert-manager's [issuer-lib](https://github.com/cert-manager/issuer-lib), and its API is `v1alpha1`.

## Contents

* [How it works](#how-it-works)
* [Quick start](#quick-start)
* [Keep the CA key non-exportable](#keep-the-ca-key-non-exportable)
* [Authentication](#authentication)
* [Policy](#policy)
* [Documentation](#documentation)
* [Verifying a release](#verifying-a-release)
* [Contributing, security and licence](#contributing-security-and-licence)

## How it works

```
CertificateRequest -> issuer -> Key Vault -> signed certificate
```

There are two kinds, `AzureKeyVaultIssuer` (namespaced) and `AzureKeyVaultClusterIssuer` (cluster scoped). Each names a Key Vault certificate, says how to authenticate to Azure, and sets a policy. issuer-lib runs the reconcilers, and this project supplies two callbacks:

* **Check** runs when an issuer is reconciled. It loads the CA certificate and its chain from Key Vault, and checks that the certificate can act as a CA. The result is the issuer's `Ready` condition.
* **Sign** runs for each approved CertificateRequest that refers to a `Ready` issuer. It builds the certificate, applies the policy, asks Key Vault to sign then returns the certificate with its chain (excluding the root certificate).

Only the cert-manager CertificateRequest API is supported. Kubernetes CertificateSigningRequests are not supported at present.

## Quick start

You need a cluster with [cert-manager](https://cert-manager.io/docs/installation/), and an Azure Key Vault holding a CA certificate. The certificate must be a CA with an RSA or ECDSA (P-256, P-384 or P-521) key - see [below](#keep-the-ca-key-non-exportable) for details.

**1. Install the controller**, pinning to a specific version. The `values.yaml` below gives an example with a [workload identity](https://azure.github.io/azure-workload-identity/docs/):

```yaml
serviceAccount:
  annotations:
    azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000
podLabels:
  azure.workload.identity/use: "true"
```

```console
helm install azure-keyvault-issuer oci://ghcr.io/mike-guy/charts/azure-keyvault-issuer \
  --version <chart version> --namespace azure-keyvault-issuer --create-namespace \
  --values values.yaml
```

Give that identity the `Key Vault Certificate User` and `Key Vault Crypto User` roles on the vault. The chart's [README](charts/azure-keyvault-issuer/README.md) has the other values.

**2. Create an issuer** that uses it:

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultClusterIssuer
metadata:
  name: my-ca
spec:
  vaultURL: https://my-ca.vault.azure.net/
  certificateName: my-ca
```

```console
kubectl get azurekeyvaultclusterissuer my-ca    # READY should be True
```

The short names are `akvci` (or `akvcis`) for `AzureKeyVaultClusterIssuer` and `akvi` (or `akvis`) for `AzureKeyVaultIssuer`, so `kubectl get akvci` works too.

**3. Request a certificate**:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app
spec:
  secretName: app-tls
  dnsNames:
    - app.example.com
  issuerRef:
    group: azure-keyvault-issuer.mike-guy.github.io
    kind: AzureKeyVaultClusterIssuer
    name: my-ca
```

```console
kubectl get certificate app    # READY should be True, and the Secret app-tls exists
```

A root certificate is not set in the returned chain, only any intermediates. Distribute it with a tool such as [trust-manager](https://cert-manager.io/docs/trust/trust-manager/). A request is only signed once it is approved, and the chart lets cert-manager's built-in approver approve for these kinds by default (`approverRole`).

More example manifests, for each way of authenticating, chains, and restricting names and namespaces, are in [docs/examples.md](docs/examples.md).

## Keep the CA key non-exportable

**I would recommend the CA key is always non-exportable**, so that it can only ever be used inside the vault. A certificate created in the vault is non-exportable by default. This controller may need to retrieve intermediate CAs from the backing secret. If the key is marked as exportable, it will also be present in this secret, something the controller does not need or want.

An exportable key is allowed, but **the issuer warns about it**: a log line, and a `CAKeyExportable` Warning event on the issuer that you can see with `kubectl describe`. This is on by default, and `--warn-on-exportable-ca-key=false` turns it off. The warning is judged from the certificate's policy, and from the backing secret with `chainInSecret`, so no warning is not proof that the key is safe. Details are in [docs/configuration.md](docs/configuration.md#keep-the-key-non-exportable).

## Authentication

An `auth` block selects exactly one method. Prefer them in this order:

| Method | How it authenticates |
|---|---|
| `workloadIdentity` | Exchanges a token for a named ServiceAccount through [workload identity federation](https://azure.github.io/azure-workload-identity/docs/). |
| `clientCertificate` | Authenticates an Entra application with a certificate and RSA key from a Kubernetes Secret. |
| `clientSecret` | Authenticates an Entra application with a client secret from a Kubernetes Secret. A last resort. |

A ClusterIssuer may omit `auth`, and then uses the controller's own ambient workload identity. A namespaced Issuer must always set it, so it can never adopt the controller's identity.

## Policy

Each issuer can limit what it signs:

| Field | Default | Meaning |
|---|---|---|
| `maxDuration` | `2160h` (90 days) | The longest lifetime. Longer requests are clamped, not refused. |
| `allowedExtKeyUsages` | `server auth`, `client auth` | The extended key usages a request may ask for. |
| `allowedDomains` | none | The DNS names that may be signed, as names, `*.example.com` or `**.example.com`. |
| `allowCA` | `false` | Permits requests for CA certificates. |

A ClusterIssuer can also list `allowedNamespaces`. With none listed it is open to every namespace, as cert-manager's own ClusterIssuers are. There is no revocation, so keep `maxDuration` short. See [docs/configuration.md](docs/configuration.md) for how each is applied.

## Documentation

| | |
|---|---|
| [Examples](docs/examples.md) | Complete issuer and Certificate manifests. |
| [Configuring an issuer](docs/configuration.md) | The Key Vault certificate, authentication, policy and what is issued. |
| [Running the controller](docs/controller.md) | Flags, events and troubleshooting. |
| [Metrics](docs/metrics.md) | Enabling and scraping them, with your own certificate. |
| [Helm chart](charts/azure-keyvault-issuer/README.md) | Values, RBAC, approval and network policy. |
| [Contributing](CONTRIBUTING.md) | Development, releases and how the code is laid out. |

## Verifying a release

The controller image and the chart are each built by a workflow in this repository, which attests where they came from and signs them with [cosign](https://docs.sigstore.dev/cosign/overview/). Check them before you deploy, and deploy by digest for anything that must not change. The commands are in [SECURITY.md](SECURITY.md#verifying-a-release).

## Contributing, security and licence

See [CONTRIBUTING.md](CONTRIBUTING.md) to work on the project, and [SECURITY.md](SECURITY.md) to report a vulnerability.

This project is licensed under the [Apache License 2.0](LICENSE).

It began from the [cert-manager sample external issuer](https://github.com/cert-manager/sample-external-issuer), which is also Apache 2.0 and copyright The cert-manager Authors. Most of that code has since been removed or rewritten, but a few files in `api/v1alpha1` still derive from it. They keep the original copyright and licence header, with a notice that they have been modified, as the licence requires:

* `groupversion_info.go`
* `azurekeyvaultissuer_types.go`
* `azurekeyvaultclusterissuer_types.go`
* `zz_generated.deepcopy.go`, generated from the files above with the header in `boilerplate.go.txt`

Every other file was written from scratch and has no such header.
