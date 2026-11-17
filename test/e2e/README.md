# e2e suite

Runs against a real cluster with cert-manager and the chart installed, and a Key Vault CA in Azure.

```
mise run e2e:kind:run # Azure resources and CA, kind cluster, then the suite
mise run e2e:aks:run  # Azure resources, CA and AKS cluster, then the suite
mise run test:e2e -- -ginkgo.label-filter='!azure'   # the specs that need no Azure
```

## What is covered

These specs cover what only a cluster, cert-manager, Entra and Key Vault can show: the seams between them and the controller. The unit tests under `internal/` cover what the controller decides (every policy pattern, key usage, key type and error class), and the helm-unittest suites cover how the chart renders, so the specs here do not repeat either.

| File | What it checks |
|---|---|
| `authentication_test.go` | Each way of signing in (client secret, client certificate, workload identity for a named ServiceAccount, the controller's ambient identity) signs in, and has a certificate signed. A credential replaced in place stops signing with Entra's refusal, and signs again once it is put back. |
| `issuance_test.go` | cert-manager asking again for a Certificate that was already signed. |
| `events_test.go` | `CAKeyExportable` on a cluster-scoped issuer, and `DurationClamped` on the CertificateRequest, so events reach the API server about the right object. |
| `policy_test.go` | What Key Vault returns: a CA below two intermediates with `chainInSecret`, RSA and P-384 CA keys, a missing certificate, and an identity that may not read secrets. And where a refusal ends up: `allowedDomains` and `allowedNamespaces` fail the request, saying why. |
| `controller_test.go` | The chart's install on a cluster: the Pod Security `restricted` level, leader election and failover with two replicas, `rbac.secretNamespaces`, cert-manager's approval, and the secure metrics endpoint with a certificate from the issuer and its token review. |
| `validation_test.go` | What the CRDs, as the chart installs them, refuse and default. No Azure. |

The authentication specs are labelled, so that one method can be run alone with `-ginkgo.label-filter`:

| Method | Spec uses | Label |
|---|---|---|
| client secret | AzureKeyVaultIssuer and AzureKeyVaultClusterIssuer, which reads it from the controller's namespace | `client-secret` |
| client certificate | AzureKeyVaultIssuer | `client-certificate` |
| workload identity, named ServiceAccount | AzureKeyVaultIssuer | `workload-identity` |
| ambient workload identity | AzureKeyVaultClusterIssuer (an AzureKeyVaultIssuer never uses it, the CRD needs `auth`) | `ambient` |

## Is any of it AKS only?

No. Nothing in the specs knows the platform.

* **Client secret and client certificate** need only Azure.
* **Workload identity for a named ServiceAccount** needs only that Entra can fetch the cluster's OIDC discovery document and keys, since the controller requests the token itself. kind gets this from `e2e:kind:cluster:create` and `e2e:kind:workload-identity:install`, which make the cluster sign as an issuer URL in a storage account's static website and publish its keys there.
* **Ambient identity** also needs the Azure workload identity webhook to inject the token into the controller's pod. AKS has it built in, and `e2e:kind:workload-identity:install` installs it on kind. The spec skips when the controller's pods lack the `azure.workload.identity/use` label.

AKS differs only in plumbing, which the `e2e:aks:*` tasks do, as the `e2e:kind:*` tasks do for kind. What is shared has no platform in its name: `e2e:azure:*`, `e2e:infra:*`, `e2e:cert-manager:install` and `test:e2e`.

`e2e:aks:run` makes the Azure resources and the AKS cluster, then installs cert-manager, the image and the chart, and runs the suite. It sets `E2E_ENABLE_AKS=true` and points `E2E_ALLOW_CONTEXT` at the `akv-issuer-e2e-aks` context. To repeat a step on its own, set both yourself, for example `E2E_ENABLE_AKS=true E2E_ALLOW_CONTEXT=akv-issuer-e2e-aks mise run e2e:aks:chart:install`. The image is built for amd64 and pushed to the e2e registry. `e2e:aks:clean` destroys the Azure resources, which include the cluster and registry. `e2e:kind:clean` deletes the kind cluster as well as destroying them.

## Constraints

* Workload identity specs for an AzureKeyVaultIssuer run in a namespace named `e2e-wi`, as Entra trusts one exact subject, so they cannot run at the same time as each other.
* The kind cluster's issuer can only be set when the cluster is made. One made before `e2e:azure:provision` has to be deleted with `e2e:kind:cluster:delete`, and the scripts say so.
