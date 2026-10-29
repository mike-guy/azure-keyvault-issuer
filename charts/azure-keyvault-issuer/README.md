# azure-keyvault-issuer

![Version: 0.0.0](https://img.shields.io/badge/Version-0.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.0](https://img.shields.io/badge/AppVersion-0.0.0-informational?style=flat-square)

A cert-manager external issuer that signs certificates with a CA key held in Azure Key Vault

**Homepage:** <https://github.com/mike-guy/azure-keyvault-issuer>

The chart installs the CRDs and the controller, which runs under the `restricted`
Pod Security Standard with no access to Secrets or ServiceAccount tokens until
you grant it one by name. It needs Helm 4; Helm 3 is not tested.

## Installing

Once there is a release, install from GitHub's container registry. The chart and
the controller are released separately, so the chart's version is not the
controller's: each chart release says which controller it runs (`appVersion`), by
image digest.

```sh
helm install azure-keyvault-issuer oci://ghcr.io/mike-guy/charts/azure-keyvault-issuer \
  --namespace azure-keyvault-issuer --create-namespace \
  --set workloadIdentity.clientID=<identity client ID> \
  --set workloadIdentity.tenantID=<tenant ID>
```

Add `--set workloadIdentity.useWebhook=true` on AKS, so its workload identity
webhook supplies the token; elsewhere the chart projects the token itself. Until
there is a release, install from a checkout by replacing the `oci://` reference
with the chart's directory. Each release's chart is signed and carries provenance;
see [SECURITY.md](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/SECURITY.md#verifying-a-release).

Then:

1. [Set up the CA and the Azure identity](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/docs/azure-setup.md), and
   [provision the CA](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/docs/ca-provisioning.md).
2. [Tell cert-manager to approve requests](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/docs/approval.md) for these issuers.
3. Create an `AzureKeyVaultIssuer` or `AzureKeyVaultClusterIssuer`: see the
   [README](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/README.md#5-create-an-issuer).

Settings that need more than a value:

- `clusterIssuer.serviceAccounts` and `clusterIssuer.secrets` name what
  ClusterIssuers may use; `tenantAccess` does the same per namespace. See
  [Letting teams use their own identity](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/docs/tenant-rbac.md).
- `metrics.tls.secretName` and `metrics.serviceMonitor.*`: see
  [Metrics](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/docs/metrics.md).
- `networkPolicy.enabled`: see
  [Network policy](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/docs/network-policy.md).
- `controller.signCertificateSigningRequests`: see
  [Kubernetes CertificateSigningRequests](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/docs/certificatesigningrequests.md).

## Requirements

Kubernetes: `>=1.30.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity for the pods. |
| clusterIssuer.secrets | list | `[]` | Names of Secrets, in the cluster resource namespace, that AzureKeyVaultClusterIssuers may reference for the client certificate and client secret fallback methods. The controller is granted `get` on these Secrets only. |
| clusterIssuer.serviceAccounts | list | `[]` | Names of ServiceAccounts, in the cluster resource namespace, that AzureKeyVaultClusterIssuers may reference. The controller is granted `create` on `serviceaccounts/token` for these names only. Never list the controller's own ServiceAccount: the chart refuses it. |
| controller.allowedVaults | list | `[]` | Key Vault URLs that namespaced Issuers may use, for example `https://my-ca.vault.azure.net`. Empty allows any vault. |
| controller.clusterIssuerAmbientCredentials | bool | `true` | Let ClusterIssuers that set no `auth` method use the controller's ambient identity. |
| controller.clusterResourceNamespace | string | `""` | Namespace in which ClusterIssuer ServiceAccount references resolve. Defaults to the release namespace. |
| controller.concurrentWorkers | int | `5` | How many CertificateRequests, and how many issuers, the controller reconciles at once. More than one stops a slow or throttled vault from holding up every other issuer. |
| controller.extraArgs | list | `[]` | Extra command-line arguments for the controller. |
| controller.gracefulShutdownTimeout | string | `"30s"` | How long to wait for in-flight work when stopping. |
| controller.issuerAmbientCredentials | bool | `false` | Let namespaced Issuers that set no `auth` method use the controller's ambient identity. Leave false in multi-tenant clusters, or any team could sign with it. |
| controller.logLevel | string | `"info"` | Log level: debug, info, warn or error. |
| controller.maxRetryDuration | string | `"5m"` | How long a CertificateRequest is retried after transient errors before it fails. |
| controller.signCertificateSigningRequests | bool | `false` | Also sign Kubernetes CertificateSigningRequests (`certificates.k8s.io`) whose signer name is an AzureKeyVaultClusterIssuer, as well as cert-manager CertificateRequests. Adds a cluster-wide watch on CertificateSigningRequests and the RBAC to sign them. Something else must approve them (see the docs). |
| crds.enabled | bool | `true` | Install the issuer CRDs with the chart. |
| crds.keep | bool | `true` | Keep the CRDs, and with them every issuer, when the release is uninstalled. |
| extraEnv | list | `[]` | Extra environment variables for the controller, for example `HTTPS_PROXY` and `NO_PROXY`, or `GOMEMLIMIT` to override the memory limit the controller derives. Behind a proxy, add the Kubernetes API server and the cluster's CIDRs to `NO_PROXY`. |
| fullnameOverride | string | `""` | Overrides the name that prefixes every resource. |
| image.digest | string | `""` | Image digest, for example `sha256:abc...`. When set it replaces the tag. The release workflow writes the digest of the signed image here. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.repository | string | `"ghcr.io/mike-guy/azure-keyvault-issuer"` | Controller image repository. |
| image.tag | string | `""` | Image tag. Defaults to the chart's appVersion. |
| imagePullSecrets | list | `[]` | Secrets for pulling the image, as a list of `name` objects. |
| metrics.enabled | bool | `true` | Serve metrics over HTTPS on port 8443, to callers that pass a TokenReview and a SubjectAccessReview. When false, there is no metrics endpoint. |
| metrics.serviceMonitor.caConfigMap.key | string | `"ca.crt"` | Key of the CA certificate in that ConfigMap. |
| metrics.serviceMonitor.caConfigMap.name | string | `""` | Name of a ConfigMap, in the release namespace, holding the CA that issued `metrics.tls.secretName`'s certificate, for example one written by trust-manager. When set, the ServiceMonitor verifies the endpoint's certificate and its name. Requires `metrics.tls.secretName`. |
| metrics.serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor. It scrapes with the Prometheus ServiceAccount's token. Unless `caConfigMap` is set, it skips certificate verification, because the controller serves a certificate it generates itself. The Prometheus ServiceAccount needs the `metrics-reader` ClusterRole. |
| metrics.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| metrics.serviceMonitor.labels | object | `{}` | Extra labels on the ServiceMonitor, for example to match a Prometheus selector. |
| metrics.tls.secretName | string | `""` | Name of a `kubernetes.io/tls` Secret, in the release namespace, whose certificate the metrics endpoint serves instead of a self-signed one. Typically issued by cert-manager for `<fullname>-metrics.<namespace>.svc`, after the chart is first installed (see the docs). The Secret is mounted as optional and read when the controller starts: until it exists, or if it can't be loaded, the controller serves a self-signed certificate and logs a warning. |
| nameOverride | string | `""` | Overrides the chart's name. |
| networkPolicy.egressPorts | list | `[443,6443]` | TCP ports the controller may reach: HTTPS for Key Vault and Entra, and the Kubernetes API server (443 on most clusters, 6443 on some, including OpenShift). |
| networkPolicy.egressTo | list | `[]` | Destinations for those ports, as NetworkPolicy peers, for example an `ipBlock`. Empty allows any. DNS is always allowed. |
| networkPolicy.enabled | bool | `false` | Create a NetworkPolicy. Off by default, because a wrong policy silently drops traffic. NetworkPolicy cannot filter by hostname, so egress to Key Vault and Entra is open on the listed ports; use Cilium or Calico FQDN policies for tighter limits (see the docs). |
| networkPolicy.ingressFrom | list | `[]` | Peers allowed to reach the probe and metrics ports. Empty allows any. |
| nodeSelector | object | `{}` | Node selector for the pods. |
| podAnnotations | object | `{}` | Annotations on the pods. |
| podDisruptionBudget.enabled | bool | `true` | Create a PodDisruptionBudget when there is more than one replica. |
| podDisruptionBudget.maxUnavailable | int | `1` | Most pods that may be unavailable at once. |
| podLabels | object | `{}` | Extra labels on the pods. |
| podSecurityContext | object | `{"fsGroup":65532,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod-level security context. The defaults meet the restricted Pod Security Standard. |
| priorityClassName | string | `""` | Name of the PriorityClass for the pods. |
| rbac.create | bool | `true` | Create the controller's RBAC. If false, you must grant it what the chart would. |
| replicaCount | int | `1` | Number of controller replicas. Only the elected leader reconciles, so more than one gives faster failover, not more throughput. |
| resources | object | `{"limits":{"memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}}` | Resource requests and limits. The controller sets its Go memory limit to 90% of the memory limit. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` | Container-level security context. The defaults meet the restricted Pod Security Standard. |
| serviceAccount.annotations | object | `{}` | Annotations on the ServiceAccount. |
| serviceAccount.create | bool | `true` | Create the controller's ServiceAccount. |
| serviceAccount.name | string | `""` | ServiceAccount name. Defaults to the release's full name. Required when `create` is false. |
| tenantAccess | list | `[]` | Lets Issuers in other namespaces reference named ServiceAccounts (workload identity) or named Secrets (the client certificate and client secret fallbacks), by granting the controller `create` on `serviceaccounts/token`, or `get` on `secrets`, for those names only. Each entry has a `namespace` and a list of `serviceAccounts`, `secrets` or both. Teams can instead create the Roles themselves (see the docs). |
| terminationGracePeriodSeconds | int | `40` | Seconds to wait for the pod to stop. Keep it above `controller.gracefulShutdownTimeout`. |
| tolerations | list | `[]` | Tolerations for the pods. |
| topologySpreadConstraints | list | `[]` | Topology spread constraints for the pods. The chart's selector labels are added to each. |
| workloadIdentity.clientID | string | `""` | Client ID of the controller's own Entra workload identity, used by issuers that set no `auth` method (the ambient identity). Leave empty if every issuer names a ServiceAccount. |
| workloadIdentity.tenantID | string | `""` | Entra tenant ID of that identity. Required when `clientID` is set. It is also the default tenant for ServiceAccount references that set none. |
| workloadIdentity.tokenExpirationSeconds | int | `3600` | Lifetime in seconds of the projected token, when the chart projects it. The minimum is 600. |
| workloadIdentity.useWebhook | bool | `false` | Let the Azure workload identity webhook inject the token and environment, as on AKS. When false, the chart projects the token and sets the variables itself, which works on any cluster whose OIDC issuer Entra can reach. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
