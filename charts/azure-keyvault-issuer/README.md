# azure-keyvault-issuer

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

A cert-manager external issuer that signs certificates with a CA held in Azure Key Vault

The controller signs cert-manager CertificateRequests with a CA held in Azure Key Vault. This page covers the chart. For the issuer API, see the [project README](https://github.com/mike-guy/azure-keyvault-issuer#readme), the [configuration guide](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/docs/configuration.md) and the [examples](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/docs/examples.md).

## Installing

[cert-manager](https://cert-manager.io/docs/installation/) must already be installed.

```console
helm install azure-keyvault-issuer oci://ghcr.io/mike-guy/charts/azure-keyvault-issuer \
  --version 0.1.0 \
  --namespace azure-keyvault-issuer --create-namespace
```

The chart and the controller are versioned separately. The chart's `appVersion`, currently `0.1.0`, is the controller image it deploys unless `image.tag` or `image.digest` says otherwise. Both are signed. See [SECURITY.md](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/SECURITY.md#verifying-a-release) for how to verify them.

A typical `values.yaml` uses workload identity, limits where Secrets are read, and turns on metrics:

```yaml
serviceAccount:
  annotations:
    azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000
podLabels:
  azure.workload.identity/use: "true"
rbac:
  secretNamespaces:
    - team-a
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
```

The controller runs under the `restricted` Pod Security Standard, so the namespace can enforce it:

```console
kubectl label namespace azure-keyvault-issuer pod-security.kubernetes.io/enforce=restricted
```

## Authenticating to Azure

Prefer workload identity. Federate an Entra application or user-assigned managed identity with the controller's ServiceAccount, then:

```yaml
serviceAccount:
  annotations:
    azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000
podLabels:
  azure.workload.identity/use: "true"
```

The [Azure Workload Identity webhook](https://azure.github.io/azure-workload-identity/docs/) then injects the environment variables the controller's ambient credential reads, including `AZURE_TENANT_ID`. An AzureKeyVaultClusterIssuer with no `auth` block uses this identity. Issuers that name their own ServiceAccount, client certificate or client secret do not need it.

## Access to Secrets and ServiceAccounts

An AzureKeyVaultIssuer reads its credential Secret, or mints a token for its ServiceAccount, in its own namespace. So by default the controller may `get` Secrets and `create` ServiceAccount tokens in every namespace, which is how cert-manager and other external issuers work. It can only `get` a Secret by name, and never list or watch them. A compromised controller could still read any Secret whose name it can guess.

To limit that, list the namespaces:

```yaml
rbac:
  secretNamespaces:
    - team-a
    - team-b
```

The access then goes to those namespaces and the cluster resource namespace, which is the release namespace unless `clusterResourceNamespace` says otherwise. The cost is that each new namespace that holds an AzureKeyVaultIssuer's credentials or ServiceAccount needs a `helm upgrade` to add it. Until then that issuer is not `Ready`, with a Forbidden error in its condition.

If you only use AzureKeyVaultClusterIssuers, their credentials are in the cluster resource namespace, so list that namespace to give the controller access there and nowhere else. An empty list means every namespace, so it cannot be used to mean none.

## Approving requests

cert-manager only signs a CertificateRequest once it is approved, and its built-in approver may only approve requests for the signers it has been told of. The chart grants it that for both issuer kinds, with a ClusterRole that allows `approve` on `azurekeyvaultissuers.azure-keyvault-issuer.mike-guy.github.io/*` and `azurekeyvaultclusterissuers.azure-keyvault-issuer.mike-guy.github.io/*`, and a binding to cert-manager's ServiceAccount. Without it, requests stay unapproved and are never signed, and the controller logs nothing, as it never sees them.

If cert-manager runs under another ServiceAccount or in another namespace, set `approverRole.serviceAccountName` and `approverRole.namespace`. If [approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/) or another approver does the approving, set `approverRole.enabled=false` and grant that approver the same `approve` rule, as it needs it too. It is not created when `rbac.create` is false.

## CustomResourceDefinitions

The chart installs the CRDs, so `helm upgrade` updates them. They are annotated `helm.sh/resource-policy: keep`, so `helm uninstall` leaves them, and every issuer, in place. Delete them by hand if you want them gone. Set `crds.install=false` if you manage them yourself.

## Metrics

Metrics are off by default. With `metrics.enabled=true` they are served over HTTPS and need a bearer token, so whatever scrapes them needs this role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: azure-keyvault-issuer-metrics-reader
rules:
  - nonResourceURLs: ["/metrics"]
    verbs: ["get"]
```

`metrics.serviceMonitor.enabled=true` creates a Prometheus Operator ServiceMonitor. See the project's [metrics documentation](https://github.com/mike-guy/azure-keyvault-issuer/blob/main/docs/metrics.md) for using your own certificate.

## Network policy

`networkPolicy.enabled=true` allows ingress only to the probe port, and to the metrics port from `networkPolicy.metricsFrom`. Egress is limited to DNS and port 443, which covers the API server, Microsoft Entra and Key Vault, as a NetworkPolicy cannot name hosts. Add `networkPolicy.extraEgress` if your API server is on another port.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity of the pods. |
| approverRole.enabled | bool | `true` | Let cert-manager's built-in approver approve CertificateRequests for the issuer kinds. It cannot without this, and no request is signed. Turn it off where approver-policy, or another approver, does the approving. Needs `rbac.create`. |
| approverRole.namespace | string | `"cert-manager"` | The namespace that ServiceAccount is in. |
| approverRole.serviceAccountName | string | `"cert-manager"` | The ServiceAccount of cert-manager's approver. |
| azure.maxRetries | string | `nil` | How many times a failed Azure request is retried. 0 disables retries. Unset uses the controller's default. |
| azure.tryTimeout | string | `nil` | How long one Azure request attempt may take, such as `30s`. Unset uses the controller's default. |
| caExpiryWarningThreshold | string | `nil` | How close to expiry the CA chain must be for the controller to record a `CAExpiring` warning event on the issuer, such as `720h`. Go durations have no day unit, so 90 days is `2160h`. Unset uses the controller's default, 90 days. |
| clusterResourceNamespace | string | `""` | Namespace in which a ClusterIssuer's Secrets and ServiceAccount are found. Defaults to the release namespace. |
| crds.install | bool | `true` | Install the CustomResourceDefinitions with the chart. |
| crds.keep | bool | `true` | Keep the CustomResourceDefinitions when the release is uninstalled. Deleting them deletes every issuer. |
| extraArgs | list | `[]` | Extra command line arguments for the controller. |
| extraEnv | list | `[]` | Extra environment variables for the controller, such as `AZURE_TENANT_ID`. |
| fullnameOverride | string | `""` | Overrides the full name of resources. |
| image.digest | string | `""` | Image digest, such as `sha256:...`. When set, it is used instead of the tag. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.repository | string | `"ghcr.io/mike-guy/azure-keyvault-issuer"` | Image repository. |
| image.tag | string | `""` | Image tag. Defaults to the chart's appVersion. |
| imagePullSecrets | list | `[]` | Secrets used to pull the image. |
| logging.encoder | string | `nil` | Log format: `json` or `console`. Unset uses the controller's default. |
| logging.level | string | `nil` | Log level: `debug`, `info`, `error`, or an integer above 0 for more verbose debug logs. Unset uses the controller's default. |
| maxConcurrentReconciles | string | `nil` | How many objects each controller reconciles at once. Unset uses the controller's default. |
| metrics.certSecretName | string | `""` | Name of a `kubernetes.io/tls` Secret to serve instead of a self-signed certificate. Needs `secure`. |
| metrics.enabled | bool | `false` | Serve Prometheus metrics. Off by default, as the controller's metrics endpoint is. |
| metrics.port | int | `8443` | Port of the metrics endpoint. |
| metrics.secure | bool | `true` | Serve metrics over HTTPS and require a bearer token, checked with a TokenReview and SubjectAccessReview. Setting this to false serves plain HTTP that anyone who can reach the port can read. |
| metrics.serviceMonitor.enabled | bool | `false` | Create a Prometheus Operator ServiceMonitor. Needs `metrics.enabled`. |
| metrics.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| metrics.serviceMonitor.labels | object | `{}` | Extra labels on the ServiceMonitor, such as the ones a Prometheus selects on. |
| metrics.serviceMonitor.tlsConfig | object | `{}` | TLS settings of the scrape, used when `metrics.certSecretName` is set, such as a `ca` and `serverName`. With the self-signed certificate, verification is skipped, as it cannot succeed. |
| nameOverride | string | `""` | Overrides the chart name in resource names. |
| networkPolicy.enabled | bool | `false` | Create a NetworkPolicy that limits ingress to the probe and metrics ports, and egress to DNS and HTTPS. |
| networkPolicy.extraEgress | list | `[]` | Extra egress rules, such as for a cluster whose API server is not on port 443. |
| networkPolicy.metricsFrom | list | `[]` | Peers allowed to reach the metrics port, as NetworkPolicy `from` entries. Empty allows none. |
| nodeSelector | object | `{}` | Node selector of the pods. |
| podAnnotations | object | `{}` | Annotations on the pods. |
| podDisruptionBudget.enabled | bool | `true` | Create a PodDisruptionBudget. Only rendered when `replicaCount` is above 1. |
| podLabels | object | `{}` | Extra labels on the pods. For workload identity set `azure.workload.identity/use: "true"`. |
| podSecurityContext.fsGroup | int | `65532` |  |
| podSecurityContext.runAsGroup | int | `65532` |  |
| podSecurityContext.runAsNonRoot | bool | `true` |  |
| podSecurityContext.runAsUser | int | `65532` |  |
| podSecurityContext.seccompProfile.type | string | `"RuntimeDefault"` |  |
| priorityClassName | string | `""` | Priority class of the pods. |
| rbac.create | bool | `true` | Create the ClusterRole, Roles and bindings. |
| rbac.secretNamespaces | list | `[]` | Limit where the controller may read Secrets and mint ServiceAccount tokens to these namespaces, plus the cluster resource namespace. Empty, the default, grants it in every namespace, so an AzureKeyVaultIssuer works wherever it is created. Limiting it is safer, as a compromised controller can then only read Secrets in those namespaces, but each new namespace that holds an AzureKeyVaultIssuer's credentials or ServiceAccount then needs a `helm upgrade`. Until then its issuer is not Ready, with a Forbidden error. |
| reconcileTimeout | string | `nil` | The longest a single issuer check or signing may take, such as `2m`. Unset uses the controller's default. |
| replicaCount | int | `1` | Number of controller replicas. Leader election is always on, so only one replica reconciles and the rest are for availability. |
| resources | object | `{"limits":{"memory":"128Mi"},"requests":{"cpu":"50m","memory":"64Mi"}}` | Resource requests and limits. The memory limit also sets the Go memory limit. |
| securityContext.allowPrivilegeEscalation | bool | `false` |  |
| securityContext.capabilities.drop[0] | string | `"ALL"` |  |
| securityContext.readOnlyRootFilesystem | bool | `true` |  |
| serviceAccount.annotations | object | `{}` | Annotations on the ServiceAccount. For workload identity set `azure.workload.identity/client-id`. |
| serviceAccount.create | bool | `true` | Create the ServiceAccount. If false, `name` must name an existing one. |
| serviceAccount.name | string | `""` | Name of the ServiceAccount. Defaults to the full name of the release. |
| tolerations | list | `[]` | Tolerations of the pods. |
| topologySpreadConstraints | list | `[]` | Topology spread constraints of the pods. |
| warnOnExportableCAKey | string | `nil` | Record a `CAKeyExportable` warning event on an issuer whose CA private key can be exported from Key Vault. Judged from the certificate's policy, and from the backing secret when the issuer has `chainInSecret` set. No warning does not prove the key is safe. Unset uses the controller's default, which is on. |
