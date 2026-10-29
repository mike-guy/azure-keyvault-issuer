# Metrics

The controller serves Prometheus metrics (controller-runtime's, such as reconcile
counts, errors and queue depth) over **HTTPS** on port 8443, through the Service
`<release>-metrics`. Set `metrics.enabled: false` to turn the endpoint off.

Every caller must authenticate. The controller checks the caller's bearer token
with a TokenReview, then checks that it may `get` the `/metrics` URL with a
SubjectAccessReview. The chart creates a `<release>-metrics-reader` ClusterRole
for that. Bind it to whatever scrapes the metrics:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prometheus-akvi-metrics
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: azure-keyvault-issuer-metrics-reader
subjects:
  - kind: ServiceAccount
    name: prometheus-k8s     # your Prometheus's ServiceAccount
    namespace: monitoring
```

With the Prometheus Operator, `metrics.serviceMonitor.enabled: true` creates a
ServiceMonitor that scrapes with the Prometheus ServiceAccount's token.

## The issuer's own metrics

As well as controller-runtime's metrics, the controller serves these:

| Metric | Type | Labels | What it is |
|---|---|---|---|
| `azure_keyvault_issuer_ca_expiration_timestamp_seconds` | gauge | `kind`, `namespace`, `name` | When the issuer's CA chain expires, as a Unix timestamp: the earliest expiry of the Key Vault CA and, with `chainSource: Secret`, the certificates above it. `namespace` is empty for a ClusterIssuer. |
| `azure_keyvault_issuer_azure_requests_total` | counter | `host`, `method`, `code` | HTTP attempts made to Azure: Key Vault and Microsoft Entra. `code` is the status code, or `error` when no response arrived. |
| `azure_keyvault_issuer_azure_request_duration_seconds` | histogram | `host`, `method`, `code` | How long each of those attempts took. |

### Alerting on CA expiry

The issuer never issues a certificate that outlives its CA chain, so as the CA
nears expiry, every certificate it issues gets shorter, and renewals come faster
and faster. When the CA expires, the issuer stops working and so does every
certificate it issued. Alert well before that, and rotate the CA
([CA provisioning](ca-provisioning.md#rotation)):

```yaml
# PrometheusRule
- alert: AzureKeyVaultIssuerCAExpiringSoon
  expr: azure_keyvault_issuer_ca_expiration_timestamp_seconds - time() < 30 * 24 * 3600
  labels:
    severity: warning
  annotations:
    summary: "CA of {{ $labels.kind }} {{ $labels.namespace }}/{{ $labels.name }} expires within 30 days"
```

The gauge is updated every time the issuer is checked and every time it signs,
so it follows a rotated CA with the next certificate. Within 30 days of expiry,
the issuer also records a `CAExpiringSoon` warning event on itself, visible in
`kubectl describe`.

### Reading the Azure request metrics

They show *why* signing is failing or slow, where controller-runtime's metrics
show only *that* reconciles fail:

- `code="429"` is throttling. azcore waits and retries it, but a steady rate
  means the vault is near its limits (see Key Vault's service limits).
- `code="403"` on the vault's host is a missing role assignment; `code="400"` or
  `401` on `login.microsoftonline.com` is Microsoft Entra refusing the sign-in
  ([Troubleshooting](troubleshooting.md)).
- **`code="401"` on the vault's host is normal.** Key Vault answers the first
  request of each new client with a 401 that tells it which tenant and scope to
  get a token for (its authentication challenge), and the client then sends the
  request again with a token. The issuer makes new clients for every
  certificate, so expect a 401 for each 200. The issuer does this deliberately:
  each new client asks for a token, so a credential built from a Secret reads
  the Secret again, and a rotated Secret takes effect on the next certificate.

Every attempt counts, retries included, so one signature can add several.

## The endpoint's certificate

By default the controller generates a **self-signed** certificate when it starts.
Nothing can verify it, so the ServiceMonitor sets `insecureSkipVerify: true`. The
traffic is still encrypted, but Prometheus does not check that it is talking to
the controller, so anything able to pose as the Service would receive
Prometheus's token.

To remove that, give the controller a certificate Prometheus can verify. You will
most likely want it issued by this issuer, from your Key Vault CA. The controller
must be running before it can sign anything, its own certificate included, so the
setup has two steps: install as normal, then issue the certificate and upgrade
the release to use it.

### 1. Install the chart

Install as normal, and create the AzureKeyVaultClusterIssuer you will use (see
the [README](../README.md#quick-start)). The metrics endpoint serves its
self-signed certificate for now.

### 2. Issue the metrics certificate

Create a Certificate for the metrics Service in the release's namespace. With
the release `azure-keyvault-issuer` in `akvi-system` and a ClusterIssuer
`internal-ca`:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: azure-keyvault-issuer-metrics
  namespace: akvi-system
spec:
  secretName: azure-keyvault-issuer-metrics-tls
  dnsNames:
    - azure-keyvault-issuer-metrics.akvi-system.svc
    - azure-keyvault-issuer-metrics.akvi-system.svc.cluster.local
  usages:
    - digital signature
    - server auth
  privateKey:
    algorithm: ECDSA
    rotationPolicy: Always
  issuerRef:
    group: azure-keyvault-issuer.mike-guy.github.io
    kind: AzureKeyVaultClusterIssuer
    name: internal-ca
```

The first DNS name must match the Service exactly, because the ServiceMonitor
checks it. cert-manager must approve the request, as for any other Certificate
(see [Approving requests](approval.md)). Wait for it:

```sh
kubectl wait --namespace akvi-system --for=condition=Ready certificate/azure-keyvault-issuer-metrics
```

Any other cert-manager issuer works too, for example a CA issuer. What matters
is that the Secret holds `tls.crt` and `tls.key`.

### 3. Give Prometheus the CA

The issued Secret's `ca.crt` is empty (this issuer leaves the root to
[trust-manager](trust-manager.md)), so Prometheus needs the root from a ConfigMap
in the release's namespace. If you already distribute the root with a
trust-manager `Bundle`, include that namespace in its `namespaceSelector`. The
Bundle's target ConfigMap, for example `internal-ca` with key `ca-bundle.crt`,
is then the one to use. Or create one by hand:

```sh
kubectl create configmap akvi-metrics-ca --namespace akvi-system --from-file=ca.crt=root.pem
```

### 4. Upgrade the release to use them

```yaml
# azure-keyvault-issuer chart values
metrics:
  tls:
    secretName: azure-keyvault-issuer-metrics-tls
  serviceMonitor:
    enabled: true
    caConfigMap:
      name: internal-ca          # or akvi-metrics-ca
      key: ca-bundle.crt         # or ca.crt
```

`helm upgrade` with these values mounts the Secret into the pod and passes
`--metrics-cert-path`. Because the pod template changes, Kubernetes replaces the
pod. The new one finds the certificate when it starts and logs:

```text
metrics endpoint serves the certificate in its certificate path
```

The ServiceMonitor now verifies the certificate against that CA and the
Service's name, with no `insecureSkipVerify`. The chart refuses
`metrics.tls.secretName` without `caConfigMap` while the ServiceMonitor is on,
and the other way round, so it cannot be half set up.

To check by hand:

```sh
kubectl port-forward --namespace akvi-system service/azure-keyvault-issuer-metrics 8443 &
openssl s_client -connect localhost:8443 -CAfile root.pem \
  -servername azure-keyvault-issuer-metrics.akvi-system.svc -verify_return_error </dev/null
```

## Renewal and failure

- **Renewal needs no restart.** cert-manager renews the certificate before it
  expires and updates the Secret. Kubernetes updates the mounted files, and the
  controller notices and serves the new certificate.
- **The Secret is mounted as optional**, and the controller reads it only when it
  starts. If the Secret is missing when the pod starts, or its certificate can't
  be loaded, the controller still starts. It serves a self-signed certificate and
  logs a warning:

  ```text
  metrics endpoint serves a self-signed certificate until the controller restarts, because its certificate can't be loaded
  ```

  Prometheus then reports verification failures for the target. Once the Secret
  is back (cert-manager re-issues a deleted one, through this controller),
  restart the controller:
  `kubectl rollout restart --namespace akvi-system deployment/azure-keyvault-issuer`.
  The pod never waits for the Secret, because the Secret may depend on the
  controller running.

## Why it works this way

Most cert-manager issuers serve metrics over plain HTTP. controller-runtime-based
projects scaffolded by kubebuilder serve HTTPS with a self-signed certificate, as
this controller does by default. kubebuilder offers a certificate from
cert-manager, mounted as a required Secret and issued by cert-manager's built-in
self-signed issuer. That pattern would deadlock here if the certificate came from
this issuer, so the Secret is optional and the switch happens at upgrade time.
cert-manager itself can instead generate its own CA into a Secret. That would
mean the controller writing a CA private key into a Secret, which conflicts with
keeping keys in Key Vault and with the controller's narrow access to Secrets.
