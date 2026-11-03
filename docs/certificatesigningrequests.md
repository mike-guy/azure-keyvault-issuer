# Signing Kubernetes CertificateSigningRequests

Kubernetes has its own API for asking for a certificate, separate from
cert-manager: the `CertificateSigningRequest` (`certificates.k8s.io/v1`). The
controller can sign these as well as cert-manager CertificateRequests. It is
**off by default**.

Most users don't need it. If your workloads get certificates through cert-manager
(a `Certificate`, ingress-shim, csi-driver or istio-csr), leave it off. Turn it on
when something in the cluster asks for certificates through the Kubernetes API
itself, and should get them from your Key Vault CA.

## How a CertificateSigningRequest is signed

1. A user or a program creates a `CertificateSigningRequest`. It holds their CSR,
   and names who should sign it in `spec.signerName`.
2. Someone allowed to approve it does, for example with
   `kubectl certificate approve <name>`.
3. The controller sees the approved request, signs the certificate with the
   ClusterIssuer's CA, and writes it, with the Key Vault CA and any intermediates,
   into the request's `status.certificate`.
4. The requester reads the certificate from there. Unlike a cert-manager
   `Certificate`, nothing writes it to a Secret.

The controller never creates a CertificateSigningRequest and never approves one.

## Turning it on

```yaml
# azure-keyvault-issuer chart values
controller:
  signCertificateSigningRequests: true
```

This passes `--sign-certificatesigningrequests` to the controller and grants it,
cluster-wide:

- `get`, `list` and `watch` on `certificatesigningrequests`, and `patch` on their
  status;
- `sign` on the signer names `azurekeyvaultclusterissuers.azure-keyvault-issuer.mike-guy.github.io/*`.
  The API server refuses a certificate written for any other signer name.

The controller then watches every CertificateSigningRequest in the cluster,
including the ones nodes make for their kubelets, and ignores any whose signer
name isn't one of its ClusterIssuers.

## The signer name

```text
azurekeyvaultclusterissuers.azure-keyvault-issuer.mike-guy.github.io/<ClusterIssuer name>
```

Only **ClusterIssuers** can sign CertificateSigningRequests. A
CertificateSigningRequest is cluster-scoped, so its signer name has no namespace
that could locate a namespaced Issuer, and issuer-lib, which the controller is
built on, ignores the namespaced kind.

## Asking for a certificate

```sh
openssl ecparam -name prime256v1 -genkey -noout -out app.key
openssl req -new -key app.key -subj "/CN=app.example.com" \
  -addext "subjectAltName=DNS:app.example.com" -out app.csr
```

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: app
spec:
  signerName: azurekeyvaultclusterissuers.azure-keyvault-issuer.mike-guy.github.io/internal-ca
  request: <base64 of app.csr>  # base64 < app.csr | tr -d '\n'
  usages:
    - digital signature
    - server auth
  expirationSeconds: 86400       # optional; the minimum is 600
```

```sh
kubectl certificate approve app
kubectl get csr app -o jsonpath='{.status.certificate}' | base64 -d > app-chain.pem
```

## Lifetime and CA requests

The ClusterIssuer's `spec.policy` applies exactly as it does to a
CertificateRequest:

- **Lifetime.** Taken from cert-manager's annotation
  `experimental.cert-manager.io/request-duration` (for example `48h`) if set, then
  from `spec.expirationSeconds`, then cert-manager's default of 90 days. It is
  clamped to `policy.maxDuration` and to the CA's own expiry, and the clamp is
  recorded as a `DurationClamped` event on the CertificateSigningRequest (in the
  `default` namespace, because the request is cluster-scoped).
- **CA certificates.** A request with the annotation
  `experimental.cert-manager.io/request-is-ca: "true"` is refused unless
  `policy.allowCA` is true. The refusal sets the request's `InvalidRequest` and
  `Failed` conditions.

## Approving them

cert-manager's approver, and its `approveSignerNames` setting, cover
cert-manager CertificateRequests only (see [Approving requests](approval.md)).
Nothing approves CertificateSigningRequests for our signer names unless you set
it up.

- **By hand:** `kubectl certificate approve <name>` or `kubectl certificate deny <name>`.
- **By a person or program you trust:** grant it these permissions, ideally for
  one ClusterIssuer rather than the wildcard:

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: approve-internal-ca
  rules:
    - apiGroups: ["certificates.k8s.io"]
      resources: ["certificatesigningrequests"]
      verbs: ["get", "list", "watch"]
    - apiGroups: ["certificates.k8s.io"]
      resources: ["certificatesigningrequests/approval"]
      verbs: ["update"]
    - apiGroups: ["certificates.k8s.io"]
      resources: ["signers"]
      resourceNames: ["azurekeyvaultclusterissuers.azure-keyvault-issuer.mike-guy.github.io/internal-ca"]
      verbs: ["approve"]
  ```

**On AKS with Azure RBAC for Kubernetes authorisation**, the built-in Azure roles,
*Azure Kubernetes Service RBAC Cluster Admin* included, are not enough: in our
end-to-end tests the cluster admin could not approve for a custom signer name.
Bind the ClusterRole above to the approver with Kubernetes RBAC (a
`ClusterRoleBinding`), which AKS checks as well.

Approval is the security gate. Anyone allowed to create CertificateSigningRequests
can ask for any name, so whoever approves must check what each request asks for
(its SANs, usages and lifetime) before approving it.
