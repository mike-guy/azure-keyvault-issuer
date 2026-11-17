# Examples

Each example is complete. Replace the GUIDs, the vault URL and the certificate name with your own. See [configuration.md](configuration.md) for what each field means.

* [Requesting a certificate](#requesting-a-certificate)
* [A ClusterIssuer using the controller's identity](#a-clusterissuer-using-the-controllers-identity)
* [An Issuer using workload identity](#an-issuer-using-workload-identity)
* [An Issuer using a client certificate](#an-issuer-using-a-client-certificate)
* [An Issuer using a client secret](#an-issuer-using-a-client-secret)
* [A CA below intermediates](#a-ca-below-intermediates)
* [Restricting names and namespaces](#restricting-names-and-namespaces)
* [Issuing CA certificates](#issuing-ca-certificates)

## Requesting a certificate

A Certificate refers to an issuer with the group and kind of the issuer, as with any external issuer.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: app
  namespace: team-a
spec:
  secretName: app-tls
  dnsNames:
    - app.team-a.example.com
  duration: 720h
  renewBefore: 240h
  issuerRef:
    group: azure-keyvault-issuer.mike-guy.github.io
    kind: AzureKeyVaultClusterIssuer   # or AzureKeyVaultIssuer
    name: my-ca
```

Check it:

```console
kubectl --namespace team-a get certificate app
kubectl --namespace team-a get certificaterequest
kubectl get azurekeyvaultclusterissuer my-ca
```

If the issuer is not `Ready`, `kubectl describe` shows why. If the CertificateRequest is never approved, see [Approving requests](../charts/azure-keyvault-issuer/README.md#approving-requests).

## A ClusterIssuer using the controller's identity

With no `auth`, the controller's own workload identity is used. This is the least to configure, and suits a CA that every namespace may use. Set up the controller's identity as described in the [chart README](../charts/azure-keyvault-issuer/README.md#authenticating-to-azure).

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultClusterIssuer
metadata:
  name: my-ca
spec:
  vaultURL: https://my-ca.vault.azure.net/
  certificateName: my-ca
```

## An Issuer using workload identity

The controller requests a token for the named ServiceAccount, which must be in the issuer's namespace. Give the Entra application or managed identity a federated credential with your cluster's OIDC issuer URL as the issuer, and `system:serviceaccount:team-a:my-ca-signer` as the subject.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-ca-signer
  namespace: team-a
---
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultIssuer
metadata:
  name: my-ca
  namespace: team-a
spec:
  vaultURL: https://my-ca.vault.azure.net/
  certificateName: my-ca
  auth:
    workloadIdentity:
      clientID: 00000000-0000-0000-0000-000000000000
      tenantID: 11111111-1111-1111-1111-111111111111
      serviceAccountRef:
        name: my-ca-signer
```

The ServiceAccount needs no annotations and no pod. The controller must be allowed to create tokens for it, which the chart grants by default (see `rbac.secretNamespaces`).

## An Issuer using a client certificate

For clusters that cannot federate with Entra. The Secret holds `tls.crt` and `tls.key` (an unencrypted RSA key), and the certificate must be registered on the Entra application.

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultIssuer
metadata:
  name: my-ca
  namespace: team-a
spec:
  vaultURL: https://my-ca.vault.azure.net/
  certificateName: my-ca
  auth:
    clientCertificate:
      clientID: 00000000-0000-0000-0000-000000000000
      tenantID: 11111111-1111-1111-1111-111111111111
      secretRef:
        name: my-ca-client-cert
```

```console
kubectl --namespace team-a create secret tls my-ca-client-cert --cert=client.crt --key=client.key
```

## An Issuer using a client secret

A last resort. The Secret holds the client secret under the key you name.

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultIssuer
metadata:
  name: my-ca
  namespace: team-a
spec:
  vaultURL: https://my-ca.vault.azure.net/
  certificateName: my-ca
  auth:
    clientSecret:
      clientID: 00000000-0000-0000-0000-000000000000
      tenantID: 11111111-1111-1111-1111-111111111111
      secretRef:
        name: my-ca-client-secret
        key: clientSecret
```

```console
kubectl --namespace team-a create secret generic my-ca-client-secret --from-literal=clientSecret=<secret>
```

## A CA below intermediates

If the Key Vault CA is issued by an intermediate, merge the intermediates into the certificate in the vault, then set `chainInSecret`. Each certificate then comes back with the chain above the Key Vault CA. The identity also needs to read secrets.

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultClusterIssuer
metadata:
  name: my-ca
spec:
  vaultURL: https://my-ca.vault.azure.net/
  certificateName: my-ca
  chainInSecret: true
```

## Restricting names and namespaces

A ClusterIssuer that signs only for two domains, only for two namespaces, and for at most 30 days:

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultClusterIssuer
metadata:
  name: my-ca
spec:
  vaultURL: https://my-ca.vault.azure.net/
  certificateName: my-ca
  allowedNamespaces:
    - team-a
    - team-b
  policy:
    maxDuration: 720h
    allowedDomains:
      - example.com            # the domain itself
      - "*.example.com"        # app.example.com
      - "**.internal.example.org"   # a.b.internal.example.org
    allowedExtKeyUsages:
      - server auth
```

Quote entries that start with `*`, as YAML reads a bare `*` as an alias.

## Issuing CA certificates

To sign intermediate CAs, set `allowCA` and list the usages those CAs may carry. This cannot be combined with `allowedDomains`, and the Key Vault CA's path length must allow it. A CA with path length 1 can issue a CA that signs only end certificates.

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultClusterIssuer
metadata:
  name: my-root
spec:
  vaultURL: https://my-ca.vault.azure.net/
  certificateName: my-ca
  allowedNamespaces:
    - cert-manager
  policy:
    allowCA: true
    allowedExtKeyUsages:
      - server auth
      - client auth
```

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: team-a-ca
  namespace: cert-manager
spec:
  isCA: true
  commonName: team-a-ca
  secretName: team-a-ca
  duration: 8760h
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    group: azure-keyvault-issuer.mike-guy.github.io
    kind: AzureKeyVaultClusterIssuer
    name: my-root
```

Note that `duration` here is clamped to the issuer's `maxDuration`, which is 90 days unless you raise it.
