# Azure setup

What to create in Azure so the controller can sign with your CA: a vault, a
least-privilege role, an identity, and the trust between that identity and your
cluster (or, as a fallback, a certificate or secret for it). Making the CA
certificate itself is on [its own page](ca-provisioning.md).

The commands use the Azure CLI. Set these first, and use your own names:

```sh
SUBSCRIPTION=$(az account show --query id -o tsv)
TENANT=$(az account show --query tenantId -o tsv)
RG=my-ca-rg
LOCATION=northeurope
VAULT=my-ca-vault
```

Only the Azure public cloud is supported (`*.vault.azure.net`).

## 1. The vault

Use **Azure RBAC** for access, not access policies: the roles below are RBAC
roles. A Standard vault holds software keys, and a Premium vault also holds
HSM-backed ones.

```sh
az group create --name $RG --location $LOCATION
az keyvault create --name $VAULT --resource-group $RG --location $LOCATION \
  --enable-rbac-authorization true            # add --sku premium for HSM keys
```

Keep the vault's soft-delete on (it is by default), and consider purge
protection for a production CA: without it, a deleted vault, and the CA key in
it, can be purged for good.

## 2. A role that can only read the certificate and sign

The issuer needs two things from Key Vault: read the CA certificate, and ask for
a signature. This custom role grants exactly those and nothing else. It cannot
read secrets, export or change a key, or create anything.

```sh
cat > role.json <<EOF
{
  "Name": "Azure Key Vault Issuer",
  "IsCustom": true,
  "Description": "Read certificates and sign with keys: what azure-keyvault-issuer needs.",
  "Actions": [],
  "DataActions": [
    "Microsoft.KeyVault/vaults/certificates/read",
    "Microsoft.KeyVault/vaults/keys/sign/action"
  ],
  "AssignableScopes": ["/subscriptions/$SUBSCRIPTION/resourceGroups/$RG"]
}
EOF
az role definition create --role-definition @role.json
```

Widen `AssignableScopes` if you want to assign it in other resource groups.

If you cannot create a custom role, use two built-in ones instead: **Key Vault
Crypto User** (which can sign) and **Key Vault Reader**. They grant more than the
issuer needs: Crypto User can also encrypt, decrypt, wrap, unwrap and update any
key in the vault, and Reader can read everything in it but secret values. Prefer
the custom role.

Assign the role on the vault. (The end-to-end tests do this, so it is the tested
scope. Azure RBAC can also scope a role to one certificate or key, which would be
tighter; if you do, assign it on both the certificate and the key of the same
name, and check that issuing works.)

## 3. An identity, and its trust with your cluster

The controller signs in to Azure as a **workload identity**: a Kubernetes
ServiceAccount token that Microsoft Entra exchanges for an Azure token, so there is
no secret to store. Create a user-assigned managed identity for it, give it the
role, and tell Entra which ServiceAccount to trust.

```sh
az identity create --name akvi-issuer --resource-group $RG --location $LOCATION
CLIENT_ID=$(az identity show --name akvi-issuer --resource-group $RG --query clientId -o tsv)
PRINCIPAL_ID=$(az identity show --name akvi-issuer --resource-group $RG --query principalId -o tsv)
VAULT_ID=$(az keyvault show --name $VAULT --query id -o tsv)

az role assignment create --assignee-object-id $PRINCIPAL_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Azure Key Vault Issuer" --scope $VAULT_ID

az identity federated-credential create --name akvi --identity-name akvi-issuer \
  --resource-group $RG \
  --issuer "$OIDC_ISSUER" \
  --subject "system:serviceaccount:$NAMESPACE:$SERVICE_ACCOUNT" \
  --audiences api://AzureADTokenExchange
```

Two values come from your cluster:

- **`OIDC_ISSUER`** is the URL your cluster publishes its token-signing keys at.
  Entra fetches them from there, so it must be reachable from the internet.
  - On **AKS**, enable the issuer and read its URL:

    ```sh
    az aks update --resource-group $AKS_RG --name $AKS --enable-oidc-issuer --enable-workload-identity
    OIDC_ISSUER=$(az aks show --resource-group $AKS_RG --name $AKS --query oidcIssuerProfile.issuerUrl -o tsv)
    ```

  - On **any other cluster**, you publish it yourself:
    see [on-prem workload identity](on-prem-workload-identity.md).
- **`NAMESPACE` and `SERVICE_ACCOUNT`** are the ServiceAccount whose token the
  identity trusts. Which one depends on how issuers authenticate.

Entra accepts a federated credential for the ServiceAccount's *exact* name. A
token for any other ServiceAccount, or from any other issuer, is refused.

## 4. Tell the controller which identity to use

There are two ways for an issuer to authenticate with workload identity, and you
can use both. If your cluster cannot use workload identity at all, see
[section 6](#6-fallbacks-a-client-certificate-or-client-secret).

**A ServiceAccount reference** (preferred; the only way a namespaced issuer may
authenticate by default). The issuer names a ServiceAccount, and the controller
asks Kubernetes for a short-lived token for it. Create the federated credential
above for that ServiceAccount (`team-a/team-a-issuer`, say), and have the team's
namespace allow the controller to request its token, as described in
[Letting teams use their own identity](tenant-rbac.md).

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultIssuer
metadata:
  name: team-a-ca
  namespace: team-a
spec:
  vaultURL: https://my-ca-vault.vault.azure.net/
  certificateName: issuing-ca
  auth:
    workloadIdentity:
      clientID: <the identity's client ID>
      tenantID: <your tenant ID>      # optional: defaults from the controller
      serviceAccountRef:
        name: team-a-issuer
```

**The controller's own identity** ("ambient"). An issuer with no `auth` uses the
identity of the controller's pod. This is allowed for a `AzureKeyVaultClusterIssuer`
by default, and refused for a namespaced `AzureKeyVaultIssuer`, so one team cannot
borrow the platform's access. Create the federated credential for the controller's
ServiceAccount (`<release namespace>/azure-keyvault-issuer`, by default), and install
the chart with its client and tenant IDs:

```yaml
workloadIdentity:
  clientID: <the identity's client ID>
  tenantID: <your tenant ID>
  useWebhook: true   # on AKS: let its webhook inject the token. Leave false elsewhere.
```

With `useWebhook: false` the chart projects the token into the pod itself, which
works on any cluster Entra can reach. With `true`, the chart labels the pod and
annotates its ServiceAccount for AKS's workload identity webhook instead.

## 5. If the chain comes from the secret

The issuer reads only the certificate by default. For a PKI deeper than two tiers
it reads the certificate's backing secret too (`chainSource: Secret`; see
[CA provisioning](ca-provisioning.md)), which needs one more permission: the
built-in **Key Vault Secrets User** role, assigned on **that one secret**, never the
whole vault:

```sh
az role assignment create --assignee-object-id $PRINCIPAL_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" --scope "$VAULT_ID/secrets/issuing-ca"
```

The secret has the same name as the certificate. The issuer refuses to read it
unless the key is non-exportable, since an exportable certificate's secret holds
its private key.

## 6. Fallbacks: a client certificate or client secret

Use these only if workload identity is not possible: for example, Entra cannot
reach your cluster's OIDC issuer and you may not publish it, or your tenant does
not allow federated credentials. Both store a long-lived credential in a
Kubernetes Secret, and anyone who obtains it can sign in as the issuer **from
anywhere**, not just from your cluster. Prefer a certificate to a client secret:
its private key never leaves your cluster, whereas a client secret is sent to
Entra with every sign-in.

A managed identity cannot hold a certificate or a secret, so create an Entra
**application** and its service principal instead, and give that the role:

```sh
APP_ID=$(az ad app create --display-name akvi-issuer --query appId -o tsv)
SP_ID=$(az ad sp create --id $APP_ID --query id -o tsv)
VAULT_ID=$(az keyvault show --name $VAULT --query id -o tsv)

az role assignment create --assignee-object-id $SP_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Azure Key Vault Issuer" --scope $VAULT_ID
```

The Secret goes in the issuer's namespace, or for a `AzureKeyVaultClusterIssuer`
in the cluster resource namespace. The controller may read it only once you grant
it that one Secret by name: see [Letting teams use their own identity](tenant-rbac.md#secrets-for-the-fallback-methods).

### A client certificate (preferred)

Make an RSA key and a self-signed certificate (Entra accepts only RSA), register
the certificate with the application, and store both in a `kubernetes.io/tls`
Secret. Keep the lifetime short and rotate it (below).

```sh
openssl req -x509 -newkey rsa:3072 -nodes -days 90 -subj "/CN=akvi-issuer" \
  -keyout tls.key -out tls.crt
az ad app credential reset --id $APP_ID --append --cert @tls.crt   # the public certificate only
kubectl create secret tls akvi-client-cert -n team-a --cert tls.crt --key tls.key
rm tls.key
```

The key must not be encrypted. `tls.crt` may hold a chain; only its first
certificate, the one matching the key, is used.

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultIssuer
metadata:
  name: team-a-ca
  namespace: team-a
spec:
  vaultURL: https://my-ca-vault.vault.azure.net/
  certificateName: issuing-ca
  auth:
    clientCertificate:
      clientID: <the application's client ID>   # $APP_ID
      tenantID: <your tenant ID>                # optional: defaults from the controller
      secretRef:
        name: akvi-client-cert
```

### A client secret (last resort)

```sh
SECRET=$(az ad app credential reset --id $APP_ID --append --display-name akvi \
  --end-date 2027-01-31 --query password -o tsv)
printf %s "$SECRET" | kubectl create secret generic akvi-client-secret -n team-a \
  --from-file=clientSecret=/dev/stdin
unset SECRET
```

Piping it in keeps the secret out of your shell history and the process list.
Whitespace around the value is ignored.

```yaml
  auth:
    clientSecret:
      clientID: <the application's client ID>
      secretRef:
        name: akvi-client-secret
        key: clientSecret
```

### Rotating

The controller reads the Secret every time it needs a new Azure token, so
**updating the Secret in place** takes effect at once, with no restart and no
edit to the issuer. To rotate without a gap:

1. Add the new certificate or secret to the application, keeping the old one
   (`az ad app credential reset --append …`, as above).
2. Replace the Secret's contents, for example
   `kubectl create secret tls akvi-client-cert -n team-a --cert new.crt --key new.key --dry-run=client -o yaml | kubectl apply -f -`.
3. Once a certificate has been issued since the change, remove the old credential:
   `az ad app credential list --id $APP_ID --cert` (or without `--cert` for
   secrets) shows its key ID, then
   `az ad app credential delete --id $APP_ID --key-id <key ID> --cert`.

If the new Secret cannot be used (a missing key, or a key that does not match the
certificate, say), the issuer fails at once rather than carrying on with the old
credential, so a broken rotation is visible straight away.

### Keeping the Secret safe

- Turn on [encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
  for Secrets in etcd. AKS encrypts etcd's disks; [KMS etcd encryption](https://learn.microsoft.com/azure/aks/use-kms-etcd-encryption)
  adds encryption with your own key.
- Limit who can read the Secret. The controller needs only `get` on that one name.
- Keep credentials short-lived, and remove old ones from the application as soon
  as they are replaced.
- Removing the controller's access to the Secret stops the issuer at its next
  token request. To cut the credential off everywhere, delete it from the
  application in Entra.

## Propagation

Azure takes time to act on what you create. A new role assignment can take a few
minutes to apply, and a new federated credential, application certificate or
client secret can take a minute or so before Entra accepts it. Until then an issuer reports not ready with a 403 or
an `AADSTS` error. It retries by itself and becomes ready once Azure catches up. See
[troubleshooting](troubleshooting.md).
