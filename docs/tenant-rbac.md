# Letting teams use their own identity

An `AzureKeyVaultIssuer` (or an `AzureKeyVaultClusterIssuer`) can authenticate
to Azure as a named ServiceAccount, with `spec.auth.workloadIdentity.serviceAccountRef`.
The controller asks the Kubernetes API for a short-lived token for that
ServiceAccount (the TokenRequest API) and exchanges it with Microsoft Entra for
an Azure token.

Kubernetes RBAC alone decides which ServiceAccounts the controller may do this
for. The controller starts with no such right. You grant it **one named
ServiceAccount at a time**, never a whole namespace. The same applies to the
Secrets used by the client certificate and client secret fallbacks
([below](#secrets-for-the-fallback-methods)).

## For a team's namespace

Create this Role and RoleBinding in the team's namespace. The `resourceNames`
line is what keeps the grant to one ServiceAccount:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: azure-keyvault-issuer-token
  namespace: team-a
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    resourceNames: ["team-a-issuer"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: azure-keyvault-issuer-token
  namespace: team-a
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: azure-keyvault-issuer-token
subjects:
  - kind: ServiceAccount
    name: azure-keyvault-issuer # the controller's ServiceAccount
    namespace: cert-manager     # the namespace the chart is installed in
```

The chart can create the same objects for you, with `tenantAccess`:

```yaml
tenantAccess:
  - namespace: team-a
    serviceAccounts: [team-a-issuer]
```

The ServiceAccount also needs a federated credential in Entra, with the subject
`system:serviceaccount:team-a:team-a-issuer` and the audience
`api://AzureADTokenExchange`, and a role on the Key Vault (see the Azure setup
docs).

An Issuer can only name a ServiceAccount in its **own** namespace. There is no
namespace field to point it elsewhere.

Without the Role, the issuer reports a clear condition naming the ServiceAccount
and the Kubernetes error.

## For ClusterIssuers

A ClusterIssuer's ServiceAccount is looked up in the **cluster resource
namespace**, which is the controller's own namespace unless you set
`controller.clusterResourceNamespace`. List the names in the chart:

```yaml
clusterIssuer:
  serviceAccounts: [shared-issuer]
```

## Never grant the controller's own ServiceAccount

The controller's own ServiceAccount carries its **ambient identity**. If an
issuer could name it in `serviceAccountRef`, it would get that identity even
with `--issuer-ambient-credentials=false`. The controller has no check for this:
it can only mint tokens for ServiceAccounts RBAC lets it, so the rule is that
you never grant that one. The chart refuses it, both in `clusterIssuer.serviceAccounts`
and in `tenantAccess` for its own namespace.

If you write the Role by hand, do the same. Also keep the right to create
Issuers in the controller's namespace to administrators, because an Issuer there
could name any ServiceAccount that namespace grants.

## Secrets for the fallback methods

The client certificate and client secret methods ([Azure setup](azure-setup.md#6-fallbacks-a-client-certificate-or-client-secret))
read a named Secret instead of minting a token. The controller starts with no
access to any Secret, and never lists or watches them: it only gets one by name.
Grant it **one named Secret at a time**:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: azure-keyvault-issuer-secrets
  namespace: team-a
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["akvi-client-cert"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: azure-keyvault-issuer-secrets
  namespace: team-a
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: azure-keyvault-issuer-secrets
subjects:
  - kind: ServiceAccount
    name: azure-keyvault-issuer # the controller's ServiceAccount
    namespace: cert-manager     # the namespace the chart is installed in
```

Never leave `resourceNames` out: without it the Role covers every Secret in the
namespace. Or let the chart create the objects, for a team's namespace and for
ClusterIssuers (in the cluster resource namespace):

```yaml
tenantAccess:
  - namespace: team-a
    secrets: [akvi-client-cert]
clusterIssuer:
  secrets: [shared-client-cert]
```

An entry may list `serviceAccounts`, `secrets` or both; the chart makes a
separate Role for each.

As with ServiceAccounts, an Issuer can only name a Secret in its own namespace,
and anyone who may create an Issuer in a namespace can point it at any Secret the
controller is granted there. The issuer itself never exposes the Secret's
contents: they appear in no condition, event or log line.

Without the Role, the issuer reports a condition naming the Secret and the
Kubernetes error.

**How quickly removing access takes effect.** Deleting the Secret Role stops the
issuer at its next Azure token request, because the controller reads the Secret
each time it needs a token. Deleting a token Role stops a workload-identity
issuer only once the Azure token it already holds expires, which can take up to
about an hour. To cut access off at once for either, remove the identity's role
assignment on the vault, or its credential in Entra; even then, Azure tokens
already issued stay valid until they expire.

## Related guardrails

- `controller.issuerAmbientCredentials` (default `false`): lets namespaced
  Issuers with no `auth` use the controller's own identity. Leave it off in a
  multi-tenant cluster.
- `controller.allowedVaults`: limits which Key Vaults namespaced Issuers may use.
