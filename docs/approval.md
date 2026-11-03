# Approving requests

cert-manager does not let an issuer sign a CertificateRequest until it is
**approved**. Its built-in approver approves requests automatically, but only for
the signer names it has been granted `approve` RBAC for. For an external issuer
you must tell cert-manager to approve ours. The chart does not ship approver
RBAC, because that belongs to cert-manager's installation.

Our controller only acts on requests that already carry the `Approved`
condition. An unapproved request is left alone, and a denied one is failed.

This page is about cert-manager CertificateRequests. Kubernetes
CertificateSigningRequests, which the controller can sign when that is turned
on, are approved differently: see
[Signing Kubernetes CertificateSigningRequests](certificatesigningrequests.md).

## Approving everything for our issuers

Set cert-manager's `approveSignerNames` chart value to include our two signer
names. The value replaces cert-manager's default list (its own Issuer and
ClusterIssuer), so keep those two entries:

```yaml
# cert-manager chart values
approveSignerNames:
  - issuers.cert-manager.io/*
  - clusterissuers.cert-manager.io/*
  - azurekeyvaultissuers.azure-keyvault-issuer.mike-guy.github.io/*
  - azurekeyvaultclusterissuers.azure-keyvault-issuer.mike-guy.github.io/*
```

Keep cert-manager's own two entries, or its built-in issuers stop being
approved.

## Multi-tenant clusters

Auto-approving everything means anyone who can create a Certificate against one
of these issuers gets a signed certificate. That is fine for a single team. For a
shared cluster, use [approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/),
which approves only requests that match a policy, for example limiting each team
to its own DNS names. Leave our signer names out of `approveSignerNames`, and
write a `CertificateRequestPolicy` that names them.
