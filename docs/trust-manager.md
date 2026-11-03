# Distributing trust with trust-manager

A certificate this issuer signs is only useful to a client that trusts the CA
behind it. The issuer does not hand clients the root: it puts the leaf, the Key
Vault CA and any intermediates in the certificate, and leaves the **root** out, and
it sets no `ca.crt` in the issued Secret. cert-manager recommends
[trust-manager](https://cert-manager.io/docs/trust/trust-manager/) for the root,
because trust changes (a new root, a rotated CA) then reach every namespace from
one place, instead of being copied by hand.

This page shows the shape of a trust-manager setup. Installing trust-manager is
covered by its own documentation.

## What to distribute

The root of the chain your Key Vault CA was signed under, and any intermediates a
client would not otherwise have:

- for a CA your organisation's PKI signed, your organisation's root, which you
  probably already distribute;
- for the [evaluation CA](ca-provisioning.md#trying-it-out-an-evaluation-ca), the
  `root.pem` you made. Nothing outside your test cluster trusts it, which is why
  that CA is for evaluation only.

Check what a client will see before you rely on it:

```sh
kubectl get secret my-cert -o jsonpath='{.data.tls\.crt}' | base64 -d > chain.pem
openssl verify -CAfile root.pem -untrusted chain.pem chain.pem
```

`chain.pem` holds the certificate and the CA that signed it, and `root.pem` is the
only thing trusted. It should print `chain.pem: OK`. If it does not, a client that
trusts only that root will refuse the certificate too.

## A Bundle

trust-manager reads its sources from its own namespace (`cert-manager` unless you
changed it), so put the root in a ConfigMap there:

```sh
kubectl create configmap internal-root --namespace cert-manager --from-file=root.pem=root.pem
```

Then a `Bundle` copies it, as a ConfigMap, into every namespace that matches:

```yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: internal-ca
spec:
  sources:
    - configMap:
        name: internal-root
        key: root.pem
  target:
    configMap:
      key: ca-bundle.crt
    # Optional: only these namespaces. Leave it out for every namespace.
    namespaceSelector:
      matchLabels:
        trust: internal
```

Each selected namespace then holds a ConfigMap `internal-ca` with the bundle in
`ca-bundle.crt`, which workloads mount as their trust store. A workload that
should trust public CAs as well can add `useDefaultCAs: true` as another source.
The same ConfigMap in the controller's namespace lets Prometheus verify the
controller's own metrics certificate (see [Metrics](metrics.md)).

## Rotating the CA

Put the **new** root in the Bundle's sources *alongside* the old one and let it
reach every namespace, and only then move issuers to the new CA version (see
"Rotation" in [CA provisioning](ca-provisioning.md)). Remove the old root once
nothing it signed is still in use. A CA rotated under the same root needs no
change here.
