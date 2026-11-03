# Network policy

The chart can create a NetworkPolicy for the controller. It is **off by
default** (`networkPolicy.enabled: false`), because a wrong policy drops traffic
without any message, and the chart cannot know your cluster's addresses.

## What it allows

| Direction | What | Why |
|---|---|---|
| Ingress | TCP to the probe port (8081) and, if metrics are on, the metrics port (8443) | Kubelet probes and Prometheus. Metrics callers must also pass a TokenReview and a SubjectAccessReview. |
| Egress | UDP and TCP 53 | DNS |
| Egress | TCP 443 and 6443 (`networkPolicy.egressPorts`) | Key Vault, Microsoft Entra and the Kubernetes API server (443 on most clusters, 6443 on some, including OpenShift) |

This follows cert-manager's chart, which also allows ports rather than
addresses.

## What it cannot do

A Kubernetes NetworkPolicy cannot filter by hostname. The controller needs
`*.vault.azure.net` and `login.microsoftonline.com`, whose addresses change, so
the policy can only open port 443. By default, egress is open to any
destination on those ports. Narrow it with `networkPolicy.egressTo`, which takes
standard NetworkPolicy peers, for example a CIDR for your API server and one for
an egress proxy:

```yaml
networkPolicy:
  enabled: true
  egressTo:
    - ipBlock:
        cidr: 10.0.0.0/8
```

Restrict who may scrape metrics with `networkPolicy.ingressFrom`.

## Restricting by hostname

For hostname rules, use a CNI that supports them:

- **Cilium:** a `CiliumNetworkPolicy` with `toFQDNs` for `*.vault.azure.net` and
  `login.microsoftonline.com`.
- **Calico:** a `GlobalNetworkPolicy` with a domain-name allow list (Calico
  Enterprise or Calico Cloud).

The chart does not template these, because they depend on your CNI. If you use
one, leave `networkPolicy.enabled` off and let the CNI policy carry the egress
rules.
