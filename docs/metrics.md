# Metrics

The controller serves controller-runtime's Prometheus metrics (reconcile counts, errors, queue depth, and so on).
They are off until you set `--metrics-bind-address`, for example `:8443`. The endpoint is HTTPS and needs
authentication by default.

| Mode | Flags | Prometheus needs |
|---|---|---|
| Self-signed certificate (default) | `--metrics-bind-address=:8443` | `insecureSkipVerify: true` and a bearer token |
| Your own certificate | adds `--metrics-cert-path=<dir>` | the CA, a `serverName` and a bearer token |
| Plain HTTP | `--metrics-bind-address=:8080 --metrics-secure=false` | nothing, and so anyone who can reach the port can read it |

## Authentication

In the two HTTPS modes every caller must send a bearer token. The controller checks it with a TokenReview, then checks
with a SubjectAccessReview that the caller may `get` the `/metrics` URL. The controller's ClusterRole therefore needs
`create` on `tokenreviews` and `subjectaccessreviews`, and whatever scrapes the metrics needs a role that allows
`get` on the non-resource URL `/metrics`.

## Self-signed certificate

With no `--metrics-cert-path`, the controller generates a certificate at start up that is valid only for `localhost`.
Traffic is encrypted, but Prometheus cannot verify the server, so it must skip verification. The token is still
checked, so the risk is that a token is sent to something pretending to be the controller. Use your own certificate
if that matters.

```yaml
endpoints:
  - port: https
    scheme: https
    bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
    tlsConfig:
      insecureSkipVerify: true
```

## Your own certificate

The controller serves the certificate and key in `--metrics-cert-path`, and reloads them when they change, so a
renewed certificate needs no restart. The files are `tls.crt` and `tls.key`, the keys of a `kubernetes.io/tls` Secret.
Change the names with `--metrics-cert-name` and `--metrics-cert-key`.

If the directory or either file is missing, the controller refuses to start. Without that check,
controller-runtime would quietly serve the self-signed certificate instead.

The certificate can come from any issuer. It is a certificate for a workload like any other. Give it the names that
Prometheus connects to:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: azure-keyvault-issuer-metrics
  namespace: cert-manager          # the controller's namespace
spec:
  secretName: azure-keyvault-issuer-metrics-tls
  dnsNames:
    - <metrics-service>.<namespace>.svc
    - <metrics-service>.<namespace>.svc.cluster.local
  issuerRef:
    name: <any issuer>
```

Mount the Secret as a directory, not with `subPath`, because Kubernetes never updates a `subPath` mount:

```yaml
containers:
  - args:
      - --metrics-bind-address=:8443
      - --metrics-cert-path=/var/run/secrets/metrics-tls
    volumeMounts:
      - name: metrics-tls
        mountPath: /var/run/secrets/metrics-tls
        readOnly: true
volumes:
  - name: metrics-tls
    secret:
      secretName: azure-keyvault-issuer-metrics-tls
```

Prometheus then verifies the server with the issuer's CA:

```yaml
tlsConfig:
  serverName: <metrics-service>.<namespace>.svc
  ca:
    configMap:
      name: <configmap holding the CA>
      key: ca.crt
```

### Getting the certificate from this issuer

This works, in stages, because the controller must be running before its own issuer can sign anything:

1. Start the controller with no `--metrics-cert-path`. It serves the self-signed certificate.
2. Create the issuer and wait for it to be Ready.
3. Create the `Certificate` above, with this issuer as its `issuerRef`, and wait for the Secret.
4. Add the volume and `--metrics-cert-path` to the Deployment. The pod restarts and serves the new certificate.

Things to know:

- The `Certificate` must be in a namespace the issuer allows. A ClusterIssuer's `allowedNamespaces` has to include the
  controller's namespace.
- Renewal needs this issuer and Key Vault to be working. Give the certificate a long `duration` and a generous
  `renewBefore`, and alert on cert-manager's `certmanager_certificate_expiration_timestamp_seconds`, so that
  verified scraping is not lost while Key Vault is down.

## Plain HTTP

`--metrics-secure=false` serves HTTP with no authentication. Use it only where a NetworkPolicy limits who can reach the
port. `--metrics-cert-path` cannot be combined with it.
