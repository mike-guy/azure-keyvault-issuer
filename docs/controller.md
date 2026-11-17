# Running the controller

The chart sets the flags for you from its values (see the chart's [README](../charts/azure-keyvault-issuer/README.md)). This page is for the flags themselves, and for working out what has gone wrong.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--cluster-resource-namespace` | the controller's namespace | Where a ClusterIssuer's Secrets and ServiceAccount are found. |
| `--leader-elect` | `true` | Leader election, so only one replica reconciles at a time. It needs to run in a cluster, so use `--leader-elect=false` to run the controller on your own machine. |
| `--max-concurrent-reconciles` | `3` | How many objects each controller reconciles at once. See [below](#concurrency). |
| `--reconcile-timeout` | `2m` | The longest one check or signing may take in total, including the Secret read, token request and every Key Vault call. At most `10m`. |
| `--ca-expiry-warning-threshold` | `2160h` (90 days) | How close to expiry the CA chain must be for a `CAExpiring` Warning event on the issuer when it signs. Go durations have no day unit. At most 10 years. |
| `--warn-on-exportable-ca-key` | `true` | Record a `CAKeyExportable` Warning event on an issuer whose CA key is exportable. Use `=false` to turn it off. |
| `--azure-max-retries` | `3` | How many times a failed Azure request is retried. `0` disables retries. At most `10`. |
| `--azure-try-timeout` | `10s` | How long one Azure request attempt may take. At most `1m`. |
| `--health-probe-bind-address` | `:8081` | Serves `/healthz` and `/readyz`. |
| `--metrics-bind-address` | `0` (off) | Where metrics are served. See [metrics.md](metrics.md). |
| `--metrics-secure` | `true` | Serve metrics over HTTPS with authentication. |
| `--metrics-cert-path`, `--metrics-cert-name`, `--metrics-cert-key` | none, `tls.crt`, `tls.key` | A certificate for the metrics endpoint. Without a path, a self-signed one is served. |
| `--enable-http2` | `false` | Enable HTTP/2 for the metrics endpoint. |
| `--zap-*` | | controller-runtime's logging flags, such as `--zap-log-level`. |
| `--version` | | Print the version and exit. |

The Go memory limit is set from the container's, so the runtime does not grow past it. `GOMEMLIMIT`, if set, takes precedence, and `AUTOMEMLIMIT` changes the ratio from its default of 0.9.

## Concurrency

issuer-lib runs one controller for each issuer kind and one for CertificateRequests, and `--max-concurrent-reconciles` applies to each, so the most work in flight is a multiple of it. An object is never reconciled twice at once.

More than one worker stops a single slow issuer, such as one with a bad credential or a vault that is timing out, from holding up the rest. Raise it for a large burst of requests against one vault, and watch for `429` responses from Key Vault. Set it to `1` for serial behaviour. The default has not been load tested.

## Metrics

The controller serves controller-runtime's metrics (reconcile counts, errors and queue depth). They are off by default and, once enabled, are served over HTTPS with authentication. See [metrics.md](metrics.md).

## Events

The issuer records Kubernetes events for things that do not stop a certificate being issued, but that you should act on. `kubectl describe` on the issuer shows them.

| Reason | Type | On | Meaning |
|---|---|---|---|
| `CAKeyExportable` | Warning | issuer | The CA key can be exported from Key Vault. See [Keep the key non-exportable](configuration.md#keep-the-key-non-exportable). |
| `CAExpiring` | Warning | issuer | The CA chain expires within `--ca-expiry-warning-threshold`. Recorded when a certificate is signed. |
| `CertificateClamped` | Warning | issuer | A certificate's lifetime was cut back to the expiry of the CA chain. The CA needs renewing. |
| `DurationClamped` | Normal | CertificateRequest | The requested duration was longer than the issuer's `maxDuration`. |

Kubernetes keeps events for about an hour, so do not rely on them to alert. See [CA expiry](#ca-expiry).

## When things go wrong

Start with the issuer, then the request:

```console
kubectl describe azurekeyvaultclusterissuer my-ca
kubectl --namespace team-a describe certificaterequest <name>
```

Errors fall into three classes, which decide how they are retried:

| Class | Examples | Behaviour |
|---|---|---|
| Permanent | An invalid issuer spec, a request the policy refuses, a namespace that is not allowed | The request fails, or the issuer is not `Ready`, until something changes. |
| Retry slowly | A Key Vault certificate that is missing, expired or unusable, a missing vault permission or rejected credential, a missing Secret | Retried every five minutes, as nothing announces the fix. |
| Backoff | Throttling, a 5xx response, a network failure | Retried with backoff, and failed five minutes after the request was created. |

Messages from Azure are flattened to one line and cut to 800 bytes, to fit a status condition and an event.

Common causes:

| Symptom | Likely cause |
|---|---|
| A CertificateRequest stays unapproved, and the controller logs nothing | Nothing has approved it. The chart's `approverRole` lets cert-manager approve, and approver-policy needs the same `approve` rule. |
| The issuer is not `Ready`, with `Forbidden` | The controller may not read the Secret or create the ServiceAccount token in that namespace. Check `rbac.secretNamespaces`. |
| The issuer is not `Ready`, with a `403` from Key Vault | The identity lacks a vault permission. See [the permissions](configuration.md#the-key-vault-certificate). |
| The issuer is not `Ready`, with a `401` or an Entra error | The credential is rejected: a wrong client ID or tenant, an expired secret or certificate, or a federated credential with the wrong subject. |
| A request is denied or failed | It asks for something the issuer's policy does not allow, or comes from a namespace the ClusterIssuer does not allow. The message says which. |

For more detail, raise the log level with `--zap-log-level=debug` (the chart's `logging.level`). Azure SDK requests and retries are logged at levels 1 and 2. Logs never hold secret data or tokens. For how errors and logs are written, see [errors-and-logging.md](errors-and-logging.md).

## Limitations

* **There is no revocation.** Keep `maxDuration` short.
* **Only the cert-manager CertificateRequest API is supported**, not Kubernetes CertificateSigningRequests.
* **The CA is not set on the CertificateRequest** (`ca.crt`), as issuer-lib discourages it. Distribute it with a tool such as [trust-manager](https://cert-manager.io/docs/trust/trust-manager/).
* **Only the Azure public cloud** is supported.
* **The credential is rebuilt on every check and signing**, so each costs a Secret read and a token exchange. A rotated Secret or revoked identity takes effect at once.

### CA expiry

An issuer never issues a certificate that outlives its CA chain. As the CA nears expiry, issued certificates get shorter and renewals come faster, until the issuer stops working. The issuer records `CAExpiring` and `CertificateClamped` events, but only when it signs, and Kubernetes drops them after about an hour. An idle issuer says nothing.

So monitor the expiry of the CA certificate in Key Vault itself, for example with Azure Monitor or Event Grid certificate-near-expiry events.
