# Workload identity outside AKS

The controller signs in to Azure with a Kubernetes ServiceAccount token that
Microsoft Entra exchanges for an Azure token, so there is no client secret or
certificate to store. AKS publishes what Entra needs to trust those tokens. Any
other cluster, in another cloud or on-premises, can do the same by publishing it
itself. The end-to-end tests run exactly this on a kind cluster, so the steps below
are the tested ones.

## What Entra needs

When the controller presents a token, Entra:

1. reads the token's `iss` (issuer) claim, and looks for a federated credential on
   the identity with that issuer and the token's `sub` (the ServiceAccount);
2. fetches `<issuer>/.well-known/openid-configuration` and the keys it points to,
   from the **public internet**, with no credentials;
3. checks the token's signature with those keys.

So your cluster must:

- sign its ServiceAccount tokens with an **RSA** key (Entra accepts only `RS256`);
- advertise an **issuer URL** that is `https`, has no trailing slash, and serves
  two documents publicly;
- have those documents describe the key it really signs with.

The documents hold public keys only, so publishing them exposes nothing secret. The
cluster's API server does not need to be reachable from the internet, only the
two documents do.

If you cannot publish them at all, the issuer can instead sign in with an Entra
application's certificate or client secret from a Kubernetes Secret: see the
[fallbacks in Azure setup](azure-setup.md#6-fallbacks-a-client-certificate-or-client-secret).
Prefer publishing if you can, since that stores no credential.

## 1. Choose where to publish

Any static HTTPS host works: an Azure storage account's static website, a GitHub
Pages site, an object store behind a CDN. Say it is `https://oidc.example.com/my-cluster`.
That URL, with no trailing slash, is the **issuer**. Use a distinct path for each
cluster.

## 2. Make the API server sign with an RSA key and advertise the issuer

Start the API server with these flags. For kubeadm, put them in the
`ClusterConfiguration`'s `apiServer.extraArgs`, and mount the key files into the
control plane.

| Flag | Value |
|---|---|
| `--service-account-issuer` | the issuer URL, exactly as it is above |
| `--service-account-jwks-uri` | `<issuer>/openid/v1/jwks` |
| `--service-account-signing-key-file` | the RSA private key |
| `--service-account-key-file` | the matching public key |

The controller manager needs the private key too, as `--service-account-private-key-file`.

The key must be RSA: Kubernetes can also sign with ECDSA keys, which Entra does not
accept. Check what your cluster signs with: decode the header of a token from
`kubectl create token default`, which must say `"alg": "RS256"`. When you change
the signing key, keep the old public key in `--service-account-key-file` (it can be
repeated) until the tokens signed with it have expired.

kubeadm already generates an RSA service-account key (`sa.key`, RSA-2048 unless
the `ClusterConfiguration` sets another `encryptionAlgorithm`) and passes it with
the two key flags, so on a kubeadm cluster only the first two flags need setting.
The end-to-end tests do exactly that for kind, then copy the API server's own key
set as in step 3: see `kind/up` in
[`test/e2e/scripts/cluster.sh`](../test/e2e/scripts/cluster.sh), a worked example.

## 3. Publish the two documents

The **discovery document**, at `<issuer>/.well-known/openid-configuration`:

```json
{
  "issuer": "https://oidc.example.com/my-cluster",
  "jwks_uri": "https://oidc.example.com/my-cluster/openid/v1/jwks",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

The **key set**, at `<issuer>/openid/v1/jwks`, is the public half of the signing key
as a JSON Web Key Set, with `"use": "sig"` and `"alg": "RS256"` and a `kid` that
matches the `kid` in the tokens' headers.

If the API server already serves them, you can copy its own documents instead of
writing your own: `kubectl get --raw /.well-known/openid-configuration` and
`kubectl get --raw /openid/v1/jwks`. Check the discovery document's `issuer` and
`jwks_uri` before you publish it: they must be the URLs you publish at, not the
API server's own address.

Serve both with `Content-Type: application/json`. Check that they are public, and
that the issuer matches character for character:

```sh
curl -fsS https://oidc.example.com/my-cluster/.well-known/openid-configuration
curl -fsS https://oidc.example.com/my-cluster/openid/v1/jwks
```

## 4. Create the federated credential

Create the identity and its role as in [Azure setup](azure-setup.md), using your
issuer URL as `--issuer`. Then install the chart with `workloadIdentity.useWebhook: false`
(the default). The chart projects a token into the controller's pod with the audience
`api://AzureADTokenExchange`, so no webhook is needed, and a ServiceAccount
reference works the same way.

## When the keys change

If you replace the signing key, publish the new public key alongside the old one
before the API server starts signing with it, and remove the old one only once no
token signed with it is still valid. Tokens are short-lived: ten minutes for a
ServiceAccount reference, and by default an hour for the controller's own projected
token (`workloadIdentity.tokenExpirationSeconds`). Entra may cache the key set, so
leave some time between publishing a key and relying on it.

## If it does not work

An issuer that cannot sign in reports an `AADSTS` error, which says what Entra
disliked: an issuer that does not match, a signature it cannot verify with the
published keys, or a subject with no federated credential. See
[troubleshooting](troubleshooting.md).
