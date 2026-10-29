# Provisioning the CA

The issuer signs with a CA key that stays in Azure Key Vault. This page covers
making that CA, which is your job rather than the issuer's: the issuer only
reads a Key Vault *certificate* and asks Key Vault to sign with its key.

For a first try, [make an evaluation CA](#trying-it-out-an-evaluation-ca) with a
throwaway root. **Do not use it in production.**

## What the issuer needs

A Key Vault certificate, in a Standard or Premium vault with Azure RBAC, that is:

- **a CA**: the certificate has basic constraints `CA:TRUE` and the key usage
  `keyCertSign`, and is currently valid;
- **backed by a key it can use**: RSA 2048, 3072 or 4096, or EC P-256, P-384 or
  P-521, in software or in an HSM (a Premium vault). Managed HSM is not
  supported, because it has no certificate objects;
- **not exportable** (strongly recommended): the key is generated in Key Vault with
  `exportable: false` and never leaves it. The issuer enforces this only for
  `chainSource: Secret`, where it refuses an exportable certificate. A certificate's policy has no setting for the key's
  permitted operations: Key Vault derives them from the certificate's key usage,
  so keep that to `keyCertSign`, `cRLSign` and `digitalSignature`, as the
  policy below does;
- **in a version that is enabled and issued**: not disabled, and not still
  waiting for its signed certificate.

The issuer checks that the certificate is an issued, enabled, currently valid CA
with a supported key (and, for `chainSource: Secret`, the rules above) when an
issuer is created or changed and on every certificate, and says what is wrong in the issuer's `Ready` condition (see
[troubleshooting](troubleshooting.md)).

## Production: a subordinate CA from your own PKI

Have your organisation's existing PKI sign the Key Vault CA as a subordinate.
Key Vault makes the key pair and a signing request, so the key never exists
anywhere else.

Key Vault cannot create a certificate that is itself a CA: a self-signed
certificate always comes back `CA:FALSE`, which the issuer rejects. The signature
has to come from outside, which is why the flow has three steps.

1. **Create the certificate with an unknown issuer.** Key Vault generates the key
   and a pending certificate. Save this policy as `policy.json`, changing the
   subject, the key type and the lifetime to suit:

   ```json
   {
     "issuerParameters": { "name": "Unknown" },
     "keyProperties": {
       "exportable": false,
       "keyType": "EC",
       "curve": "P-256",
       "reuseKey": false
     },
     "secretProperties": { "contentType": "application/x-pem-file" },
     "x509CertificateProperties": {
       "subject": "CN=Example CA",
       "validityInMonths": 12,
       "keyUsage": ["cRLSign", "digitalSignature", "keyCertSign"]
     }
   }
   ```

   ```sh
   az keyvault certificate create --vault-name my-ca-vault --name issuing-ca \
     --policy @policy.json
   ```

   Use `"keyType": "EC-HSM"` or `"RSA-HSM"` for an HSM-backed key in a Premium
   vault. Keep `"exportable": false` and `"issuerParameters": {"name": "Unknown"}`
   (which makes the certificate wait for your PKI's signature), and the PEM content
   type, which `chainSource: Secret` requires.

2. **Get the signing request, and have your PKI sign it as a CA.**

   ```sh
   { echo "-----BEGIN CERTIFICATE REQUEST-----"
     az keyvault certificate pending show --vault-name my-ca-vault --name issuing-ca \
       --query csr -o tsv
     echo "-----END CERTIFICATE REQUEST-----"; } > issuing-ca.csr
   ```

   Constrain what you ask for, since this CA can sign for as long as it is
   trusted:

   - **a path length of 0**, so it cannot make further CAs. The issuer then
     refuses every CA request, even with `spec.policy.allowCA: true`, because
     clients would reject any CA it issued. If it must issue CAs, ask for a
     path length of one more than the depth you need: a CA with path length N
     issues CAs with at most N - 1;
   - **name constraints**, where your PKI can express them, limiting it to the
     DNS names it should issue for;
   - **a lifetime** you are happy to rotate, and shorter than its parent's.

3. **Merge the signed certificate, with its chain, back into Key Vault.** Put the
   new certificate first, then each issuer up to the root.

   ```sh
   cat issuing-ca.pem intermediate.pem root.pem > merge.pem
   az keyvault certificate pending merge --vault-name my-ca-vault --name issuing-ca \
     --file merge.pem
   ```

4. **Give clients the root.** Certificates this issuer signs only mean something
   to clients that trust your root. Distribute it, and any intermediates, with
   [trust-manager](trust-manager.md) or however your organisation does it.

Then create an issuer that points at it:

```yaml
apiVersion: azure-keyvault-issuer.mike-guy.github.io/v1alpha1
kind: AzureKeyVaultClusterIssuer
metadata:
  name: internal-ca
spec:
  vaultURL: https://my-ca-vault.vault.azure.net/
  certificateName: issuing-ca
```

## Trying it out: an evaluation CA

**For evaluation and development only.** Nothing outside your test cluster should
trust this CA: its root is made on your machine, and its key is thrown away. It
follows the production flow, with a local root in place of your PKI, because Key
Vault cannot sign a CA certificate itself.

You need `az`, `openssl` and **Key Vault Certificates Officer** on the vault. Do
step 1 of the production flow with the policy above (use `my-test-vault` and a
certificate name such as `example-ca`), then sign the request with a throwaway root
and merge the result:

```sh
{ echo "-----BEGIN CERTIFICATE REQUEST-----"
  az keyvault certificate pending show --vault-name my-test-vault --name example-ca \
    --query csr -o tsv
  echo "-----END CERTIFICATE REQUEST-----"; } > example-ca.csr

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj "/CN=Example root (evaluation only)" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout root.key -out root.pem

printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\n' > ca.ext
openssl x509 -req -in example-ca.csr -CA root.pem -CAkey root.key \
  -CAcreateserial -days 180 -extfile ca.ext -out example-ca.pem

cat example-ca.pem root.pem > merge.pem
az keyvault certificate pending merge --vault-name my-test-vault --name example-ca \
  --file merge.pem

rm root.key   # discard the root's key; keep root.pem for clients to trust
```

The CA has a path length of 0 and lasts 180 days, inside its root's 365. Give
clients `root.pem` (for example with [trust-manager](trust-manager.md)). Because
the root's key is gone, rotating the evaluation CA means making a new root and
distributing it.

## The certificate chain

Each issued certificate comes back with the Key Vault CA appended, so clients
can build the chain. What else is appended depends on `spec.chainSource`:

- **`Certificate`** (the default) suits a two-tier PKI: an offline root and the
  Key Vault CA. The chain is the Key Vault CA's own certificate. The root is
  **not** included: clients get it from trust-manager.
- **`Secret`** suits a deeper PKI: root, one or more intermediates, then the Key
  Vault CA. When you merge a signed certificate, Key Vault keeps the whole chain
  in the certificate's backing secret, and the issuer reads that, so the chain
  stays right after a rotation. It needs one more permission (see
  [Azure setup](azure-setup.md)), and the issuer refuses to read the secret
  unless the key is non-exportable and the content type is PEM, because the
  secret of an exportable certificate would hold the private key.

## Importing an existing CA key

Key Vault can import a CA certificate with its private key. Avoid it: the key has
already existed outside an HSM, so you are trusting every place it has been.
If you must, import it with `exportable: false` so Key Vault will not give it
back, and consider the old copies of the key compromised for the purposes of
how long you rely on them.

## Public trust

Certificates from this issuer are for **private trust**: internal services, mTLS
and service meshes. Publicly trusted CAs do not issue subordinate CAs to
ordinary organisations (the CA/Browser Forum rules forbid it), so you cannot make
browsers trust this one. For certificates the public internet trusts, use ACME,
for example Let's Encrypt through cert-manager's ACME issuer.

## Rotation

Rotate well before the CA expires. No certificate the issuer signs outlives its
CA chain (the Key Vault CA, or a certificate above it that expires first), so as
expiry nears, every certificate it issues gets shorter and renewals come faster.
Within 30 days of expiry the issuer records a `CAExpiringSoon` warning event on
itself, and the `azure_keyvault_issuer_ca_expiration_timestamp_seconds` metric
lets you alert on it ([Metrics](metrics.md#alerting-on-ca-expiry)). Key Vault can
also email the vault's contacts before a certificate expires (a certificate
policy lifetime action).

A new CA means a new version of the Key Vault certificate, a new key, and a new
signature from your PKI. Plan it so that nothing issued in the meantime fails:

1. **Pin the issuers to the current version first.** With no
   `spec.certificateVersion`, the issuer uses Key Vault's *current* version, and
   a new version is current the moment you create it, while it is still
   pending. The issuer fails closed on a pending or disabled current version
   rather than quietly using an older CA, so unpinned issuers stop issuing.

   ```sh
   az keyvault certificate show --vault-name my-ca-vault --name issuing-ca --query id -o tsv
   # https://my-ca-vault.vault.azure.net/certificates/issuing-ca/<version>
   ```

   Set the last part as `spec.certificateVersion` on every issuer that uses it.
2. **Create the new version, have it signed and merge it**, as above. The new key
   is generated in Key Vault, as before.
3. **Distribute trust** for the new CA's chain, and wait until clients have it.
   For a new CA under the same root, there is nothing to distribute.
4. **Cut over**: set `spec.certificateVersion` to the new version, or remove it to
   follow the current version again.
5. **Retire the old version** once nothing it signed is still in use, by
   disabling it:

   ```sh
   az keyvault certificate set-attributes --vault-name my-ca-vault --name issuing-ca \
     --version <old version> --enabled false
   ```

Certificates already issued stay valid until they expire, and cert-manager
renews them from the CA the issuer is using at the time. The issuer fetches the CA
on every request, so a change takes effect on the next certificate with no delay.
