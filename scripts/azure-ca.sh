#!/usr/bin/env bash
# Makes the CA certificates in the e2e vault, each with a key that is
# non-exportable. Safe to run again. The vault is Terraform's, so this needs
# e2e:infra:apply to have run.
#
# Five CAs are made, so that the suite can test both shapes of chain, the kinds
# of key that Key Vault signs with, and the warning that the issuer records
# about an exportable key:
#
#   e2e-ca             root -> Key Vault CA
#   e2e-ca-chain       root -> intermediate 1 -> intermediate 2 -> Key Vault CA
#   e2e-ca-exportable  as e2e-ca, but the key can be exported (CAKeyExportable)
#   e2e-ca-rsa         as e2e-ca, with an RSA 2048 key in place of ECDSA P-256
#   e2e-ca-p384        as e2e-ca, with an ECDSA P-384 key
#
set -euo pipefail

if [[ -z "${E2E_VAULT_NAME:-}" && -f .e2e/infra.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .e2e/infra.env
  set +a
fi

: "${E2E_AZURE_SUBSCRIPTION:?not set, run this with mise}"
: "${E2E_VAULT_NAME:?not set, run e2e:infra:apply first}"
: "${E2E_CA_CERTIFICATE_NAME:?not set, run e2e:infra:apply first}"

state_dir=".e2e"
vault="$E2E_VAULT_NAME"
chain_cert_name="${E2E_CA_CERTIFICATE_NAME}-chain"
exportable_cert_name="${E2E_CA_CERTIFICATE_NAME}-exportable"
rsa_cert_name="${E2E_CA_CERTIFICATE_NAME}-rsa"
p384_cert_name="${E2E_CA_CERTIFICATE_NAME}-p384"
ec_key='"keyType": "EC", "curve": "P-256"'

az_sub=(--subscription "$E2E_AZURE_SUBSCRIPTION")

# retry runs a command until it succeeds, for up to two minutes. A role
# assignment on a new vault takes a while to be effective.
retry() {
  for _ in $(seq 1 24); do
    "$@" && return 0
    sleep 5
  done
  return 1
}

# make_ca NAME SUBJECT CA_PATHLEN INTERMEDIATES ROOT_FILE EXPORTABLE DAYS KEY
#
# Makes the certificate NAME in the vault, with a Key Vault CA whose path length
# is CA_PATHLEN, below INTERMEDIATES intermediate CAs and a root, which is kept
# in ROOT_FILE. The merged chain holds the intermediates, and the root only when
# there are none, as consumers already trust a root. The key is exportable if
# EXPORTABLE is true, and the Key Vault CA is valid for DAYS. KEY is the Key
# Vault key properties, such as '"keyType": "EC", "curve": "P-256"'.
make_ca() {
  local cert_name="$1" subject="$2" ca_pathlen="$3" intermediates="$4" root_file="$5" exportable="$6" days="$7" key="$8"

  echo "== CA certificate $cert_name in $vault"
  # A request that was never merged shows too, but has no certificate yet.
  local issued
  issued="$(az keyvault certificate show "${az_sub[@]}" --vault-name "$vault" --name "$cert_name" --query cer --output tsv 2>/dev/null || true)"
  if [[ -n "$issued" ]]; then
    [[ -f "$root_file" ]] \
      || { echo "$cert_name exists but $root_file does not: destroy the vault with e2e:infra:destroy, or delete the certificate and purge it" >&2; return 1; }
    return 0
  fi

  local work
  work="$(mktemp -d)"

  # A failed earlier run can leave a request that was never merged.
  az keyvault certificate pending delete "${az_sub[@]}" --vault-name "$vault" --name "$cert_name" --output none 2>/dev/null || true

  cat > "$work/policy.json" <<EOF
{
  "issuerParameters": { "name": "Unknown" },
  "keyProperties": { $key, "exportable": $exportable, "reuseKey": false },
  "secretProperties": { "contentType": "application/x-pem-file" },
  "x509CertificateProperties": {
    "subject": "$subject",
    "keyUsage": ["keyCertSign", "cRLSign"],
    "validityInMonths": 12
  }
}
EOF

  retry az keyvault certificate create "${az_sub[@]}" --vault-name "$vault" --name "$cert_name" \
    --policy "@$work/policy.json" --output none

  local csr
  csr="$(az keyvault certificate pending show "${az_sub[@]}" --vault-name "$vault" --name "$cert_name" --query csr --output tsv)"
  case "$csr" in
    -----BEGIN*) printf '%s\n' "$csr" > "$work/csr.pem" ;;
    *) { echo "-----BEGIN CERTIFICATE REQUEST-----"; printf '%s\n' "$csr" | fold -w 64; echo "-----END CERTIFICATE REQUEST-----"; } > "$work/csr.pem" ;;
  esac

  openssl ecparam -name prime256v1 -genkey -noout -out "$work/root.key"
  openssl req -x509 -new -key "$work/root.key" -sha256 -days 730 -subj "/CN=${subject#CN=} root" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out "$work/root.crt"

  # Each intermediate is signed by the one above it, starting from the root. Its path length lets
  # everything below it sign: the CAs under it, the Key Vault CA, and the CAs the Key Vault CA may sign.
  local signer_key="$work/root.key" signer_crt="$work/root.crt" i pathlen
  local chain=()
  for ((i = 1; i <= intermediates; i++)); do
    pathlen=$((ca_pathlen + 1 + intermediates - i))
    openssl ecparam -name prime256v1 -genkey -noout -out "$work/int$i.key"
    openssl req -new -key "$work/int$i.key" -subj "/CN=${subject#CN=} intermediate $i" -out "$work/int$i.csr"
    cat > "$work/int$i.ext" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:$pathlen
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
    openssl x509 -req -in "$work/int$i.csr" -CA "$signer_crt" -CAkey "$signer_key" -CAcreateserial \
      -days 365 -sha256 -extfile "$work/int$i.ext" -out "$work/int$i.crt"
    signer_key="$work/int$i.key"
    signer_crt="$work/int$i.crt"
    # The merged chain goes from the Key Vault CA upwards, so each intermediate comes before the last.
    chain=("$work/int$i.crt" ${chain[@]+"${chain[@]}"})
  done

  cat > "$work/ca.ext" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:$ca_pathlen
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
  openssl x509 -req -in "$work/csr.pem" -CA "$signer_crt" -CAkey "$signer_key" -CAcreateserial \
    -days "$days" -sha256 -extfile "$work/ca.ext" -out "$work/ca.crt"

  if ((intermediates == 0)); then
    chain=("$work/root.crt")
  fi
  cat "$work/ca.crt" "${chain[@]}" > "$work/bundle.pem"
  az keyvault certificate pending merge "${az_sub[@]}" --vault-name "$vault" --name "$cert_name" \
    --file "$work/bundle.pem" --output none

  cp "$work/root.crt" "$root_file"
  rm -rf "$work"
}

mkdir -p "$state_dir"

# A path length of 1 lets the CA issue end certificates, and a CA that has none below it.
make_ca "$E2E_CA_CERTIFICATE_NAME" "CN=akvi-e2e-ca" 1 0 "$state_dir/root-ca.crt" false 365 "$ec_key"
# A path length of 0 lets the CA issue end certificates only, as nothing below it needs to sign.
make_ca "$chain_cert_name" "CN=akvi-e2e-chain-ca" 0 2 "$state_dir/chain-root-ca.crt" false 365 "$ec_key"
make_ca "$exportable_cert_name" "CN=akvi-e2e-exportable-ca" 0 0 "$state_dir/exportable-root-ca.crt" true 365 "$ec_key"
make_ca "$rsa_cert_name" "CN=akvi-e2e-rsa-ca" 0 0 "$state_dir/rsa-root-ca.crt" false 365 '"keyType": "RSA", "keySize": 2048'
make_ca "$p384_cert_name" "CN=akvi-e2e-p384-ca" 0 0 "$state_dir/p384-root-ca.crt" false 365 '"keyType": "EC", "curve": "P-384"'

{
  echo "E2E_ROOT_CA_FILE=$PWD/$state_dir/root-ca.crt"
  echo "E2E_CHAIN_CA_CERTIFICATE_NAME=$chain_cert_name"
  echo "E2E_CHAIN_ROOT_CA_FILE=$PWD/$state_dir/chain-root-ca.crt"
  echo "E2E_EXPORTABLE_CA_CERTIFICATE_NAME=$exportable_cert_name"
  echo "E2E_EXPORTABLE_ROOT_CA_FILE=$PWD/$state_dir/exportable-root-ca.crt"
  echo "E2E_RSA_CA_CERTIFICATE_NAME=$rsa_cert_name"
  echo "E2E_RSA_ROOT_CA_FILE=$PWD/$state_dir/rsa-root-ca.crt"
  echo "E2E_P384_CA_CERTIFICATE_NAME=$p384_cert_name"
  echo "E2E_P384_ROOT_CA_FILE=$PWD/$state_dir/p384-root-ca.crt"
} > "$state_dir/ca.env"

echo "CAs ready in $vault"
