#!/usr/bin/env bash
# Writes the e2e root's outputs as files for mise to load into every task, so
# the suite and the other scripts need nothing passed to them:
#
#   .e2e/infra.env
#   .e2e/secrets.env
#   .e2e/client.crt, .e2e/client.key
set -euo pipefail

state_dir=".e2e"
tf="$(dirname "$0")/terraform.sh"

mkdir -p "$state_dir"

# KEY=value lines from a JSON object of strings.
env_lines() {
  jq -r 'to_entries[] | "\(.key)=\(.value)"'
}

"$tf" output -json env | env_lines > "$state_dir/infra.env"

umask 077
"$tf" output -json secret_env | env_lines > "$state_dir/secrets.env"

if [[ "$("$tf" output -json client_certificate_pem)" != "null" ]]; then
  "$tf" output -raw client_certificate_pem > "$state_dir/client.crt"
  "$tf" output -raw client_private_key_pem > "$state_dir/client.key"
  {
    echo "E2E_CLIENT_CERT_FILE=$PWD/$state_dir/client.crt"
    echo "E2E_CLIENT_KEY_FILE=$PWD/$state_dir/client.key"
  } >> "$state_dir/secrets.env"
fi

echo "wrote $state_dir/infra.env and $state_dir/secrets.env"
