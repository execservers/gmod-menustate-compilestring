#!/usr/bin/env bash
# Return build-time TLS SPKI pins for GitHub API and common release CDNs.
# Certificate chains are checked against the runner's CA store and hostname.
set -euo pipefail

hosts=(
  api.github.com
  github.com
  release-assets.githubusercontent.com
  objects.githubusercontent.com
)

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
entries=()
for host in "${hosts[@]}"; do
  response="$scratch/$host.tls"
  if ! timeout 20 openssl s_client \
      -connect "$host:443" -servername "$host" \
      -verify_hostname "$host" -verify_return_error -showcerts \
      </dev/null >"$response" 2>"$scratch/$host.err"; then
    echo "Unable to verify TLS certificate for $host" >&2
    cat "$scratch/$host.err" >&2
    exit 1
  fi

  # Keep leaf and first intermediate SPKIs (when supplied). Root pins are
  # deliberately excluded. Intermediate gives resilience to leaf rotation.
  awk -v prefix="$scratch/$host" '
    /-----BEGIN CERTIFICATE-----/ { count++; file = prefix "-" count ".pem" }
    count > 0 && count <= 2 { print > file }
    /-----END CERTIFICATE-----/ { close(file) }
  ' "$response"

  pins=()
  for n in 1 2; do
    pem="$scratch/$host-$n.pem"
    if [[ ! -s "$pem" ]]; then continue; fi
    pin="$(openssl x509 -in "$pem" -pubkey -noout | \
       openssl pkey -pubin -outform DER | \
       openssl dgst -sha256 -binary | openssl base64 -A)"
    if [[ -z "$pin" ]]; then
      echo "Failed to compute SPKI pin for $host" >&2
      exit 1
    fi
    pins+=("$pin")
  done
  if [[ ${#pins[@]} -eq 0 ]]; then
    echo "No verified TLS certificate for $host" >&2
    exit 1
  fi
  joined="$(IFS=,; echo "${pins[*]}")"
  entries+=("$host=$joined")
done
IFS=';'; echo "${entries[*]}"
