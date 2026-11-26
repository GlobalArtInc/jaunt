#!/usr/bin/env bash
set -euo pipefail

status=0

while read -r package forbidden; do
  deps=$(cargo tree -p "$package" -e normal --prefix none --locked | awk '{print $1}' | sort -u)
  for bad in $forbidden; do
    if grep -qxF -- "$bad" <<<"$deps"; then
      echo "boundary violation: $package depends on $bad"
      status=1
    fi
  done
done <<'RULES'
jaunt-limits jaunt-proto jaunt-ca jaunt-store jaunt-control jaunt-gate jaunt-tunnel jaunt-ssh jaunt-agent jaunt-oidc jaunt-audit jaunt-policy jaunt-record jaunt-web
jaunt-policy jaunt-ca jaunt-store
jaunt-oidc jaunt-ca jaunt-store
jaunt-tunnel jaunt-ca jaunt-store
jaunt-ssh jaunt-ca jaunt-store
jaunt-store jaunt-ca
jaunt-audit jaunt-ca
jaunt-record jaunt-ca jaunt-store jaunt-audit jaunt-control jaunt-oidc jaunt-policy jaunt-tunnel jaunt-ssh jaunt-gate
jaunt-gate jaunt-ca jaunt-store
jaunt-agent jaunt-ca jaunt-store jaunt-control jaunt-oidc jaunt-audit
jaunt jaunt-ca jaunt-store jaunt-control jaunt-audit
jaunt-kube jaunt-ca jaunt-store jaunt-control jaunt-gate
jaunt-pgwire jaunt-ca jaunt-store jaunt-control jaunt-gate
jaunt-agent jaunt-recording-s3
jaunt jaunt-recording-s3
jaunt-control jaunt-recording-s3
jaunt-audit jaunt-recording-s3
jaunt-oidc jaunt-recording-s3
jaunt-policy jaunt-recording-s3
jaunt-ssh jaunt-recording-s3
jaunt-tunnel jaunt-recording-s3
jaunt-gate jaunt-recording-s3
jaunt-web jaunt-recording-s3
jaunt-limits jaunt-recording-s3
jaunt-proto jaunt-recording-s3
jaunt-ca jaunt-recording-s3
jaunt-store jaunt-recording-s3
jaunt-record jaunt-recording-s3
jaunt-kube jaunt-recording-s3
jaunt-pgwire jaunt-recording-s3
jaunt-recording-s3 jaunt-ca jaunt-control jaunt-oidc jaunt-policy jaunt-tunnel jaunt-ssh jaunt-gate jaunt-agent jaunt-web
jaunt-host-users jaunt jauntd jaunt-agent jaunt-audit jaunt-ca jaunt-control jaunt-fake-idp jaunt-gate jaunt-limits jaunt-oidc jaunt-policy jaunt-record jaunt-recording-s3 jaunt-ssh jaunt-store jaunt-tunnel jaunt-web tokio async-std smol async-executor futures-executor mio hyper h2 reqwest rustls openssl native-tls russh ssh-key
RULES

metadata=$(cargo metadata --format-version 1 --no-deps --locked)

while read -r package kind allowed; do
  actual=$(python3 -I -c '
import json, sys
package, kind = sys.argv[1], sys.argv[2]
packages = json.load(sys.stdin)["packages"]
matches = [entry for entry in packages if entry["name"] == package]
if len(matches) != 1:
    sys.exit(f"package {package} not found exactly once in cargo metadata")
wanted = None if kind == "normal" else kind
print(",".join(sorted({dep["name"] for dep in matches[0]["dependencies"] if dep["kind"] == wanted})))
' "$package" "$kind" <<<"$metadata")
  if [ "$actual" != "${allowed#-}" ]; then
    echo "boundary violation: $package $kind dependencies are [$actual], only [${allowed#-}] are allowed"
    status=1
  fi
done <<'ALLOWED'
jaunt-host-users normal jaunt-proto,rustix,serde,serde-saphyr,serde_json,thiserror
jaunt-host-users dev rustix,tempfile
jaunt-host-users build -
ALLOWED

exit "$status"
