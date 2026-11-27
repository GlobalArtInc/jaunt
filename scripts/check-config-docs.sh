#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
doc=$repo/docs/configuration.md

sources=(
  crates/jauntd/src/config.rs
  crates/jauntd/src/audit.rs
  crates/jauntd/src/limits.rs
  crates/jauntd/src/recordings.rs
  crates/jauntd/src/web_terminal.rs
  crates/jaunt-agent/src/run/config.rs
  crates/jaunt-host-users/src/config.rs
  crates/jaunt-policy/src/raw.rs
)

camel() {
  awk '{
    n = split($0, parts, "_")
    out = parts[1]
    for (i = 2; i <= n; i++) out = out toupper(substr(parts[i], 1, 1)) substr(parts[i], 2)
    print out
  }'
}

fields() {
  awk '
    /^[[:space:]]*#\[serde\(.*deny_unknown_fields/ { armed = 1; next }
    /^[[:space:]]*#\[serde\(tag/ { armed = 0 }
    armed && /^[[:space:]]*(pub(\([a-z]+\))? )?struct [A-Za-z0-9_]+ *\{/ { inside = 1; armed = 0; next }
    inside && /^\}/ { inside = 0; next }
    inside && /^    (pub(\([a-z]+\))? )?[a-z_][a-z0-9_]*:/ {
      line = $0
      sub(/^    (pub(\([a-z]+\))? )?/, "", line)
      sub(/:.*/, "", line)
      print line
    }
  ' "$1"
}

missing=0
count=0
for source in "${sources[@]}"; do
  path=$repo/$source
  [ -f "$path" ] || { echo "missing source file: $source" >&2; exit 2; }
  names=$(fields "$path")
  if [ "$(basename "$source")" = raw.rs ]; then
    names=$(printf '%s\n' "$names" | camel)
  fi
  [ -n "$names" ] || { echo "no fields found in $source: the extractor is out of date" >&2; exit 2; }
  while IFS= read -r name; do
    count=$((count + 1))
    if ! grep -Eq "\`([a-z_.0-9]+\.)?$name\`" "$doc"; then
      echo "not documented: $name ($source)" >&2
      missing=$((missing + 1))
    fi
  done <<<"$names"
done

echo "checked $count fields from ${#sources[@]} files against docs/configuration.md"
[ "$missing" -eq 0 ] || exit 1
