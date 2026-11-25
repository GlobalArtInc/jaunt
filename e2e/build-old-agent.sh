#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
engine=${CONTAINER_ENGINE:-podman}
commit=22aea3856164f60901c68ce5572e912b95fa0cdc
cache=$repo/target/e2e/old-agent/$commit
if [ -x "$cache/jaunt-agent" ]; then
  echo "the agent of $commit is cached in $cache"
  exit 0
fi
if ! git -C "$repo" cat-file -e "$commit^{commit}" 2>/dev/null; then
  echo "the commit $commit is not in this clone: fetch the full history (fetch-depth: 0 in CI)" >&2
  exit 1
fi
full=$commit
source_dir=$repo/target/e2e/old-agent-src/$commit
mkdir -p "$source_dir"
git -C "$repo" archive "$full" | tar -x -C "$source_dir"
mkdir -p "$source_dir/target"
if [ -d "$repo/target/cargo-home" ] && [ ! -e "$source_dir/target/cargo-home" ]; then
  ln -s "$repo/target/cargo-home" "$source_dir/target/cargo-home"
fi
(
  tooling=$repo/scripts/linux-build.sh
  repo=$source_dir
  source "$tooling"
  build_linux_binaries -p jaunt-agent
)
mkdir -p "$cache"
cp "$source_dir/target/installer-linux/release/jaunt-agent" "$cache/jaunt-agent.tmp"
chmod 0755 "$cache/jaunt-agent.tmp"
mv "$cache/jaunt-agent.tmp" "$cache/jaunt-agent"
rm -rf "$source_dir"
echo "built the agent of $full into $cache"
