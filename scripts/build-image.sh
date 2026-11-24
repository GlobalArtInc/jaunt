#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
engine=${CONTAINER_ENGINE:-podman}
tag=${IMAGE_TAG:-jaunt:dev}
binaries_dir=${BINARIES_DIR:-$repo/target/image-binaries}
rust_args=()

select_rust_image() {
  if [ -n "${IMAGE_RUST_IMAGE:-}" ]; then
    printf '%s' "$IMAGE_RUST_IMAGE"
    return
  fi
  local channel exact minor
  channel=$(sed -n 's/^channel *= *"\(.*\)"$/\1/p' "$repo/rust-toolchain.toml")
  if [ -z "$channel" ]; then
    echo "cannot read the toolchain channel from rust-toolchain.toml" >&2
    exit 2
  fi
  exact=docker.io/library/rust:${channel}-bookworm
  minor=docker.io/library/rust:${channel%.*}-bookworm
  if "$engine" image inspect "$exact" >/dev/null 2>&1; then
    printf '%s' "$exact"
  elif "$engine" image inspect "$minor" >/dev/null 2>&1; then
    printf '%s' "$minor"
  fi
}

choose_rust_image() {
  local image
  image=$(select_rust_image)
  if [ -n "$image" ]; then
    rust_args=(--build-arg "RUST_IMAGE=$image")
    echo "building in the local $image" >&2
  else
    echo "building in the Rust image pinned in the Dockerfile" >&2
  fi
}

build_image() {
  local revision
  revision=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)
  choose_rust_image
  "$engine" build --target jauntd ${rust_args[@]+"${rust_args[@]}"} \
    --build-arg "REVISION=$revision" \
    --build-arg "CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -t "$tag" "$repo"
}

engine_is_remote() {
  [ "$engine" = podman ] && [ "$("$engine" info --format '{{.Host.ServiceIsRemote}}')" = true ]
}

extract_binaries() {
  case "$binaries_dir" in
    "" | / | . | .. | "$repo" | "$HOME")
      echo "refusing to use '$binaries_dir' as the output directory" >&2
      exit 2
      ;;
  esac
  choose_rust_image
  rm -rf "$binaries_dir"
  mkdir -p "$binaries_dir"
  if engine_is_remote; then
    local staging container
    staging=jaunt-binaries:staging
    "$engine" build --target binaries ${rust_args[@]+"${rust_args[@]}"} -t "$staging" "$repo"
    container=$("$engine" create "$staging" /jauntd)
    "$engine" cp "$container:/." "$binaries_dir"
    "$engine" rm "$container" >/dev/null
    "$engine" rmi "$staging" >/dev/null
  else
    "$engine" build --target binaries ${rust_args[@]+"${rust_args[@]}"} \
      --output "type=local,dest=$binaries_dir" "$repo"
  fi
  echo "binaries are in $binaries_dir"
}

case "${1:-}" in
  image) build_image ;;
  binaries) extract_binaries ;;
  *)
    echo "usage: $0 image|binaries" >&2
    exit 2
    ;;
esac
