#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
engine=${CONTAINER_ENGINE:-podman}
rust_image=${RELEASE_RUST_IMAGE:-docker.io/library/rust:1.99.1-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383}
out_dir=${2:-$repo/dist}
macos_deployment_target=11.0

usage() {
  echo "usage: $0 <x86_64-unknown-linux-musl|aarch64-unknown-linux-musl|x86_64-apple-darwin|aarch64-apple-darwin> [out-dir]" >&2
  exit 2
}

[ $# -ge 1 ] || usage
target=$1

case "$target" in
  x86_64-unknown-linux-musl)
    platform=linux/amd64
    packages=(jaunt-agent jaunt jauntd)
    ;;
  aarch64-unknown-linux-musl)
    platform=linux/arm64
    packages=(jaunt-agent jaunt jauntd)
    ;;
  x86_64-apple-darwin | aarch64-apple-darwin)
    platform=
    packages=(jaunt)
    ;;
  *) usage ;;
esac

channel=$(sed -n 's/^channel *= *"\(.*\)"$/\1/p' "$repo/rust-toolchain.toml")
if [ -z "$channel" ]; then
  echo "cannot read the toolchain channel from rust-toolchain.toml" >&2
  exit 2
fi

workspace_version() {
  sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"$/\1/p' "$repo/Cargo.toml" | head -n 1
}

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$repo" log -1 --format=%ct)
fi
export SOURCE_DATE_EPOCH

if [ -z "${VERSION:-}" ]; then
  VERSION=$(workspace_version)-$(git -C "$repo" rev-parse --short=7 HEAD)
fi

version_pattern='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
if [[ $VERSION == *$'\n'* || $VERSION == *$'\r'* || ${#VERSION} -gt 64 || ! $VERSION =~ $version_pattern ]]; then
  echo "invalid release version; expected 1.2.3 or 1.2.3-rc.1" >&2
  exit 2
fi

case "$out_dir" in
  "" | / | . | .. | "$repo" | "$HOME")
    echo "refusing to use '$out_dir' as the output directory" >&2
    exit 2
    ;;
esac

build_dir=$repo/target/release-build/$target
stage_dir=$build_dir/stage
rm -rf "$stage_dir"
mkdir -p "$build_dir" "$out_dir"

package_args=()
for package in "${packages[@]}"; do
  package_args+=(-p "$package")
done

build_linux() {
  local image_channel=${rust_image#*rust:}
  image_channel=${image_channel%%-*}
  if [ "$image_channel" != "$channel" ]; then
    echo "the Rust image ($image_channel) does not match rust-toolchain.toml ($channel)" >&2
    exit 2
  fi
  local flags="-C target-feature=+crt-static --remap-path-prefix=/src=/jaunt --remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/usr/local/rustup=/rustup"
  local owner=()
  if [ "$engine" = docker ]; then
    owner=(-e "CHOWN_TO=$(id -u):$(id -g)")
  fi
  echo "building $target in $rust_image"
  "$engine" run --rm --platform "$platform" --security-opt label=disable \
    -v "$repo:/src:ro" -w /src \
    -v "$build_dir:/work" \
    -v jaunt-release-cargo-registry:/usr/local/cargo/registry \
    -v jaunt-release-cargo-git:/usr/local/cargo/git \
    -e CARGO_TARGET_DIR=/work/target \
    -e CARGO_INCREMENTAL=0 \
    -e CARGO_TERM_COLOR=never \
    -e "RUSTUP_TOOLCHAIN=$channel" \
    -e "RUSTFLAGS=$flags" \
    -e SOURCE_DATE_EPOCH \
    ${owner[@]+"${owner[@]}"} \
    "$rust_image" sh -eu -c '
      triple=$1
      shift
      cargo build --locked --profile dist --target "$triple" "$@"
      mkdir -p /work/stage
      for name in jaunt-agent jaunt jauntd; do
        if [ -f "/work/target/$triple/dist/$name" ]; then
          install -m 0755 "/work/target/$triple/dist/$name" "/work/stage/$name"
        fi
      done
      if [ -n "${CHOWN_TO:-}" ]; then
        chown -R "$CHOWN_TO" /work
      fi
    ' sh "$target" "${package_args[@]}"
}

build_macos() {
  if [ "$(uname -s)" != Darwin ]; then
    echo "$target can only be built on macOS" >&2
    exit 2
  fi
  local sysroot cargo_home flags package
  if ! rustup target list --installed --toolchain "$channel" 2>/dev/null | grep -qx "$target"; then
    rustup toolchain install "$channel" --profile minimal --target "$target"
  fi
  sysroot=$(RUSTUP_TOOLCHAIN=$channel rustc --print sysroot)
  cargo_home=${CARGO_HOME:-$HOME/.cargo}
  flags="--remap-path-prefix=$repo=/jaunt --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot=/rustup"
  echo "building $target"
  (
    cd "$repo"
    export RUSTUP_TOOLCHAIN=$channel
    export RUSTFLAGS=$flags
    export MACOSX_DEPLOYMENT_TARGET=$macos_deployment_target
    export CARGO_INCREMENTAL=0
    export CARGO_TARGET_DIR=$build_dir/target
    cargo build --locked --profile dist --target "$target" "${package_args[@]}"
  )
  mkdir -p "$stage_dir"
  for package in "${packages[@]}"; do
    install -m 0755 "$build_dir/target/$target/dist/$package" "$stage_dir/$package"
  done
}

case "$target" in
  *-linux-musl) build_linux ;;
  *-apple-darwin) build_macos ;;
esac

binaries=()
for package in "${packages[@]}"; do
  if [ ! -f "$stage_dir/$package" ]; then
    echo "the build did not produce $package" >&2
    exit 1
  fi
  binaries+=("$stage_dir/$package")
done

python3 -I "$repo/scripts/release-package.py" \
  --version "$VERSION" --target "$target" --epoch "$SOURCE_DATE_EPOCH" \
  --license "$repo/LICENSE" --out "$out_dir" "${binaries[@]}"

echo "artifacts for $target are in $out_dir"
ls -l "$out_dir"
