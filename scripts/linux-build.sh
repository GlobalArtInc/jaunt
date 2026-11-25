select_rust_image() {
  if [ -n "${INSTALLER_RUST_IMAGE:-}" ]; then
    printf '%s' "$INSTALLER_RUST_IMAGE"
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
  else
    printf '%s' "$exact"
  fi
}

runs_as_host_user() {
  if [ -n "${LINUX_BUILD_AS_HOST_USER:-}" ]; then
    return 0
  fi
  if [ "$engine" = podman ]; then
    return 1
  fi
  ! "$engine" info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q rootless
}

build_linux_binaries() {
  local rust_image channel
  rust_image=$(select_rust_image)
  channel=$(sed -n 's/^channel *= *"\(.*\)"$/\1/p' "$repo/rust-toolchain.toml")
  mkdir -p "$repo/target/installer-linux"
  local -a identity=() cargo_home=(-v jaunt-installer-cargo-registry:/usr/local/cargo/registry)
  if runs_as_host_user; then
    mkdir -p "$repo/target/cargo-home"
    identity=(--user "$(id -u):$(id -g)" -e HOME=/tmp -e CARGO_HOME=/cargo-home -e "RUSTUP_TOOLCHAIN=$channel")
    cargo_home=(-v "$repo/target/cargo-home:/cargo-home")
  fi
  echo "building the Linux binaries in $rust_image"
  "$engine" run --rm --security-opt label=disable \
    ${identity[@]+"${identity[@]}"} \
    ${LINUX_BUILD_RUN_ARGS:-} \
    -v "$repo:/src" -w /src \
    "${cargo_home[@]}" \
    -e CARGO_TARGET_DIR=/src/target/installer-linux \
    -e CARGO_INCREMENTAL=0 \
    "$rust_image" cargo build --locked --release "$@"
}
