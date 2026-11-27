#!/usr/bin/env bash
set -euo pipefail

engine=${CONTAINER_ENGINE:-podman}
images=${VERIFY_IMAGES:-debian:12 debian:13 rockylinux:9 alpine:3.20 ubuntu:22.04 ubuntu:24.04}
installer_images=${VERIFY_INSTALLER_IMAGES:-debian:12 debian:13 rockylinux:9}
containers=${VERIFY_CONTAINERS:-1}
emulated=${VERIFY_EMULATED:-0}

if [ $# -ne 1 ] || [ ! -d "$1" ]; then
  echo "usage: $0 <release-directory>" >&2
  exit 2
fi
dir=$(cd "$1" && pwd)

failures=0
work_dirs=()
cleanup() {
  local path
  for path in ${work_dirs[@]+"${work_dirs[@]}"}; do
    rm -rf -- "${path:?}"
  done
}
trap cleanup EXIT
pass() { printf 'PASS %s\n' "$1"; }
fail() {
  printf 'FAIL %s\n' "$1"
  failures=$((failures + 1))
}

sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$@"
  else
    shasum -a 256 -c "$@"
  fi
}

check_checksums() {
  if [ ! -f "$dir/SHA256SUMS" ]; then
    fail "SHA256SUMS is missing"
    return
  fi
  if (cd "$dir" && sha256_check SHA256SUMS >/dev/null); then
    pass "SHA256SUMS matches the archives"
  else
    fail "SHA256SUMS does not match the archives"
  fi
  local listed present
  listed=$(awk '{print $2}' "$dir/SHA256SUMS" | LC_ALL=C sort)
  present=$(cd "$dir" && find . -maxdepth 1 -name '*.tar.gz' -exec basename {} \; | LC_ALL=C sort)
  if [ "$listed" = "$present" ]; then
    pass "SHA256SUMS lists every archive and nothing else"
  else
    fail "SHA256SUMS and the archives in the directory differ"
  fi
}

host_arch() {
  case "$(uname -m)" in
    arm64 | aarch64) echo aarch64 ;;
    x86_64 | amd64) echo x86_64 ;;
    *) uname -m ;;
  esac
}

container_check_script() {
  cat <<'SCRIPT'
set -eu
find_binary() {
  set -- /opt/jaunt/"$1"-*/"$1"
  if [ ! -x "$1" ]; then
    echo "missing binary for $1" >&2
    exit 1
  fi
  printf '%s' "$1"
}
agent=$(find_binary jaunt-agent)
helper=$(find_binary jaunt-host-users)
cli=$(find_binary jaunt)
daemon=$(find_binary jauntd)
for binary in "$agent" "$helper" "$cli" "$daemon"; do
  if [ "$binary" = "$helper" ]; then
    "$binary" --help
  else
    "$binary" --version
  fi
  if command -v ldd >/dev/null 2>&1; then
    listing=$(ldd "$binary" 2>&1 || true)
    case "$listing" in
      *"=>"*)
        echo "$binary is dynamically linked: $listing" >&2
        exit 1
        ;;
    esac
  fi
done
"$agent" enroll --help >/dev/null
"$agent" install --help >/dev/null
"$agent" uninstall --help >/dev/null
"$cli" login --help >/dev/null
"$daemon" --help >/dev/null
SCRIPT
}

check_in_image() {
  local target=$1 platform=$2 extract=$3 image=$4
  if container_check_script | "$engine" run --rm -i --platform "$platform" \
    --security-opt label=disable -v "$extract:/opt/jaunt:ro" "$image" sh -s >/dev/null; then
    pass "$target runs in $image"
  else
    fail "$target does not run in $image"
  fi
}

installer_check_script() {
  cat <<'SCRIPT'
set -eu
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends openssh-server >/dev/null
  mkdir -p /run/sshd
else
  dnf install -y -q openssh-server >/dev/null
fi
ssh-keygen -A >/dev/null
set -- /opt/jaunt/jaunt-agent-*/jaunt-agent
agent=$1
plan=$("$agent" install --dry-run --no-service)
case "$plan" in
  *"plan: run useradd"*) ;;
  *)
    echo "the dry run did not plan to create the missing service account" >&2
    exit 1
    ;;
esac
useradd -m -s /bin/bash jaunt
if refusal=$("$agent" install --dry-run --no-service 2>&1); then
  echo "the dry run accepted an ordinary account named jaunt" >&2
  exit 1
fi
case "$refusal" in
  *"already exists but is not a Jaunt service account"*"login shell is /bin/bash"*) ;;
  *)
    echo "unexpected refusal: $refusal" >&2
    exit 1
    ;;
esac
SCRIPT
}

check_installer_in_image() {
  local target=$1 platform=$2 extract=$3 image=$4
  if installer_check_script | "$engine" run --rm -i --platform "$platform" \
    --security-opt label=disable -v "$extract:/opt/jaunt:ro" "$image" sh -s >/dev/null; then
    pass "$target installer dry run finds accounts through getent in $image"
  else
    fail "$target installer dry run does not work in $image"
  fi
}

check_scratch() {
  local target=$1 platform=$2 extract=$3 tag=$4
  local context binary
  if ! binary=$(ls "$extract"/jaunt-agent-*/jaunt-agent 2>/dev/null); then
    fail "$target: the agent binary is missing from the archives"
    return
  fi
  context=$(mktemp -d)
  work_dirs+=("$context")
  cp "$binary" "$context/jaunt-agent"
  printf 'FROM scratch\nCOPY jaunt-agent /jaunt-agent\nENTRYPOINT ["/jaunt-agent"]\n' >"$context/Containerfile"
  if "$engine" build --quiet --platform "$platform" -t "$tag" -f "$context/Containerfile" "$context" >/dev/null \
    && "$engine" run --rm --platform "$platform" "$tag" --version >/dev/null; then
    pass "$target agent runs in an image with no libc at all"
  else
    fail "$target agent does not run in an image with no libc at all"
  fi
  "$engine" rmi --force "$tag" >/dev/null 2>&1 || true
}

check_file_kind() {
  local target=$1 extract=$2
  if ! command -v file >/dev/null 2>&1; then
    fail "$target: the file command is needed to check static linking"
    return
  fi
  local binary kind
  for binary in "$extract"/*/jaunt-agent "$extract"/*/jaunt-host-users "$extract"/*/jaunt "$extract"/*/jauntd; do
    kind=$(file -b "$binary")
    case "$kind" in
      *"statically linked"* | *"static-pie linked"*) pass "$target $(basename "$binary") is $(printf '%s' "$kind" | grep -o 'static[a-z-]* linked')" ;;
      *) fail "$target $(basename "$binary") is not static: $kind" ;;
    esac
  done
}

check_target() {
  local target=$1 arch=$2 platform=$3
  local work extract archive image
  work=$(mktemp -d)
  work_dirs+=("$work")
  extract=$work/extract
  mkdir -p "$extract"
  for archive in "$dir"/*-"$target".tar.gz; do
    if ! tar -xzf "$archive" -C "$extract"; then
      fail "$target: cannot unpack $(basename "$archive")"
      return
    fi
  done
  check_file_kind "$target" "$extract"
  check_scratch "$target" "$platform" "$extract" "jaunt-release-check:$arch"
  for image in $images; do
    check_in_image "$target" "$platform" "$extract" "$image"
  done
  for image in $installer_images; do
    check_installer_in_image "$target" "$platform" "$extract" "$image"
  done
}

check_checksums

if [ "$containers" = 1 ]; then
  native=$(host_arch)
  for arch in x86_64 aarch64; do
    target=$arch-unknown-linux-musl
    if ! ls "$dir"/*-"$target".tar.gz >/dev/null 2>&1; then
      continue
    fi
    if [ "$arch" != "$native" ] && [ "$emulated" != 1 ]; then
      echo "SKIP $target: not the host architecture (set VERIFY_EMULATED=1 to run it under emulation)"
      continue
    fi
    case "$arch" in
      x86_64) platform=linux/amd64 ;;
      aarch64) platform=linux/arm64 ;;
    esac
    check_target "$target" "$arch" "$platform"
  done
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
