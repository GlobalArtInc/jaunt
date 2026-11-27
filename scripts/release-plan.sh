#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest=${RELEASE_PLAN_CARGO_TOML:-$repo/Cargo.toml}
version_pattern='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
max_version_length=64

fail() {
  echo "error: $1" >&2
  exit 1
}

single_line() {
  [[ $1 != *$'\n'* && $1 != *$'\r'* ]]
}

valid_version() {
  single_line "$1" && [ "${#1}" -le "$max_version_length" ] && [[ $1 =~ $version_pattern ]]
}

event=${EVENT:-}
ref=${REF:-}
ref_name=${REF_NAME:-}
sha=${SHA:-}
input_version=${INPUT_VERSION:-}
input_publish=${INPUT_PUBLISH:-}
input_include_arm=${INPUT_INCLUDE_ARM:-}

single_line "$sha" && [[ $sha =~ ^[0-9a-f]{40}$ ]] || fail "the commit is not a full lowercase hexadecimal sha"

workspace_version() {
  sed -n '/^\[workspace.package\]/,/^\[/s/^version *= *"\(.*\)"$/\1/p' "$manifest" | head -n 1
}

commit_is_on_main() {
  if [ -n "${RELEASE_PLAN_ON_MAIN:-}" ]; then
    [ "$RELEASE_PLAN_ON_MAIN" = true ]
    return
  fi
  git -C "$repo" merge-base --is-ancestor "$sha" origin/main
}

tag_exists_remotely() {
  if [ -n "${RELEASE_PLAN_TAG_EXISTS:-}" ]; then
    [ "$RELEASE_PLAN_TAG_EXISTS" = true ]
    return
  fi
  local found
  found=$(git -C "$repo" ls-remote --tags origin "refs/tags/$1")
  [ -n "$found" ]
}

case "$input_include_arm" in
  "" | true | false) ;;
  *) fail "include_arm must be true or false" ;;
esac
case "$input_publish" in
  "" | true | false) ;;
  *) fail "publish must be true or false" ;;
esac

release=false
draft=true
include_arm=true

case "$event" in
  push)
    case "$ref" in
      refs/tags/v?*) ;;
      *) fail "a push run must be for a tag v<major>.<minor>.<patch>" ;;
    esac
    single_line "$ref_name" && [ "$ref_name" = "${ref#refs/tags/}" ] || fail "the tag name does not match the ref"
    version=${ref_name#v}
    valid_version "$version" || fail "the tag is not v<major>.<minor>.<patch>[-suffix]"
    commit_is_on_main || fail "the tagged commit is not on main"
    release=true
    draft=false
    ;;
  workflow_dispatch)
    if [ -n "$input_version" ]; then
      version=$input_version
      valid_version "$version" || fail "the version must look like 1.2.3 or 1.2.3-rc.1, without a leading v"
    else
      base=$(workspace_version)
      valid_version "$base" || fail "the workspace version in Cargo.toml is not a valid release version"
      version=$base-${sha:0:7}
      valid_version "$version" || fail "the default version is not a valid release version"
    fi
    if [ "$input_include_arm" = false ]; then
      include_arm=false
    fi
    if [ "$ref" = refs/heads/main ]; then
      release=true
      if tag_exists_remotely "v$version"; then
        fail "the tag v$version already exists; choose another version"
      fi
    fi
    if [ "$input_publish" = true ]; then
      draft=false
    fi
    ;;
  *) fail "unsupported event" ;;
esac

prerelease=false
case "$version" in
  *-*) prerelease=true ;;
esac

x86_linux='{"target":"x86_64-unknown-linux-musl","runner":"ubuntu-24.04"}'
arm_linux='{"target":"aarch64-unknown-linux-musl","runner":"ubuntu-24.04-arm"}'
arm_mac='{"target":"aarch64-apple-darwin","runner":"macos-15"}'
x86_mac='{"target":"x86_64-apple-darwin","runner":"macos-15"}'
x86_verify='{"arch":"x86_64","runner":"ubuntu-24.04"}'
arm_verify='{"arch":"aarch64","runner":"ubuntu-24.04-arm"}'

if [ "$include_arm" = true ]; then
  build_matrix="[$x86_linux,$arm_linux,$arm_mac,$x86_mac]"
  verify_matrix="[$x86_verify,$arm_verify]"
  archives=10
else
  build_matrix="[$x86_linux,$arm_mac,$x86_mac]"
  verify_matrix="[$x86_verify]"
  archives=6
fi

printf 'version=%s\n' "$version"
printf 'tag=v%s\n' "$version"
printf 'draft=%s\n' "$draft"
printf 'prerelease=%s\n' "$prerelease"
printf 'release=%s\n' "$release"
printf 'archives=%s\n' "$archives"
printf 'build_matrix=%s\n' "$build_matrix"
printf 'verify_matrix=%s\n' "$verify_matrix"
