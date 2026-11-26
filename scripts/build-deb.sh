#!/usr/bin/env bash
set -euo pipefail

umask 022

die() {
  printf 'build-deb: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s --package jaunt-agent|jaunt --version <tag without v> --arch amd64|arm64 --binary <path> --output <dir>\n' "$0" >&2
  exit 2
}

package=
version=
arch=
binary=
output=
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case $1 in
    --package) package=$2 ;;
    --version) version=$2 ;;
    --arch) arch=$2 ;;
    --binary) binary=$2 ;;
    --output) output=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$package" ] && [ -n "$version" ] && [ -n "$arch" ] && [ -n "$binary" ] && [ -n "$output" ] || usage

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
maintainer=${JAUNT_DEB_MAINTAINER:-GlobalArt Inc <noreply@users.noreply.github.com>}
homepage=https://github.com/GlobalArtInc/jaunt

command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb is required: build in a Debian or Ubuntu image with GNU coreutils (GNU date and du are used)"

case $package in
  jaunt-agent)
    synopsis='node agent for the Jaunt SSH access gateway'
    description=' Node agent of the Jaunt SSH access gateway. It keeps an outbound tunnel
 to the Jaunt server and logs in to the local sshd with short-lived
 certificates.
 .
 This package installs files only. It does not enrol the node, change the
 sshd configuration or start the service. The commands to run after
 installation are in /usr/share/doc/jaunt-agent/README.md.'
    suggests='Suggests: openssh-server'
    ;;
  jaunt)
    synopsis='command-line client for the Jaunt SSH access gateway'
    description=' Command-line client of the Jaunt SSH access gateway. It signs the user
 in through the identity provider of the Jaunt server and opens SSH
 sessions to nodes.'
    suggests=
    ;;
  *) die "unknown package $package" ;;
esac

case $arch in
  amd64) machine=3e00 ;;
  arm64) machine=b700 ;;
  *) die "unsupported architecture $arch" ;;
esac

[[ $version =~ ^([0-9]+\.[0-9]+\.[0-9]+)(-([0-9A-Za-z.-]+))?(\+([0-9A-Za-z.-]+))?$ ]] || die "version must look like 1.2.3, 1.2.3-rc.1 or 1.2.3+build, got $version"
deb_version=${BASH_REMATCH[1]}
if [ -n "${BASH_REMATCH[3]}" ]; then
  pre_release=${BASH_REMATCH[3]}
  deb_version+="~${pre_release//-/\~}"
fi
if [ -n "${BASH_REMATCH[5]}" ]; then
  build_metadata=${BASH_REMATCH[5]}
  deb_version+="+${build_metadata//-/.}"
fi

[ -f "$binary" ] && [ -x "$binary" ] || die "binary $binary is not an executable file"
[ "$(od -An -tx1 -N4 "$binary" | tr -d ' \n')" = 7f454c46 ] || die "binary $binary is not an ELF file"
[ "$(od -An -tx1 -j18 -N2 "$binary" | tr -d ' \n')" = "$machine" ] || die "binary $binary is not built for $arch"

epoch=${SOURCE_DATE_EPOCH:-}
if [ -z "$epoch" ]; then
  epoch=$(git -C "$repo" log -1 --format=%ct 2>/dev/null) || die "set SOURCE_DATE_EPOCH"
fi
[[ $epoch =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be a number"
export SOURCE_DATE_EPOCH=$epoch

mkdir -p -- "$output"
stage=$(mktemp -d)
trap 'rm -rf -- "${stage:?}"' EXIT
root=$stage/pkg

install -d -m 0755 "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/doc/$package"
install -m 0755 "$binary" "$root/usr/bin/$package"
install -m 0644 "$repo/packaging/copyright" "$root/usr/share/doc/$package/copyright"
install -m 0644 "$repo/packaging/README.$package.md" "$root/usr/share/doc/$package/README.md"
install -d -m 0755 "$root/usr/share/lintian/overrides"
sed "s|{{package}}|$package|g" "$repo/packaging/lintian-overrides" >"$stage/overrides"
install -m 0644 "$stage/overrides" "$root/usr/share/lintian/overrides/$package"

if [ "$package" = jaunt-agent ]; then
  install -d -m 0755 "$root/usr/lib/systemd/system"
  sed \
    -e 's|{{user}}|jaunt|g' \
    -e 's|{{binary}}|/usr/bin/jaunt-agent|g' \
    -e 's|{{config}}|/etc/jaunt/agent.yaml|g' \
    -e 's|{{state_dir}}|/var/lib/jaunt|g' \
    "$repo/crates/jaunt-agent/src/installer/jaunt-agent.service.tpl" >"$stage/unit"
  if grep -q '{{' "$stage/unit"; then
    die "unit template has a placeholder this script does not fill"
  fi
  install -m 0644 "$stage/unit" "$root/usr/lib/systemd/system/jaunt-agent.service"
fi

changelog_date=$(date -u -d "@$epoch" '+%a, %d %b %Y %H:%M:%S +0000')
{
  printf '%s (%s) unstable; urgency=medium\n\n' "$package" "$deb_version"
  printf '  * Release %s. See %s/releases/tag/v%s\n\n' "$version" "$homepage" "$version"
  printf ' -- %s  %s\n' "$maintainer" "$changelog_date"
} | gzip -9n >"$stage/changelog.gz"
install -m 0644 "$stage/changelog.gz" "$root/usr/share/doc/$package/changelog.gz"

find "$root" -exec touch -h -d "@$epoch" {} +

installed_size=$(du -sk --apparent-size --exclude=DEBIAN "$root" | cut -f1)
{
  printf 'Package: %s\n' "$package"
  printf 'Version: %s\n' "$deb_version"
  printf 'Architecture: %s\n' "$arch"
  printf 'Maintainer: %s\n' "$maintainer"
  printf 'Installed-Size: %s\n' "$installed_size"
  printf 'Section: admin\n'
  printf 'Priority: optional\n'
  printf 'Homepage: %s\n' "$homepage"
  if [ -n "$suggests" ]; then printf '%s\n' "$suggests"; fi
  printf 'Description: %s\n%s\n' "$synopsis" "$description"
} >"$root/DEBIAN/control"
touch -d "@$epoch" "$root/DEBIAN/control" "$root/DEBIAN"

deb=$output/${package}_${deb_version}_${arch}.deb
dpkg-deb --root-owner-group -Zxz --build "$root" "$deb" >/dev/null
printf '%s\n' "$deb"
