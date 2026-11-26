#!/usr/bin/env bash
set -euo pipefail

umask 022

die() {
  printf 'build-apt-repo: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: JAUNT_APT_GPG_KEY=<armored private key> [JAUNT_APT_GPG_PASSPHRASE=<passphrase>] %s --output <dir> <package.deb>...\n' "$0" >&2
  exit 2
}

output=
debs=()
while [ $# -gt 0 ]; do
  case $1 in
    --output)
      [ $# -ge 2 ] || usage
      output=$2
      shift 2
      ;;
    -*) usage ;;
    *)
      debs+=("$1")
      shift
      ;;
  esac
done
[ -n "$output" ] && [ "${#debs[@]}" -gt 0 ] || usage
[ -n "${JAUNT_APT_GPG_KEY:-}" ] || die "JAUNT_APT_GPG_KEY is not set"
signing_key=$JAUNT_APT_GPG_KEY
signing_passphrase=${JAUNT_APT_GPG_PASSPHRASE:-}
unset JAUNT_APT_GPG_KEY JAUNT_APT_GPG_PASSPHRASE

for tool in apt-ftparchive gpg gzip; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required (package apt-utils provides apt-ftparchive, gnupg provides gpg)"
done

for deb in "${debs[@]}"; do
  [ -f "$deb" ] || die "$deb is not a file"
  case $deb in
    *.deb) ;;
    *) die "$deb is not a .deb file" ;;
  esac
done

work=$(mktemp -d)
gnupg=$work/gnupg
install -d -m 0700 "$gnupg"
export GNUPGHOME=$gnupg
cleanup() {
  gpgconf --kill gpg-agent >/dev/null 2>&1 || true
  rm -rf -- "${work:?}"
}
trap cleanup EXIT

gpg_log=$work/gpg.log
gpg_fail() {
  printf 'build-apt-repo: %s failed\n' "$1" >&2
  cat "$gpg_log" >&2
  exit 1
}

printf '%s\n' "$signing_key" | gpg --batch --quiet --import 2>"$gpg_log" || gpg_fail "importing the signing key"
secret_count=$(gpg --batch --list-secret-keys --with-colons 2>"$gpg_log" | grep -c '^sec:' || true)
[ "$secret_count" = 1 ] || die "JAUNT_APT_GPG_KEY must hold exactly one secret key, found $secret_count"
fingerprint=$(gpg --batch --list-secret-keys --with-colons 2>"$gpg_log" | awk -F: '/^sec:/ { found = 1; next } found && /^fpr:/ { print $10; exit }')
[[ $fingerprint =~ ^[0-9A-F]{40,64}$ ]] || die "could not read the fingerprint of the signing key"

sign() {
  printf '%s' "$signing_passphrase" |
    gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-fd 0 --local-user "$fingerprint" "$@" 2>"$gpg_log"
}

mkdir -p -- "$output"
output=$(cd "$output" && pwd)
rm -f -- "$output/Packages" "$output/Packages.gz" "$output/Release" "$output/Release.gpg" "$output/InRelease" "$output/jaunt-archive-keyring.asc"
for deb in "${debs[@]}"; do
  target=$output/$(basename "$deb")
  if [ -e "$target" ] && ! cmp -s "$deb" "$target"; then
    die "$(basename "$deb") already exists in the repository with different content"
  fi
  install -m 0644 "$deb" "$target"
done

cat >"$work/release.conf" <<'CONF'
APT::FTPArchive::Release::Origin "Jaunt";
APT::FTPArchive::Release::Label "Jaunt";
APT::FTPArchive::Release::Description "Jaunt packages";
APT::FTPArchive::Release::Architectures "amd64 arm64";
CONF

(
  cd "$output"
  apt-ftparchive packages . >Packages
  gzip -9n -c Packages >Packages.gz
  apt-ftparchive -c "$work/release.conf" release . >"$work/Release"
)
install -m 0644 "$work/Release" "$output/Release"

sign --armor --detach-sign --output "$output/Release.gpg" "$output/Release" || gpg_fail "signing Release"
sign --clearsign --output "$output/InRelease" "$output/Release" || gpg_fail "signing InRelease"
gpg --batch --armor --export "$fingerprint" >"$output/jaunt-archive-keyring.asc" 2>"$gpg_log" || gpg_fail "exporting the public key"
chmod 0644 "$output/Release.gpg" "$output/InRelease" "$output/jaunt-archive-keyring.asc"

gpg --batch --quiet --no-default-keyring --keyring "$work/public.kbx" --import "$output/jaunt-archive-keyring.asc" 2>"$gpg_log" || gpg_fail "importing the public key"
gpg --batch --quiet --no-default-keyring --keyring "$work/public.kbx" --verify "$output/Release.gpg" "$output/Release" 2>"$gpg_log" || gpg_fail "verifying Release.gpg"
gpg --batch --quiet --no-default-keyring --keyring "$work/public.kbx" --verify "$output/InRelease" 2>"$gpg_log" || gpg_fail "verifying InRelease"

printf '%s\n' "$output"
