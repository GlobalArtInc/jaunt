#!/usr/bin/env bash
set -euo pipefail

PASSPHRASE=throw-away-passphrase
EPOCH=1700000000
SIGNATURE_REASON="is not signed"
failures=0
label=${TEST_LABEL:-local}

pass() { printf 'PASS [%s] %s\n' "$label" "$1"; }
fail() { printf 'FAIL [%s] %s\n' "$label" "$1"; failures=$((failures + 1)); }

check() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}

check_fails() {
  local description=$1 reason=$2 output status=0
  shift 2
  output=$("$@" 2>&1) || status=$?
  if [ "$status" -ne 0 ] && grep -qF -- "$reason" <<<"$output"; then pass "$description"; else fail "$description"; printf '%s\n' "$output" | sed 's/^/  output: /'; fi
}

mode_is() { [ "$(stat -c '%a %U:%G' "$2")" = "$1" ]; }
version_is() { [ "$("$1" --version)" = "$1 $2" ]; }
field_is() { [ "$(dpkg-deb -f "$1" "$2")" = "$3" ]; }
absent() { [ ! -e "$1" ]; }
file_has_line() { grep -qxF -- "$1" "$2"; }

compile_dummy() {
  local name=$1 version=$2 out=$3
  printf '%s\n' \
    '#include <stdio.h>' \
    '#include <string.h>' \
    'int main(int argc, char **argv) {' \
    '  if (argc > 1 && strcmp(argv[1], "--version") == 0) { puts(NAME " " VERSION); return 0; }' \
    '  return 1;' \
    '}' >/work/dummy.c
  gcc -static -Os -s -DNAME="\"$name\"" -DVERSION="\"$version\"" -o "$out" /work/dummy.c
}

as_foreign_arch() {
  local source=$1 out=$2 machine=$3
  cp "$source" "$out"
  printf '%b' "$machine" | dd of="$out" bs=1 seek=18 conv=notrunc 2>/dev/null
}

make_key() {
  local gnupg key
  gnupg=$(mktemp -d)
  GNUPGHOME=$gnupg gpg --batch --quiet --pinentry-mode loopback --passphrase "$PASSPHRASE" --quick-generate-key 'Jaunt Test <test@example.invalid>' ed25519 sign never 2>/dev/null
  key=$(GNUPGHOME=$gnupg gpg --batch --quiet --pinentry-mode loopback --passphrase "$PASSPHRASE" --armor --export-secret-keys 2>/dev/null)
  GNUPGHOME=$gnupg gpgconf --kill gpg-agent
  rm -rf -- "${gnupg:?}"
  printf '%s\n' "$key"
}

run_builder() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends apt-utils gnupg gcc libc6-dev >/dev/null

  local native foreign foreign_machine
  native=$(dpkg --print-architecture)
  case $native in
    amd64) foreign=arm64 foreign_machine='\xb7\x00' ;;
    arm64) foreign=amd64 foreign_machine='\x3e\x00' ;;
    *) echo "unsupported builder architecture $native" >&2; exit 1 ;;
  esac

  export SOURCE_DATE_EPOCH=$EPOCH
  local build=/repo/scripts/build-deb.sh apt_repo=/repo/scripts/build-apt-repo.sh
  local debs=/work/debs bin=/work/bin
  mkdir -p "$debs" "$bin"

  local version name
  for version in 0.0.1 0.0.2; do
    for name in jaunt-agent jaunt; do
      compile_dummy "$name" "$version" "$bin/$name-$version-$native"
      as_foreign_arch "$bin/$name-$version-$native" "$bin/$name-$version-$foreign" "$foreign_machine"
      "$build" --package "$name" --version "$version" --arch "$native" --binary "$bin/$name-$version-$native" --output "$debs" >/dev/null
      "$build" --package "$name" --version "$version" --arch "$foreign" --binary "$bin/$name-$version-$foreign" --output "$debs" >/dev/null
    done
  done

  check "packages exist for both architectures" test "$(find "$debs" -name '*.deb' | wc -l)" -eq 8
  check "the package is named from the version and the architecture" test -f "$debs/jaunt-agent_0.0.1_$native.deb"
  check "the control file carries the version" field_is "$debs/jaunt-agent_0.0.1_$foreign.deb" Version 0.0.1
  check "the control file carries the architecture" field_is "$debs/jaunt-agent_0.0.1_$foreign.deb" Architecture "$foreign"
  check_fails "a binary for the other architecture is refused" "is not built for" "$build" --package jaunt --version 0.0.1 --arch "$foreign" --binary "$bin/jaunt-0.0.1-$native" --output /work/refused
  check_fails "a version with a leading v is refused" "version must look like" "$build" --package jaunt --version v0.0.1 --arch "$native" --binary "$bin/jaunt-0.0.1-$native" --output /work/refused
  check_fails "a file that is not an ELF binary is refused" "is not an ELF file" "$build" --package jaunt --version 0.0.1 --arch "$native" --binary /repo/scripts/build-deb.sh --output /work/refused

  local pair given expected built
  for pair in 0.0.3-rc.1:0.0.3~rc.1 1.2.3-rc-1:1.2.3~rc~1 1.2.3+b1:1.2.3+b1 1.2.3-rc.1+b1:1.2.3~rc.1+b1 1.2.3+b-1:1.2.3+b.1; do
    given=${pair%%:*}
    expected=${pair#*:}
    built=$("$build" --package jaunt --version "$given" --arch "$native" --binary "$bin/jaunt-0.0.1-$native" --output /work/versions)
    check "version $given becomes $expected" field_is "$built" Version "$expected"
  done
  check "a pre-release sorts before the release" bash -c "dpkg --compare-versions 0.0.3~rc.1 lt 0.0.3 && dpkg --compare-versions 1.2.3~rc~1 lt 1.2.3 && dpkg --compare-versions 1.2.3~rc.1+b1 lt 1.2.3"
  check "a build suffix sorts after the release" dpkg --compare-versions 1.2.3+b1 gt 1.2.3
  check "the build is reproducible" bash -c "[ \"\$('$build' --package jaunt --version 0.0.1 --arch '$native' --binary '$bin/jaunt-0.0.1-$native' --output /work/again >/dev/null; sha256sum < /work/again/jaunt_0.0.1_$native.deb)\" = \"\$(sha256sum < '$debs/jaunt_0.0.1_$native.deb')\" ]"

  JAUNT_APT_GPG_KEY=$(make_key)
  export JAUNT_APT_GPG_KEY
  local other_key
  other_key=$(make_key)

  check_fails "the repository is not built with an empty key" "JAUNT_APT_GPG_KEY is not set" env JAUNT_APT_GPG_KEY= "$apt_repo" --output /work/refused-repo "$debs/jaunt_0.0.1_$native.deb"
  check_fails "the repository is not built without a key" "JAUNT_APT_GPG_KEY is not set" env -u JAUNT_APT_GPG_KEY "$apt_repo" --output /work/refused-repo "$debs/jaunt_0.0.1_$native.deb"
  check_fails "the repository is not built from a key that is not a key" "importing the signing key failed" env JAUNT_APT_GPG_KEY=not-a-key "$apt_repo" --output /work/refused-repo "$debs/jaunt_0.0.1_$native.deb"
  check_fails "the repository is not built with a wrong passphrase" "signing Release failed" env JAUNT_APT_GPG_PASSPHRASE=wrong "$apt_repo" --output /work/refused-repo "$debs/jaunt_0.0.1_$native.deb"
  export JAUNT_APT_GPG_PASSPHRASE=$PASSPHRASE

  "$apt_repo" --output /work/repo-a "$debs"/*_0.0.1_*.deb >/dev/null
  cp -a /work/repo-a /work/repo-b
  "$apt_repo" --output /work/repo-b "$debs"/*_0.0.2_*.deb >/dev/null
  cp -a /work/repo-b /work/repo-c
  printf 'tampered\n' >>/work/repo-c/Packages
  printf 'tampered\n' >>/work/repo-c/Packages.gz
  cp -a /work/repo-b /work/repo-inrelease
  rm -f -- /work/repo-inrelease/Release /work/repo-inrelease/Release.gpg
  sed -i 's/Jaunt packages/Jaunt packagez/' /work/repo-inrelease/InRelease
  cp -a /work/repo-b /work/repo-unsigned
  rm -f -- /work/repo-unsigned/Release.gpg /work/repo-unsigned/InRelease
  JAUNT_APT_GPG_KEY=$other_key JAUNT_APT_GPG_PASSPHRASE=$PASSPHRASE "$apt_repo" --output /work/repo-otherkey "$debs"/*_0.0.2_*.deb >/dev/null

  check "the repository has a detached signature, an inline signature and the public key" bash -c 'cd /work/repo-a && test -s Release.gpg && test -s InRelease && test -s jaunt-archive-keyring.asc'
  check "the repository lists every architecture" bash -c "[ \"\$(grep -c '^Package: ' /work/repo-b/Packages)\" -eq 8 ]"
  check "the secret key is not in the repository" bash -c "! grep -rq 'PRIVATE KEY' /work/repo-a /work/repo-b"

  chmod -R a+rX /work/repo-a /work/repo-b /work/repo-c /work/repo-inrelease /work/repo-unsigned /work/repo-otherkey /work/debs
  echo "$native" >/work/native
  exit "$failures"
}

refresh_jaunt_source() {
  apt-get update -qq -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/jaunt.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
}

use_repo() {
  printf 'deb [signed-by=/etc/apt/keyrings/jaunt.asc] file:/work/%s ./\n' "$1" >/etc/apt/sources.list.d/jaunt.list
}

run_clean() {
  export DEBIAN_FRONTEND=noninteractive
  local native
  native=$(cat /work/native)
  install -d -m 0755 /etc/apt/keyrings
  install -m 0644 /work/repo-a/jaunt-archive-keyring.asc /etc/apt/keyrings/jaunt.asc

  use_repo repo-a
  check "apt update accepts the signed repository" refresh_jaunt_source
  check "the candidate is version 0.0.1" bash -c "apt-cache policy jaunt-agent | grep -q 'Candidate: 0.0.1'"
  check "apt installs both packages" apt-get install -y -qq jaunt-agent jaunt
  check "jaunt-agent reports its version" version_is jaunt-agent 0.0.1
  check "jaunt reports its version" version_is jaunt 0.0.1

  check "jaunt-agent is root-owned and 0755" mode_is '755 root:root' /usr/bin/jaunt-agent
  check "jaunt is root-owned and 0755" mode_is '755 root:root' /usr/bin/jaunt
  check "the unit file is root-owned and 0644" mode_is '644 root:root' /usr/lib/systemd/system/jaunt-agent.service
  check "the agent unit runs the packaged binary with the default config" file_has_line 'ExecStart=/usr/bin/jaunt-agent run --config /etc/jaunt/agent.yaml' /usr/lib/systemd/system/jaunt-agent.service
  check "the unit has no unfilled placeholder" bash -c "! grep -q '{{' /usr/lib/systemd/system/jaunt-agent.service"
  check "the agent documentation is installed" test -s /usr/share/doc/jaunt-agent/README.md
  check "the copyright files are installed" bash -c 'test -s /usr/share/doc/jaunt-agent/copyright && test -s /usr/share/doc/jaunt/copyright'

  local listed
  listed=$(dpkg -L jaunt-agent jaunt | while read -r path; do if [ -f "$path" ]; then echo "$path"; fi; done | sort | tr '\n' ' ')
  local expected='/usr/bin/jaunt /usr/bin/jaunt-agent /usr/lib/systemd/system/jaunt-agent.service /usr/share/doc/jaunt-agent/README.md /usr/share/doc/jaunt-agent/changelog.gz /usr/share/doc/jaunt-agent/copyright /usr/share/doc/jaunt/README.md /usr/share/doc/jaunt/changelog.gz /usr/share/doc/jaunt/copyright /usr/share/lintian/overrides/jaunt /usr/share/lintian/overrides/jaunt-agent '
  check "the packages contain exactly the expected files" test "$listed" = "$expected"
  dpkg -L jaunt-agent jaunt >/work/installed-paths
  check "no packaged path is setuid or setgid" bash -c "! find \$(cat /work/installed-paths) -maxdepth 0 -perm /6000 | grep -q ."
  check "every packaged path is owned by root" bash -c "! find \$(cat /work/installed-paths) -maxdepth 0 ! -user root | grep -q ."
  check "the package ships no maintainer script" bash -c "! ls /var/lib/dpkg/info/jaunt-agent.pre* /var/lib/dpkg/info/jaunt-agent.post* /var/lib/dpkg/info/jaunt.pre* /var/lib/dpkg/info/jaunt.post* 2>/dev/null | grep -q ."
  check "the package created no service account" bash -c '! getent passwd jaunt'
  check "the package created no configuration" absent /etc/jaunt
  check "the package created no state directory" absent /var/lib/jaunt
  check "the package left sshd alone" absent /etc/ssh/sshd_config.d/50-jaunt.conf
  check "the package enabled nothing" absent /etc/systemd/system/jaunt-agent.service
  check "the package enabled no unit link" bash -c "! find /etc/systemd -name 'jaunt-agent*' | grep -q ."

  use_repo repo-b
  check "apt update accepts the repository with version 0.0.2" refresh_jaunt_source
  check "apt upgrades both packages" apt-get install -y -qq --only-upgrade jaunt-agent jaunt
  check "jaunt-agent is upgraded" version_is jaunt-agent 0.0.2
  check "jaunt is upgraded" version_is jaunt 0.0.2
  check "the upgrade keeps the file modes" mode_is '755 root:root' /usr/bin/jaunt-agent
  check "the installed version is 0.0.2" bash -c "[ \"\$(dpkg-query -W -f='\${Version}' jaunt-agent)\" = 0.0.2 ]"

  use_repo repo-c
  check_fails "apt update refuses an index that does not match the signed Release" "Hash Sum mismatch" refresh_jaunt_source

  use_repo repo-inrelease
  check_fails "apt update refuses a modified InRelease" "$SIGNATURE_REASON" refresh_jaunt_source
  use_repo repo-otherkey
  check_fails "apt update refuses a repository signed with another key" "$SIGNATURE_REASON" refresh_jaunt_source
  use_repo repo-unsigned
  check_fails "apt update refuses a repository without a signature" "$SIGNATURE_REASON" refresh_jaunt_source

  check "apt purges both packages" apt-get purge -y -qq jaunt-agent jaunt
  check "the binaries are gone" bash -c '! test -e /usr/bin/jaunt-agent && ! test -e /usr/bin/jaunt'
  check "no packaged file remains" bash -c "! while read -r path; do if [ -e \"\$path\" ] && [ ! -d \"\$path\" ]; then echo \"\$path\"; fi; done </work/installed-paths | grep -q ."
  check "the documentation directories are gone" bash -c '! test -e /usr/share/doc/jaunt-agent && ! test -e /usr/share/doc/jaunt'
  check "dpkg no longer knows the packages" bash -c '! dpkg -s jaunt-agent >/dev/null 2>&1 && ! dpkg -s jaunt >/dev/null 2>&1'

  rm -f -- /etc/apt/sources.list.d/jaunt.list
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends lintian >/dev/null
  local lint_status=0 lint_output
  lint_output=$(lintian --tag-display-limit 0 --fail-on error "/work/debs/jaunt-agent_0.0.2_$native.deb" "/work/debs/jaunt_0.0.2_$native.deb" 2>&1) || lint_status=$?
  printf '%s\n' "$lint_output" | sed 's/^/lintian: /'
  if [ "$lint_status" -eq 0 ]; then pass "lintian reports no error"; else fail "lintian reports no error"; fi

  exit "$failures"
}

case ${1:-} in
  --builder) run_builder ;;
  --clean) run_clean ;;
esac

engine=${CONTAINER_ENGINE:-podman}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
images=("$@")
if [ "${#images[@]}" -eq 0 ]; then images=(debian:12 debian:13); fi

work_dirs=()
containers=()
cleanup() {
  local name path
  for name in ${containers[@]+"${containers[@]}"}; do
    "$engine" rm -f "$name" >/dev/null 2>&1 || true
  done
  for path in ${work_dirs[@]+"${work_dirs[@]}"}; do
    rm -rf -- "${path:?}"
  done
}
trap cleanup EXIT

total_failures=0
index=0
for image in "${images[@]}"; do
  index=$((index + 1))
  started=$SECONDS
  work=$(mktemp -d "${TMPDIR:-/tmp}/jaunt-deb-test.XXXXXX")
  chmod 0755 "$work"
  work_dirs+=("$work")
  for phase in builder clean; do
    name=jaunt-deb-test-$$-$index-$phase
    containers+=("$name")
    status=0
    "$engine" run --rm --name "$name" \
      -e TEST_LABEL="$image/$phase" \
      -v "$repo:/repo:ro" \
      -v "$work:/work" \
      "$image" bash /repo/scripts/test-deb.sh "--$phase" || status=$?
    if [ "$status" -ne 0 ]; then
      printf 'FAIL [%s] phase %s exited with %s\n' "$image" "$phase" "$status"
      total_failures=$((total_failures + 1))
      break
    fi
  done
  printf 'DONE [%s] in %s seconds\n' "$image" "$((SECONDS - started))"
done

if [ "$total_failures" -ne 0 ]; then
  printf '%s image(s) failed\n' "$total_failures"
  exit 1
fi
printf 'all images passed in %s seconds\n' "$SECONDS"
