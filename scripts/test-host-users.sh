#!/usr/bin/env bash
set -euo pipefail

BINARY=/usr/local/sbin/jaunt-host-users
SOCKET=/run/jaunt/host-users.sock
CONFIG=/etc/jaunt/agent.yaml
STATE_DIR=/var/lib/jaunt-host-users
STATE_FILE=$STATE_DIR/accounts.json
LOCK_PATH=$STATE_DIR/lock
USERADD_FDS=/tmp/useradd-fds
USERADD_STDIN=/tmp/useradd-stdin
UNITS=/units
HELPER_LOG=/tmp/helper.log
CLIENT_LOG=/tmp/client.log
CLIENT_DEADLINE=30
WAIT_DEADLINE=10
CONTAINER_DEADLINE=900
DEFAULT_IMAGES=(debian:12 debian:13 rockylinux:9 ubuntu:22.04 ubuntu:24.04)
SQUATTER_FIRST=31500
SQUATTER_LAST=31509

failures=0
label=${HOST_USERS_IMAGE:-local}
last_response=
last_status=0

pass() { printf 'PASS [%s] %s\n' "$label" "$1"; }

fail() {
  printf 'FAIL [%s] %s (last response: %s, status %s)\n' "$label" "$1" "${last_response:-<none>}" "$last_status"
  failures=$((failures + 1))
}

check() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}

now() { date +%s; }

wait_for() {
  local deadline=$(($(now) + $1))
  shift
  until "$@" >/dev/null 2>&1; do
    [ "$(now)" -lt "$deadline" ] || return 1
    sleep 0.1
  done
}

request() {
  printf '{"v":1,"op":"ensure","login":"%s","ref":"H-%08X","session":"t-%s"}' "$1" "$RANDOM" "$RANDOM"
}

send_as() {
  local user=$1 line=$2
  last_status=0
  last_response=$(printf '%s\n' "$line" |
    timeout "$CLIENT_DEADLINE" setpriv --reuid="$user" --regid="$user" --init-groups \
      socat -t "$CLIENT_DEADLINE" - "UNIX-CONNECT:$SOCKET" 2>>"$CLIENT_LOG") || last_status=$?
}

ask() { send_as "${2:-jaunt}" "$(request "$1")"; }

answered() { grep -qF -- "$1" <<<"$last_response"; }
silent() { [ -z "$last_response" ]; }
logged() { grep -qE -- "$1" "$HELPER_LOG"; }
state_has() { grep -qE -- "$1" "$STATE_FILE"; }
state_lacks() { ! grep -qE -- "$1" "$STATE_FILE"; }
account_present() { getent passwd "$1" >/dev/null; }
account_absent() { ! getent passwd "$1" >/dev/null; }
group_absent() { ! getent group "$1" >/dev/null; }
path_absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
subids_absent() { ! grep -qs "^$1:" /etc/subuid /etc/subgid; }
field_of() { getent passwd "$1" | cut -d: -f"$2"; }
answer_uid() { sed -n 's/.*"uid":\([0-9]*\).*/\1/p' <<<"$last_response"; }
in_range() { [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]; }
same_text() { [ "$1" = "$2" ]; }
has_word() { grep -qw -- "$2" <<<"$1"; }

write_config() {
  local enabled=${1:-true} uid_min=${2:-30000} uid_max=${3:-30999} max_users=${4:-100}
  local home_mode=${5:-0750}
  cat >"$CONFIG" <<EOF
control_url: https://control.example.test:8443
host_users:
  enabled: $enabled
  groups: [devs]
  shell: /bin/bash
  home_base: /home
  home_mode: "$home_mode"
  uid_min: $uid_min
  uid_max: $uid_max
  max_users: $max_users
  names:
    deny: [blocked]
EOF
  chown root:root "$CONFIG"
  chmod 0644 "$CONFIG"
}

reset_attempts() {
  sed -i -E 's/"attempts":\[[0-9,]*\]/"attempts":[]/' "$STATE_FILE"
}

fill_attempts() {
  local at
  at=$(now)
  sed -i -E "s/\"attempts\":\[[0-9,]*\]/\"attempts\":[$at,$at,$at,$at,$at]/" "$STATE_FILE"
}

wrap_useradd() {
  mv /usr/sbin/useradd /usr/sbin/useradd.real
  printf '#!/bin/sh\n%s\n' "$1" >/usr/sbin/useradd
  chown root:root /usr/sbin/useradd
  chmod 0755 /usr/sbin/useradd
}

unwrap_useradd() { mv -f /usr/sbin/useradd.real /usr/sbin/useradd; }

prepare_image() {
  export DEBIAN_FRONTEND=noninteractive
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends systemd socat util-linux procps >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q systemd socat util-linux procps-ng >/dev/null
  else
    echo "unsupported image: neither apt-get nor dnf is available" >&2
    exit 2
  fi
  useradd --system --user-group --home-dir /var/lib/jaunt --shell /usr/sbin/nologin jaunt
  useradd --system --user-group --shell /usr/sbin/nologin intruder
  usermod -a -G jaunt intruder
  groupadd devs
  local uid
  for uid in $(seq "$SQUATTER_FIRST" "$SQUATTER_LAST"); do
    useradd --uid "$uid" --user-group --no-create-home "squatter$uid"
  done
  install -d -o root -g root -m 0755 /etc/jaunt /run/jaunt
  install -d -o root -g root -m 0700 "$STATE_DIR"
  write_config
}

start_helper() {
  systemd-socket-activate --listen="$SOCKET" --accept --inetd \
    "$BINARY" serve --config "$CONFIG" --agent-user jaunt >>"$HELPER_LOG" 2>&1 &
  if ! wait_for "$WAIT_DEADLINE" test -S "$SOCKET"; then
    echo "the socket did not appear" >&2
    exit 1
  fi
  chown root:jaunt "$SOCKET"
  chmod 0660 "$SOCKET"
}

render_unit() {
  sed -e "s|{{binary}}|$BINARY|g" -e "s|{{config}}|$CONFIG|g" \
    -e "s|{{user}}|jaunt|g" -e "s|{{home_base}}|/home|g" "$1" >"$2"
}

verify_units() {
  local out
  out=$(systemd-analyze verify /tmp/units/jaunt-host-users.socket /tmp/units/jaunt-host-users@.service 2>&1) || return 1
  [ -z "$out" ] || { printf '%s\n' "$out" >&2; return 1; }
}

scenario_units() {
  mkdir -p /tmp/units
  render_unit "$UNITS/jaunt-host-users.socket" /tmp/units/jaunt-host-users.socket
  render_unit "$UNITS/jaunt-host-users@.service" /tmp/units/jaunt-host-users@.service
  check "systemd-analyze verify accepts the rendered unit templates" verify_units
}

scenario_created() {
  ask alice
  check "a new login is created" answered '"result":"created"'
  local uid
  uid=$(answer_uid)
  check "the answer names the home and the groups" answered '"home":"/home/alice","groups":["alice","devs"]'
  check "the uid is in the operator range" in_range "${uid:-0}" 30000 30999
  check "the account carries the answered uid" same_text "$(field_of alice 3)" "$uid"
  check "the primary group is the private group" same_text "$(getent group alice | cut -d: -f3)" "$(field_of alice 4)"
  check "the home is home_base/login" same_text "$(field_of alice 6)" /home/alice
  check "the shell is the configured one" same_text "$(field_of alice 7)" /bin/bash
  check "the home is a 0750 directory of the account" same_text "$(stat -c '%a %U %G %F' /home/alice)" "750 alice alice directory"
  check "the supplementary group is set" has_word "$(id -nG alice)" devs
  check "the password field is a star" same_text "$(getent shadow alice | cut -d: -f2)" '*'
  check "the comment marks the account" same_text "$(field_of alice 5)" jaunt
  check "the state records the account as active" state_has '"login":"alice","uid":'"$uid"'[^}]*"state":"active"'
  check "the helper logs the creation" wait_for "$WAIT_DEADLINE" logged "INFO .*login=alice outcome=created uid=$uid exit=0"
}

scenario_exists_and_list() {
  ask alice
  check "the second request finds the account" answered '{"v":1,"result":"exists"}'
  check "list shows the active account" has_word "$("$BINARY" list)" active
  check "list --json shows the account present" grep -q '"account": "present"' <<<"$("$BINARY" list --json)"
}

scenario_disabled() {
  write_config false
  ask bob
  check "a disabled section answers disabled" answered '"result":"disabled"'
  write_config
  chmod 0664 "$CONFIG"
  ask bob
  check "a group writable configuration answers disabled" answered '"result":"disabled"'
  chmod 0644 "$CONFIG"
  chown jaunt "$CONFIG"
  ask bob
  check "a configuration owned by another user answers disabled" answered '"result":"disabled"'
  chown root "$CONFIG"
  chmod 0775 /etc/jaunt
  ask bob
  check "a group writable configuration directory answers disabled" answered '"result":"disabled"'
  chmod 0755 /etc/jaunt
  mv "$CONFIG" /etc/jaunt/real.yaml
  ln -s /etc/jaunt/real.yaml "$CONFIG"
  ask bob
  check "a configuration behind a symbolic link answers disabled" answered '"result":"disabled"'
  rm -f "$CONFIG"
  mv /etc/jaunt/real.yaml "$CONFIG"
  check "no account was created while disabled" account_absent bob
  check "the helper logs why it is disabled" wait_for "$WAIT_DEADLINE" logged 'WARN .*login=bob outcome=disabled detail=.*cannot be trusted'
}

scenario_refusals() {
  ask Bob
  check "a login that is not portable is refused" answered '"reason":"name_rule"'
  ask blocked
  check "a denied login is refused" answered '"reason":"name_rule"'
  ask postgres
  check "a reserved login is refused" answered '"reason":"reserved_name"'
  groupadd lonely
  ask lonely
  check "a login that names an existing group is refused" answered '"reason":"group_collision"'
  mkdir /home/stale
  ask stale
  check "a login whose home exists is refused" answered '"reason":"home_exists"'
  write_config true 30000 30999 1
  ask carol
  check "a full quota is refused" answered '"reason":"max_users"'
  write_config
  fill_attempts
  ask carol
  check "five attempts in a minute are refused" answered '"reason":"rate_limit"'
  reset_attempts
  for login in Bob blocked postgres lonely stale carol; do
    if account_present "$login"; then fail "refused login $login exists"; fi
  done
}

scenario_uid_range() {
  write_config true "$SQUATTER_FIRST" "$SQUATTER_LAST" 10
  ask frank
  check "a range without a free uid is refused as uid_range" answered '"reason":"uid_range"'
  check "nothing is left of the refused login" account_absent frank
  check "the refused login has no record" state_lacks '"login":"frank"'
  write_config
  reset_attempts
}

scenario_wrong_peer() {
  ask grace intruder
  check "a peer with another uid gets no answer" silent
  check "the rejected peer is logged with its uid" wait_for "$WAIT_DEADLINE" logged "WARN connection=rejected peer_uid=$(id -u intruder) "
  check "the rejected peer created nothing" account_absent grace
}

timed_reply() {
  local started
  started=$(now)
  last_status=0
  last_response=$(timeout "$CLIENT_DEADLINE" setpriv --reuid=jaunt --regid=jaunt --init-groups \
    socat -t 2 - "UNIX-CONNECT:$SOCKET" 2>>"$CLIENT_LOG" < <("$@")) || last_status=$?
  elapsed=$(($(now) - started))
}

slow_writer() {
  printf '{'
  for _ in $(seq 1 25); do
    sleep 1
    printf ' '
  done
}

silent_writer() { sleep 25; }

scenario_limits() {
  local long
  long=$(printf 'a%.0s' $(seq 1 2000))
  send_as jaunt "{\"v\":1,\"op\":\"ensure\",\"login\":\"$long\",\"ref\":\"H-0000000B\",\"session\":\"t-1\"}"
  check "a request over 1 KiB is refused at the request stage" answered '"stage":"request"'
  timed_reply slow_writer
  check "a client sending one byte a second is cut by the request budget" answered '"stage":"request"'
  check "the slow client is cut within 10 s (took ${elapsed}s)" [ "$elapsed" -le 10 ]
  timed_reply silent_writer
  check "a silent client is cut by the request budget" answered '"stage":"request"'
  check "the silent client is cut within 10 s (took ${elapsed}s)" [ "$elapsed" -le 10 ]
}

scenario_parallel() {
  reset_attempts
  (ask dave && printf '%s\n' "$last_response" >/tmp/parallel-1) &
  local first=$!
  (ask dave && printf '%s\n' "$last_response" >/tmp/parallel-2) &
  local second=$!
  wait "$first" "$second"
  local created exists
  created=$(cat /tmp/parallel-1 /tmp/parallel-2 | grep -c '"result":"created"' || true)
  exists=$(cat /tmp/parallel-1 /tmp/parallel-2 | grep -c '"result":"exists"' || true)
  check "two parallel requests for one login create it once and find it once" same_text "$created $exists" "1 1"
  check "exactly one passwd entry exists for the login" same_text "$(grep -c '^dave:' /etc/passwd)" 1
}

scenario_wrapped_failures() {
  reset_attempts
  wrap_useradd '/usr/sbin/useradd.real "$@"; exit 12'
  ask henry
  unwrap_useradd
  check "useradd exiting 12 is reported with its code" answered '"stage":"useradd","exit_code":12'
  check "the account left by exit 12 is rolled back" account_absent henry
  check "the rolled back group is gone" group_absent henry
  check "the rolled back home is gone" path_absent /home/henry
  check "the rolled back subordinate ids are gone" subids_absent henry
  check "the rolled back login has no record" state_lacks '"login":"henry"'
  check "the rollback is logged" wait_for "$WAIT_DEADLINE" logged 'login=henry outcome=failed stage=useradd .*exit=12 .*rollback=removed userdel_exit=0'

  wrap_useradd 'exit 4'
  ask irene
  unwrap_useradd
  check "useradd exiting 4 is refused as uid_range" answered '"reason":"uid_range"'
  check "nothing exists after exit 4" account_absent irene

  wrap_useradd '/usr/sbin/useradd.real "$@"; exit 9'
  ask ivan
  unwrap_useradd
  check "useradd exiting 9 is reported with its code" answered '"stage":"useradd","exit_code":9'
  check "the account behind exit 9 is never rolled back" account_present ivan
  check "the account behind exit 9 is not marked managed" state_lacks '"login":"ivan"'
  check "no rollback ran for exit 9" wait_for "$WAIT_DEADLINE" logged 'login=ivan outcome=failed stage=useradd uid=[0-9]+ exit=9$'
  reset_attempts
}

scenario_home_window() {
  reset_attempts
  write_config true 30000 30999 100 0700
  wrap_useradd 'for arg in "$@"; do login=$arg; done
/usr/sbin/useradd.real "$@"; status=$?
stat -c %a "/home/$login" >/tmp/mode-after-useradd; exit $status'
  ask lena
  unwrap_useradd
  write_config
  check "a login with home_mode 0700 is created" answered '"result":"created"'
  check "useradd itself creates the home no more open than home_mode" same_text "$(cat /tmp/mode-after-useradd)" 700
  check "the final home mode is home_mode" same_text "$(stat -c %a /home/lena)" 700
  reset_attempts
}

lacks_text() { ! grep -qF -- "$1" "$2"; }

scenario_inherited_descriptors() {
  reset_attempts
  rm -f "$USERADD_FDS" "$USERADD_STDIN"
  wrap_useradd "ls -l /proc/\$\$/fd >$USERADD_FDS 2>&1
readlink /proc/\$\$/fd/0 >$USERADD_STDIN 2>&1
exec /usr/sbin/useradd.real \"\$@\""
  ask nora
  unwrap_useradd
  check "a login created through the descriptor probe is created" answered '"result":"created"'
  check "useradd sees its descriptors" grep -q -- ' 0 -> ' "$USERADD_FDS"
  check "useradd inherits no socket" lacks_text 'socket:' "$USERADD_FDS"
  check "useradd inherits no descriptor of the state lock" lacks_text "$LOCK_PATH" "$USERADD_FDS"
  check "useradd inherits no descriptor of the state file" lacks_text accounts.json "$USERADD_FDS"
  check "useradd reads its standard input from /dev/null" same_text "$(cat "$USERADD_STDIN")" /dev/null
  reset_attempts
}

no_surviving_sleeper() { ! ps -eo stat=,args= | grep -v '^Z' | grep -q '[s]leep 31'; }

scenario_timeout() {
  reset_attempts
  wrap_useradd '/usr/sbin/useradd.real "$@"; sleep 31 & wait'
  local started
  started=$(now)
  ask judy
  local elapsed=$(($(now) - started))
  unwrap_useradd
  check "a useradd past 5 s is reported without an exit code" answered '{"v":1,"result":"failed","stage":"useradd"}'
  check "the timed out request with its rollback ends within 10 s (took ${elapsed}s)" in_range "$elapsed" 5 10
  check "the account left by the timed out useradd is rolled back" account_absent judy
  check "the whole process group of the timed out useradd is killed" wait_for "$WAIT_DEADLINE" no_surviving_sleeper
  check "the timeout is logged" wait_for "$WAIT_DEADLINE" logged 'login=judy outcome=failed stage=useradd .*exit=signal timed_out=yes rollback=removed'
}

scenario_untrusted_tool() {
  reset_attempts
  chmod g+w /usr/sbin
  ask mona
  chmod g-w /usr/sbin
  check "a group writable directory above useradd fails at the tool stage" answered '"stage":"tool"'
  chown jaunt /usr/sbin
  ask mona
  chown root /usr/sbin
  check "a directory above useradd owned by another user fails at the tool stage" answered '"stage":"tool"'
  check "no account is created with an untrusted tool" account_absent mona
  check "the untrusted directory is logged" wait_for "$WAIT_DEADLINE" logged 'login=mona outcome=failed stage=tool detail="/usr/sbin cannot be trusted: it is not owned by root"'
}

scenario_killed_helper() {
  reset_attempts
  wrap_useradd '/usr/sbin/useradd.real "$@"; kill -KILL "$PPID"; exit 0'
  ask kate
  unwrap_useradd
  check "a helper killed after useradd sends no answer" silent
  check "the account created before the kill exists" account_present kate
  check "the state still holds the pending record" state_has '"login":"kate",[^}]*"state":"pending"'
  ask kate
  check "the next request reconciles and finds the account" answered '"result":"exists"'
  check "the pending record becomes unconfirmed" state_has '"login":"kate",[^}]*"state":"unconfirmed"'
  check "the reconciliation is logged" wait_for "$WAIT_DEADLINE" logged 'WARN .*login=kate outcome=exists not_adopted=kate'
  check "list shows the unconfirmed account" grep -q 'kate  *unconfirmed' <<<"$("$BINARY" list)"
}

inside() {
  : >"$HELPER_LOG"
  : >"$CLIENT_LOG"
  prepare_image
  start_helper
  scenario_units
  scenario_created
  scenario_exists_and_list
  scenario_disabled
  scenario_refusals
  scenario_uid_range
  scenario_wrong_peer
  scenario_limits
  scenario_parallel
  scenario_wrapped_failures
  scenario_home_window
  scenario_inherited_descriptors
  scenario_timeout
  scenario_untrusted_tool
  scenario_killed_helper
  if [ "$failures" -ne 0 ]; then
    printf -- '---- helper log [%s] ----\n' "$label"
    cat "$HELPER_LOG"
    printf -- '---- client log [%s] ----\n' "$label"
    cat "$CLIENT_LOG"
  fi
  printf 'DONE [%s] %d failure(s)\n' "$label" "$failures"
  [ "$failures" -eq 0 ]
}

qualify_image() {
  case $1 in
    */*) printf '%s' "$1" ;;
    *) printf 'docker.io/library/%s' "$1" ;;
  esac
}

container=

cleanup() {
  if [ -n "$container" ]; then
    "$engine" rm --force --ignore "$container" >/dev/null 2>&1 || echo "could not remove container $container" >&2
  fi
}

native_reference() {
  local image=$1 arch image_arch digest reference
  arch=$("$engine" info --format '{{.Host.Arch}}')
  if ! image_arch=$("$engine" image inspect --format '{{.Architecture}}' "$image" 2>/dev/null); then
    "$engine" pull -q "$image" >/dev/null
    image_arch=$("$engine" image inspect --format '{{.Architecture}}' "$image")
  fi
  if [ "$image_arch" = "$arch" ]; then
    printf '%s' "$image"
    return
  fi
  digest=$("$engine" manifest inspect "$image" | python3 -I -c '
import json, sys
arch = sys.argv[1]
for entry in json.load(sys.stdin).get("manifests", []):
    platform = entry.get("platform", {})
    if platform.get("os") == "linux" and platform.get("architecture") == arch:
        print(entry["digest"])
        break
' "$arch")
  if [ -z "$digest" ]; then
    echo "$image has no linux/$arch variant" >&2
    return 1
  fi
  reference=${image%:*}@$digest
  if ! "$engine" image inspect "$reference" >/dev/null 2>&1; then
    "$engine" pull -q "$reference" >/dev/null
  fi
  printf '%s' "$reference"
}

run_image() {
  local image started status=0
  image=$(native_reference "$(qualify_image "$1")") || return 1
  container=jaunt-host-users-test-$(printf '%s' "$1" | tr -c 'a-zA-Z0-9' '-')-$$
  started=$(now)
  echo "testing the host users helper on $image"
  "$engine" run --rm --init --name "$container" --timeout "$CONTAINER_DEADLINE" \
    --security-opt label=disable \
    -e HOST_USERS_IMAGE="$1" \
    -v "$binary:$BINARY:ro" \
    -v "$script_path:/host-users-test.sh:ro" \
    -v "$repo/crates/jaunt-host-users/units:$UNITS:ro" \
    "$image" bash /host-users-test.sh --inside || status=$?
  container=
  echo "elapsed [$1] $(($(now) - started)) s"
  return "$status"
}

main() {
  if [ "$#" -eq 0 ]; then
    set -- "${DEFAULT_IMAGES[@]}"
  fi
  engine=${CONTAINER_ENGINE:-podman}
  script_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
  repo=$(cd "$(dirname "$script_path")/.." && pwd)
  binary=$repo/target/installer-linux/release/jaunt-host-users
  trap cleanup EXIT
  trap 'exit 130' INT TERM
  source "$repo/scripts/linux-build.sh"
  build_linux_binaries -p jaunt-host-users
  local image status=0 started
  started=$(now)
  for image in "$@"; do
    run_image "$image" || status=1
  done
  echo "elapsed total $(($(now) - started)) s"
  exit "$status"
}

if [ "${1:-}" = "--inside" ]; then
  inside
else
  main "$@"
fi
