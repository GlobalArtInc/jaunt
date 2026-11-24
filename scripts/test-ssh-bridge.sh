#!/usr/bin/env bash
set -euo pipefail

AGENT=/usr/local/bin/jaunt-agent
STAND=/usr/local/bin/ssh-stand
STAND_DIR=/run/stand
STATE_DIR=/var/lib/jaunt
CONFIG=/etc/jaunt/agent.yaml
SSHD_LOG=/var/log/sshd.log
TARGET=deploy@node1.jaunt.test
DEADLINE=90

failures=0
passes=0
label=${BRIDGE_IMAGE:-local}
agent_pid=
agent_log=
last_status=0
last_out=
last_err=

pass() {
  printf 'PASS [%s] %s\n' "$label" "$1"
  passes=$((passes + 1))
}

fail() {
  printf 'FAIL [%s] %s\n' "$label" "$1"
  failures=$((failures + 1))
}

check() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}

wait_for() {
  local description=$1 deadline=$((SECONDS + DEADLINE))
  shift
  until "$@" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "timed out waiting for $description"
      return 1
    fi
    sleep 0.2
  done
}

lines() { if [ -f "$1" ]; then wc -l <"$1" | tr -d ' '; else echo 0; fi; }
accepted_logins() { grep -c 'Accepted publickey for deploy ' "$SSHD_LOG" || true; }
log_has() { grep -qF -- "$2" "$1"; }
status_is() { [ "$last_status" -eq "$1" ]; }
status_is_not_zero() { [ "$last_status" -ne 0 ]; }
out_is() { [ "$last_out" = "$1" ]; }
out_has() { grep -qF -- "$1" <<<"$last_out"; }
err_has() { grep -qF -- "$1" <<<"$last_err"; }
same() { [ "$1" = "$2" ]; }
grew_by() { [ $(($(lines "$1") - $2)) -eq "$3" ]; }
process_gone() { ! kill -0 "$1" 2>/dev/null; }
no_deploy_sessions() { ! pgrep -f '^sshd-session: deploy' >/dev/null; }

ssh_run() {
  local input=$1
  shift
  last_status=0
  last_out=$(printf '%b' "$input" | timeout "$DEADLINE" ssh -F "$STAND_DIR/client/config" "$@" 2>/tmp/ssh-err) || last_status=$?
  last_err=$(cat /tmp/ssh-err)
}

prepare_image() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq openssh-server openssh-client procps >/dev/null
  mkdir -p /run/sshd
  ssh-keygen -A >/dev/null
  if [ -f /etc/pam.d/sshd ]; then
    sed -i 's/^\(session[[:space:]]\{1,\}\)required\([[:space:]]\{1,\}pam_loginuid.so\)/\1optional\2/' /etc/pam.d/sshd
  fi
  useradd -m -s /bin/bash -p '*' deploy
}

start_agent() {
  agent_log=$1
  : >"$agent_log"
  setpriv --reuid=jaunt --regid=jaunt --init-groups -- "$AGENT" run --config "$CONFIG" >>"$agent_log" 2>&1 &
  agent_pid=$!
}

stop_agent() {
  kill -TERM "$agent_pid" 2>/dev/null || true
  wait_for "the agent to exit" process_gone "$agent_pid" || true
  wait "$agent_pid" 2>/dev/null || true
}

set_up_node() {
  "$AGENT" install --no-service >/tmp/install.log 2>&1
  check "install: sshd trusts inner-ca.pub for a connection to the 127.0.0.1 listener" sshd_trusts_loopback
  /usr/sbin/sshd -E "$SSHD_LOG"
  RUST_LOG=info "$STAND" "$STAND_DIR" >/var/log/stand.log 2>&1 &
  wait_for "the stand to listen" test -f "$STAND_DIR/ready"
  timeout "$DEADLINE" setpriv --reuid=jaunt --regid=jaunt --init-groups -- \
    "$AGENT" enroll --server http://127.0.0.1:7001 --name node1 --state-dir "$STATE_DIR" \
    >/tmp/enroll.log 2>&1
  check "enroll: the node holds an enrollment" test -s "$STATE_DIR/state.json"
}

sshd_trusts_loopback() {
  [ "$(/usr/sbin/sshd -T -C addr=127.0.0.1,user=deploy,host=localhost,laddr=127.0.0.1,lport=22 |
    sed -n 's/^trustedusercakeys //p')" = "$STATE_DIR/inner-ca.pub" ]
}

test_sessions() {
  start_agent /var/log/agent.log
  wait_for "the agent to accept SSH sessions" log_has "$agent_log" "the agent now accepts SSH sessions"
  check "start: inner-ca.pub holds the in-memory inner CA" grep -q '^ssh-ed25519 ' "$STATE_DIR/inner-ca.pub"

  local logins
  logins=$(accepted_logins)
  ssh_run '' "$TARGET" 'exit 7'
  check "exec: 'exit 7' returns 7 through the gate" status_is 7
  check "exec: sshd recorded the inner login with the session key id" grep -q 'Accepted publickey for deploy .*ID jaunt:stand-session-[0-9]*:alice@example.com' "$SSHD_LOG"

  ssh_run '' "$TARGET" id -un
  check "exec: id shows the login deploy" out_is deploy

  ssh_run 'echo shell-$((6*7))\nexit\n' -T "$TARGET"
  check "shell: a login shell runs commands" out_has shell-42
  ssh_run 'echo pty-$((6*7))\nexit\n' -tt "$TARGET"
  check "shell: a pty shell runs commands" out_has pty-42
  check "sshd: one inner login per session" same "$(accepted_logins)" "$((logins + 4))"
}

test_denial() {
  local logins authorized
  logins=$(accepted_logins)
  authorized=$(lines "$STAND_DIR/authorize.log")
  touch "$STAND_DIR/deny"
  ssh_run '' "$TARGET" true
  printf '%s\n' "$last_err" >/tmp/deny-err
  rm -f "$STAND_DIR/deny"
  check "deny: ssh fails" status_is_not_zero
  check "deny: the user sees an ordinary Permission denied" err_has "Permission denied"
  check "deny: control was asked once" grew_by "$STAND_DIR/authorize.log" "$authorized" 1
  check "deny: sshd recorded no login" same "$(accepted_logins)" "$logins"
}

offers_only_the_certificate() { ! grep 'Offering public key:' <<<"$last_err" | grep -qv '/run/stand/client/id-cert.pub'; }

test_extra_identity_file() {
  ssh-keygen -q -t ed25519 -N '' -C extra -f /tmp/extra-key
  local extra=(-o IdentityFile=/tmp/extra-key -v)
  ssh_run '' "${extra[@]}" "$TARGET" 'exit 7'
  check "extra identity file: the session works" status_is 7
  check "extra identity file: OpenSSH offers only the certificate when it is accepted" offers_only_the_certificate
  local logins
  logins=$(accepted_logins)
  touch "$STAND_DIR/deny"
  ssh_run '' "${extra[@]}" "$TARGET" true
  rm -f "$STAND_DIR/deny"
  grep -E 'Offering public key|Authentications that can continue' <<<"$last_err" >/tmp/extra-sequence
  printf 'INFO [%s] extra identity file, denied by control: %s\n' "$label" "$(grep -v '^debug' <<<"$last_err" | tr '\n' ' ')"
  check "extra identity file, denied: ssh fails" status_is_not_zero
  check "extra identity file, denied: OpenSSH offers the extra key after the refused certificate" err_has "Offering public key: /tmp/extra-key"
  check "extra identity file, denied: sshd recorded no login" same "$(accepted_logins)" "$logins"
}

session_running() { [ "$(accepted_logins)" -gt "$1" ]; }

test_restart_with_live_session() {
  local logins ends client
  logins=$(accepted_logins)
  ends=$(lines "$STAND_DIR/session-end.log")
  timeout "$DEADLINE" ssh -F "$STAND_DIR/client/config" "$TARGET" 'sleep 300' </dev/null >/dev/null 2>&1 &
  client=$!
  wait_for "the live session to log in" session_running "$logins" || true
  stop_agent
  check "restart: the agent stopped on SIGTERM" process_gone "$agent_pid"
  wait_for "the client to notice" process_gone "$client" || true
  wait "$client" 2>/dev/null || true
  check "restart: control got exactly one session_end" grew_by "$STAND_DIR/session-end.log" "$ends" 1
  check "restart: the session_end names a stand session" grep -q '"session_id":"stand-session-' "$STAND_DIR/session-end.log"
  wait_for "the deploy sshd sessions to close" no_deploy_sessions || true
  check "restart: sshd closed the deploy session" no_deploy_sessions
  ps -u deploy -o pid,ppid,args >/tmp/deploy-ps 2>&1
  pkill -u deploy || true
}

test_missing_trust() {
  local logins
  touch "$STAND_DIR/no-trust"
  start_agent /var/log/agent-no-trust.log
  wait_for "the tunnel" log_has "$agent_log" "the tunnel is connected"
  logins=$(accepted_logins)
  ssh_run '' "$TARGET" true
  check "no trust: ssh fails" status_is_not_zero
  check "no trust: the agent refused the stream" log_has "$agent_log" "trust_not_loaded"
  check "no trust: sshd recorded no login" same "$(accepted_logins)" "$logins"
  rm -f "$STAND_DIR/no-trust"
  wait_for "the trust set after it appears" log_has "$agent_log" "the agent now accepts SSH sessions"
  ssh_run '' "$TARGET" 'exit 7'
  check "no trust: sessions work once the trust set loads" status_is 7
  stop_agent
}

dump_logs() {
  local file
  for file in /tmp/extra-sequence /tmp/deny-err /tmp/deploy-ps /tmp/install.log /tmp/enroll.log /var/log/stand.log /var/log/agent.log /var/log/agent-no-trust.log "$SSHD_LOG"; do
    if [ -f "$file" ]; then
      echo "----- $file (tail)"
      tail -n 40 "$file"
    fi
  done
}

inside() {
  set +e
  prepare_image
  set_up_node
  test_sessions
  test_denial
  test_extra_identity_file
  test_restart_with_live_session
  test_missing_trust
  if [ "$failures" -ne 0 ]; then
    dump_logs
    printf 'RESULT [%s]: %d passed, %d failed\n' "$label" "$passes" "$failures"
    exit 1
  fi
  printf 'RESULT [%s]: %d passed, 0 failed\n' "$label" "$passes"
}

qualify_image() {
  case $1 in
    */*) printf '%s' "$1" ;;
    *) printf 'docker.io/library/%s' "$1" ;;
  esac
}

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

build_binaries() {
  local rust_image
  rust_image=$(select_rust_image)
  echo "building the Linux agent and test stand in $rust_image"
  "$engine" run --rm --security-opt label=disable \
    -v "$repo:/src" -w /src \
    -v jaunt-installer-cargo-registry:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/src/target/installer-linux \
    -e CARGO_INCREMENTAL=0 \
    "$rust_image" cargo build -p jaunt-agent --locked --release --bin jaunt-agent --example ssh_stand
}

run_image() {
  local image
  image=$(qualify_image "$1")
  echo "testing the SSH bridge on $image"
  "$engine" run --rm --security-opt label=disable \
    -e BRIDGE_IMAGE="$1" \
    -v "$binaries/jaunt-agent:$AGENT:ro" \
    -v "$binaries/examples/ssh_stand:$STAND:ro" \
    -v "$script_path:/bridge-test.sh:ro" \
    "$image" bash /bridge-test.sh --inside
}

main() {
  if [ "$#" -lt 1 ]; then
    echo "usage: $0 <image>..." >&2
    exit 2
  fi
  engine=${CONTAINER_ENGINE:-podman}
  script_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
  repo=$(cd "$(dirname "$script_path")/.." && pwd)
  binaries=$repo/target/installer-linux/release
  build_binaries
  local image status=0
  for image in "$@"; do
    run_image "$image" || status=1
  done
  exit "$status"
}

if [ "${1:-}" = "--inside" ]; then
  inside
else
  main "$@"
fi
