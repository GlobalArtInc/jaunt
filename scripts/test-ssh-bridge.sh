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
TRANSFER_DEADLINE=300
KILL_LIMIT=10
NODE_HOME=/home/deploy
WORK=/tmp/bridge-work
WWW=/tmp/www
SERVICE_PORT=8088
LOCAL_PORT=18088
FORWARD_DROPIN=/etc/ssh/sshd_config.d/00-jaunt-test-forwarding.conf
MARKER=jaunt-forward-marker
NOT_PERMITTED="jaunt: port forwarding is not allowed by your roles"
LOOPBACK_ONLY="jaunt: forwarding is limited to localhost on the node"
SLOW_ECHO_BYTES=268435456
SLOW_ECHO_LIMIT=60

failures=0
passes=0
label=${BRIDGE_IMAGE:-local}
agent_pid=
service_pid=
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
no_deploy_sessions() { ! pgrep -f '^sshd(-session)?: deploy' >/dev/null; }
deploy_session_open() { pgrep -f '^sshd(-session)?: deploy' >/dev/null; }
config() { printf '%s' "$STAND_DIR/client/config"; }
digest_of() { sha256sum "$1" | cut -d' ' -f1; }
tree_digest() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) | sha256sum | cut -d' ' -f1; }
sent_over() {
  case $1 in
    sftp) log_has /tmp/timed.log "Sending subsystem: sftp" && ! log_has /tmp/timed.log "Sending command: scp" ;;
    legacy) log_has /tmp/timed.log "Sending command: scp" && ! log_has /tmp/timed.log "Sending subsystem: sftp" ;;
  esac
}
listens_on() { ss -Hltn "sport = :$1" | grep -q LISTEN; }
agent_fds() { find "/proc/$agent_pid/fd" -mindepth 1 -maxdepth 1 | wc -l; }
fds_at_most() { [ "$(agent_fds)" -le "$1" ]; }
at_most() { awk -v value="$1" -v limit="$2" 'BEGIN { exit !(value <= limit) }'; }
now() { date +%s.%N; }
wait_stable() {
  local file=$1 quiet=$2 count since deadline=$((SECONDS + DEADLINE)) current
  count=$(lines "$file")
  since=$(now)
  until at_most "$quiet" "$(seconds_since "$since")"; do
    sleep 0.2
    current=$(lines "$file")
    if [ "$current" != "$count" ]; then
      count=$current
      since=$(now)
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "timed out waiting for $file to stay unchanged"
      return 1
    fi
  done
}
seconds_since() { awk -v start="$1" -v end="$(now)" 'BEGIN { printf "%.1f", end - start }'; }

ssh_run() {
  local input=$1
  shift
  last_status=0
  last_out=$(printf '%b' "$input" | timeout "$DEADLINE" ssh -F "$STAND_DIR/client/config" "$@" 2>/tmp/ssh-err) || last_status=$?
  last_err=$(cat /tmp/ssh-err)
}

prepare_image() {
  export DEBIAN_FRONTEND=noninteractive
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null
    apt-get install -y -qq openssh-server openssh-client procps iproute2 rsync python3 >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q openssh-server openssh-clients procps-ng iproute rsync python3 util-linux findutils >/dev/null
  else
    echo "unsupported image: neither apt-get nor dnf is available" >&2
    exit 2
  fi
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

timed() {
  local description=$1 started
  shift
  started=$(now)
  last_status=0
  timeout "$TRANSFER_DEADLINE" "$@" >/tmp/timed.log 2>&1 || last_status=$?
  printf 'TIME [%s] %s: %s s\n' "$label" "$description" "$(seconds_since "$started")"
}

report_environment() {
  local selinux="no selinuxfs in the container (SELinux cannot be enforcing here)"
  if [ -r /sys/fs/selinux/enforce ]; then
    selinux="selinuxfs enforce=$(cat /sys/fs/selinux/enforce)"
  fi
  printf 'INFO [%s] %s; sshd: %s; SELinux: %s\n' "$label" "$(ssh -V 2>&1)" \
    "$(/usr/sbin/sshd -V 2>&1 | head -n 1)" "$selinux"
}

test_scp() {
  local digest mode
  local -a flags
  mkdir -p "$WORK"
  head -c 1G /dev/urandom >"$WORK/big"
  digest=$(digest_of "$WORK/big")
  for mode in sftp legacy; do
    if [ "$mode" = sftp ]; then flags=(); else flags=(-O); fi
    timed "scp ($mode) upload of 1 GiB" scp -v -F "$(config)" "${flags[@]}" "$WORK/big" "$TARGET:big"
    check "scp ($mode): the 1 GiB upload succeeds" status_is 0
    check "scp ($mode): the upload used the $mode protocol" sent_over "$mode"
    check "scp ($mode): the uploaded file has the same sha256" same "$(digest_of "$NODE_HOME/big")" "$digest"
    timed "scp ($mode) download of 1 GiB" scp -v -F "$(config)" "${flags[@]}" "$TARGET:big" "$WORK/back"
    check "scp ($mode): the 1 GiB download succeeds" status_is 0
    check "scp ($mode): the download used the $mode protocol" sent_over "$mode"
    check "scp ($mode): the downloaded file has the same sha256" same "$(digest_of "$WORK/back")" "$digest"
    rm -f "$NODE_HOME/big" "$WORK/back"
  done
}

test_sftp() {
  local digest
  head -c 16M /dev/urandom >"$WORK/small"
  digest=$(digest_of "$WORK/small")
  printf 'put %s small\nls -l small\nget small %s\n' "$WORK/small" "$WORK/small-back" >"$WORK/batch"
  ssh_run_sftp
  check "sftp: the batch (put, ls, get) succeeds" status_is 0
  check "sftp: ls lists the uploaded file" out_has small
  check "sftp: the uploaded file has the same sha256" same "$(digest_of "$NODE_HOME/small")" "$digest"
  check "sftp: the downloaded file has the same sha256" same "$(digest_of "$WORK/small-back")" "$digest"
  rm -f "$NODE_HOME/small" "$WORK/small" "$WORK/small-back" "$WORK/batch"
}

ssh_run_sftp() {
  last_status=0
  last_out=$(timeout "$DEADLINE" sftp -F "$(config)" -b "$WORK/batch" "$TARGET" 2>/tmp/sftp-err) || last_status=$?
  last_err=$(cat /tmp/sftp-err)
}

test_rsync() {
  local digest index
  mkdir -p "$WORK/tree/sub"
  split -b 256M "$WORK/big" "$WORK/tree/part-"
  rm -f "$WORK/big"
  for index in $(seq 1 64); do head -c 4096 /dev/urandom >"$WORK/tree/sub/small-$index"; done
  digest=$(tree_digest "$WORK/tree")
  timed "rsync upload of a 1 GiB tree" rsync -a -e "ssh -F $(config)" "$WORK/tree/" "$TARGET:tree/"
  check "rsync: the 1 GiB tree upload succeeds" status_is 0
  check "rsync: the uploaded tree has the same sha256 per file" same "$(tree_digest "$NODE_HOME/tree")" "$digest"
  timed "rsync download of a 1 GiB tree" rsync -a -e "ssh -F $(config)" "$TARGET:tree/" "$WORK/tree-back/"
  check "rsync: the 1 GiB tree download succeeds" status_is 0
  check "rsync: the downloaded tree has the same sha256 per file" same "$(tree_digest "$WORK/tree-back")" "$digest"
  rm -rf "$NODE_HOME/tree" "$WORK/tree" "$WORK/tree-back"
}

http_get() {
  python3 -c 'import sys, urllib.request; print(urllib.request.urlopen(sys.argv[1], timeout=20).read().decode().strip())' "$1"
}

start_service() {
  mkdir -p "$WWW"
  printf '%s\n' "$MARKER" >"$WWW/marker"
  head -c 256M /dev/zero >"$WWW/big"
  (cd "$WWW" && exec python3 -m http.server --bind 127.0.0.1 "$SERVICE_PORT") >/tmp/www.log 2>&1 &
  service_pid=$!
  wait_for "the loopback service" listens_on "$SERVICE_PORT"
}

stdio_forward() {
  ssh_run 'GET /marker HTTP/1.0\r\n\r\n' -W "$1:$SERVICE_PORT" "$TARGET"
}

forward_refused_by_sshd() {
  stdio_forward localhost
  status_is_not_zero && err_has "administratively prohibited" && ! err_has "jaunt:"
}

refused_local_forward() {
  local local_port=$1 destination=$2 text=$3 log=$4 forward
  ssh -F "$(config)" -N -L "$local_port:$destination" "$TARGET" 2>"$log" &
  forward=$!
  wait_for "the local end of -L $destination" listens_on "$local_port"
  http_get "http://127.0.0.1:$local_port/" >/dev/null 2>&1
  wait_for "the refusal of -L $destination" log_has "$log" "$text"
  kill "$forward" 2>/dev/null
  wait "$forward" 2>/dev/null
}

forward_works() {
  stdio_forward localhost
  status_is 0 && out_has "$MARKER"
}

reload_sshd() {
  kill -HUP "$(cat /run/sshd.pid)"
}

test_forwarding() {
  local forward
  start_service
  stdio_forward localhost
  check "forward without the role permission: refused" status_is_not_zero
  check "forward without the role permission: the user sees why" err_has "$NOT_PERMITTED"
  refused_local_forward "$((LOCAL_PORT + 2))" "localhost:$SERVICE_PORT" "$NOT_PERMITTED" /tmp/forward-denied-err
  check "-L without the role permission: refused with the text" log_has /tmp/forward-denied-err "$NOT_PERMITTED"

  touch "$STAND_DIR/forward"
  ssh -F "$(config)" -o ExitOnForwardFailure=yes -N -L "$LOCAL_PORT:localhost:$SERVICE_PORT" "$TARGET" 2>/tmp/forward-err &
  forward=$!
  wait_for "the local end of -L" listens_on "$LOCAL_PORT"
  check "-L: the loopback service of the node answers through the forward" same "$(http_get "http://127.0.0.1:$LOCAL_PORT/marker" 2>/dev/null)" "$MARKER"
  kill "$forward" 2>/dev/null
  wait "$forward" 2>/dev/null

  refused_local_forward "$((LOCAL_PORT + 1))" 10.0.0.1:80 "$LOOPBACK_ONLY" /tmp/forward-other-err
  check "-L to another address: refused with the text" log_has /tmp/forward-other-err "$LOOPBACK_ONLY"

  stdio_forward 127.0.0.1
  check "-W 127.0.0.1: the request and its EOF reach the service, the answer comes back" out_has "$MARKER"
  check "-W 127.0.0.1: ssh exits 0" status_is 0
  stdio_forward 10.0.0.1
  check "-W to another address: refused" status_is_not_zero
  check "-W to another address: the user sees why" err_has "$LOOPBACK_ONLY"

  printf 'AllowTcpForwarding no\n' >"$FORWARD_DROPIN"
  reload_sshd
  wait_for "sshd to refuse forwarding" forward_refused_by_sshd
  check "AllowTcpForwarding no on the node: sshd's refusal reaches the user" forward_refused_by_sshd
  rm -f "$FORWARD_DROPIN"
  reload_sshd
  wait_for "sshd to allow forwarding again" forward_works
  check "AllowTcpForwarding back to the default: forwarding works again" forward_works
  rm -f "$STAND_DIR/forward"
}

slow_reader() {
  python3 -c '
import sys, time
total = 0
while True:
    chunk = sys.stdin.buffer.read1(32768)
    if not chunk:
        break
    total += len(chunk)
    time.sleep(0.001)
print(total)'
}

test_slow_reader() {
  local started elapsed
  started=$(now)
  last_status=0
  last_out=$(head -c "$SLOW_ECHO_BYTES" /dev/zero | timeout "$SLOW_ECHO_LIMIT" ssh -F "$(config)" "$TARGET" cat | slow_reader) || last_status=$?
  elapsed=$(seconds_since "$started")
  printf 'TIME [%s] echo of 256 MiB through a slow reader: %s s\n' "$label" "$elapsed"
  check "slow reader: every byte of the 256 MiB echo arrives" out_is "$SLOW_ECHO_BYTES"
  check "slow reader: the echo finishes within ${SLOW_ECHO_LIMIT} s" at_most "$elapsed" "$SLOW_ECHO_LIMIT"
}

test_kill_client() {
  local mode logins ends client started elapsed
  for mode in -tt -T; do
    logins=$(accepted_logins)
    ends=$(lines "$STAND_DIR/session-end.log")
    setsid ssh -F "$(config)" "$mode" "$TARGET" 'sleep 300' </dev/null >/dev/null 2>&1 &
    client=$!
    wait_for "the session to log in" session_running "$logins"
    wait_for "the deploy sshd session" deploy_session_open
    started=$(now)
    kill -KILL -- "-$client"
    wait_for "sshd to close the session after kill -9" no_deploy_sessions
    elapsed=$(seconds_since "$started")
    printf 'TIME [%s] sshd session gone after kill -9 of the client (%s): %s s\n' "$label" "$mode" "$elapsed"
    check "kill -9 ($mode): sshd closed the deploy session" no_deploy_sessions
    check "kill -9 ($mode): within ${KILL_LIMIT} s" at_most "$elapsed" "$KILL_LIMIT"
    wait_for "the session end" grew_by "$STAND_DIR/session-end.log" "$ends" 1
    wait_stable "$STAND_DIR/session-end.log" 2
    check "kill -9 ($mode): control got exactly one session_end" grew_by "$STAND_DIR/session-end.log" "$ends" 1
    wait "$client" 2>/dev/null
    pkill -u deploy sleep || true
  done
}

test_no_leaks() {
  local baseline session_bytes forward_bytes
  wait_for "no deploy sessions before the leak check" no_deploy_sessions
  baseline=$(agent_fds)
  session_bytes=$(timeout "$DEADLINE" ssh -F "$(config)" "$TARGET" 'cat /dev/zero' | head -c 64M | wc -c | tr -d ' ')
  touch "$STAND_DIR/forward"
  forward_bytes=$(printf 'GET /big HTTP/1.0\r\n\r\n' | timeout "$DEADLINE" ssh -F "$(config)" -W "localhost:$SERVICE_PORT" "$TARGET" 2>/dev/null | head -c 32M | wc -c | tr -d ' ')
  rm -f "$STAND_DIR/forward"
  check "leaks: the session moved 64 MiB before the client cut it" same "$session_bytes" 67108864
  check "leaks: the forward moved 32 MiB before the client cut it" same "$forward_bytes" 33554432
  wait_for "the sessions closed mid-transfer to end" no_deploy_sessions
  wait_for "the agent file descriptors to return to $baseline" fds_at_most "$baseline"
  printf 'INFO [%s] agent file descriptors: %s before, %s after two transfers cut by the client\n' "$label" "$baseline" "$(agent_fds)"
  check "leaks: the agent holds no more file descriptors after transfers cut by the client" fds_at_most "$baseline"
  check "leaks: the agent is still running" kill -0 "$agent_pid"
  ssh_run '' "$TARGET" 'exit 7'
  check "leaks: a new session still works" status_is 7
}

dump_logs() {
  local file
  for file in /tmp/forward-err /tmp/forward-denied-err /tmp/forward-other-err /tmp/timed.log /tmp/sftp-err /tmp/www.log /tmp/extra-sequence /tmp/deny-err /tmp/deploy-ps /tmp/install.log /tmp/enroll.log /var/log/stand.log /var/log/agent.log /var/log/agent-no-trust.log "$SSHD_LOG"; do
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
  report_environment
  test_forwarding
  test_scp
  test_sftp
  test_rsync
  test_slow_reader
  test_kill_client
  test_no_leaks
  kill "$service_pid" 2>/dev/null
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
