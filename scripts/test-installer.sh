#!/usr/bin/env bash
set -euo pipefail

SSHD=/usr/sbin/sshd
AGENT=/usr/local/bin/jaunt-agent
HELPER=/usr/local/bin/jaunt-host-users
HELPER_STAGED=/staged/jaunt-host-users
HELPER_SOCKET=/etc/systemd/system/jaunt-host-users.socket
HELPER_SERVICE=/etc/systemd/system/jaunt-host-users@.service
HELPER_STATE_DIR=/var/lib/jaunt-host-users
HELPER_STATE=$HELPER_STATE_DIR/accounts.json
STATE_DIR=/var/lib/jaunt
CA_FILE=$STATE_DIR/inner-ca.pub
DROPIN=/etc/ssh/sshd_config.d/50-jaunt.conf
UNIT=/etc/systemd/system/jaunt-agent.service
CONFIG=/etc/jaunt/agent.yaml
HEADER='# Managed by jaunt-agent. Do not edit.'
CUSTOM_STATE_DIR=/opt/jaunt-custom/state
FOREIGN_CA=/etc/ssh/foreign-ca.pub
FOREIGN_DROPIN=/etc/ssh/sshd_config.d/10-foreign-ca.conf
SPECS=(
  "addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1,lport=22"
  "addr=::1,user=root,host=localhost,laddr=::1,lport=22"
  "addr=10.255.255.1,laddr=10.255.255.2,lport=22"
  "addr=203.0.113.9,laddr=203.0.113.10,lport=22"
)
ALL_ROOTS=(/etc/ssh /etc/jaunt /etc/systemd/system /var/lib/jaunt /opt/precious /opt/elsewhere)

failures=0
label=${INSTALLER_IMAGE:-local}
last_status=0
last_output=
baseline=

pass() { printf 'PASS [%s] %s\n' "$label" "$1"; }
fail() { printf 'FAIL [%s] %s\n' "$label" "$1"; failures=$((failures + 1)); }

check() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}

run_agent() {
  last_status=0
  last_output=$("$AGENT" "$@" 2>&1) || last_status=$?
}

run_agent_as_jaunt() {
  last_status=0
  last_output=$(runuser -u jaunt -- "$AGENT" "$@" 2>&1) || last_status=$?
}

output_has() { grep -qF -- "$1" <<<"$last_output"; }
output_lacks() { ! grep -qF -- "$1" <<<"$last_output"; }
first_line_is() { [ "$(head -n 1 "$2")" = "$1" ]; }
managed_checksums() { sha256sum "$DROPIN" "$UNIT" "$CONFIG"; }
status_is_zero() { [ "$last_status" -eq 0 ]; }
status_is_nonzero() { [ "$last_status" -ne 0 ]; }
absent() { [ ! -e "$1" ]; }
present() { [ -e "$1" ]; }
mode_is() { [ "$(stat -c '%a' "$2")" = "$1" ]; }
owner_is() { [ "$(stat -c '%U:%G' "$2")" = "$1" ]; }
has_line() { grep -qxF -- "$1" "$2"; }
is_empty_file() { [ -f "$1" ] && [ ! -s "$1" ]; }
user_absent() { ! getent passwd "${1:-jaunt}" >/dev/null; }
user_present() { getent passwd "${1:-jaunt}" >/dev/null; }
group_present() { getent group "$1" >/dev/null; }
user_shell_is_nologin() { [ "$(getent passwd jaunt | cut -d: -f7)" = /usr/sbin/nologin ]; }
user_home_is_state_dir() { [ "$(getent passwd jaunt | cut -d: -f6)" = "$STATE_DIR" ]; }
same_text() { [ "$1" = "$2" ]; }
same_file() { [ "$(cat "$1")" = "$(cat "$2")" ]; }
sshd_config_valid() { "$SSHD" -t; }

is_trusted() {
  local out
  out=$("$SSHD" -T -C "$1") || return 1
  [ "$(printf '%s\n' "$out" | sed -n 's/^trustedusercakeys //p')" = "$CA_FILE" ]
}

is_untrusted() {
  local out value
  out=$("$SSHD" -T -C "$1") || return 1
  [ -n "$out" ] || return 1
  value=$(printf '%s\n' "$out" | sed -n 's/^trustedusercakeys //p')
  [ -z "$value" ] || [ "$value" = none ]
}

effective_dump() {
  "$SSHD" -T
  local spec
  for spec in "${SPECS[@]}"; do
    echo "## $spec"
    "$SSHD" -T -C "$spec"
  done
}

capture_specs() {
  local prefix=$1 index
  "$SSHD" -T >"/tmp/$prefix-plain.txt"
  for index in "${!SPECS[@]}"; do
    "$SSHD" -T -C "${SPECS[$index]}" >"/tmp/$prefix-$index.txt"
  done
}

unchanged_spec() { same_file "/tmp/pre-$1.txt" "/tmp/post-$1.txt"; }

changed_only_in_the_trust_line() {
  local pre post
  pre=$(grep -v '^trustedusercakeys ' "/tmp/pre-$1.txt")
  post=$(grep -v '^trustedusercakeys ' "/tmp/post-$1.txt")
  [ "$pre" = "$post" ] && ! same_file "/tmp/pre-$1.txt" "/tmp/post-$1.txt"
}

manifest() {
  local roots=("$@")
  if [ "${#roots[@]}" -eq 0 ]; then
    roots=("${ALL_ROOTS[@]}")
  fi
  { find "${roots[@]}" -xdev 2>/dev/null || true; } | sort | while IFS= read -r path; do
    stat -c '%n %F %a %U:%G' "$path"
    if [ -f "$path" ] && [ ! -L "$path" ]; then sha256sum "$path"; fi
  done
}

restore_config() { cp -p /tmp/sshd_config.pristine /etc/ssh/sshd_config; }

non_loopback_address() {
  local line last=
  while IFS= read -r line; do
    case $line in
      *'|-- '*) last=${line#*'|-- '} ;;
      *'/32 host LOCAL'*)
        case $last in
          127.*) ;;
          *)
            printf '%s\n' "$last"
            return 0
            ;;
        esac
        ;;
    esac
  done </proc/net/fib_trie
  return 1
}

prepare_image() {
  export DEBIAN_FRONTEND=noninteractive
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null
    apt-get install -y -qq openssh-server openssh-client systemd >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q openssh-server openssh-clients systemd >/dev/null
  else
    echo "unsupported image: neither apt-get nor dnf is available" >&2
    exit 2
  fi
  mkdir -p /run/sshd
  ssh-keygen -A >/dev/null
  ssh-keygen -q -t ed25519 -N '' -f /tmp/test-ca
  cp -p /etc/ssh/sshd_config /tmp/sshd_config.pristine
  if [ -f /etc/pam.d/sshd ]; then
    sed -i 's/^\(session[[:space:]]\{1,\}\)required\([[:space:]]\{1,\}pam_loginuid.so\)/\1optional\2/' /etc/pam.d/sshd
  fi
}

test_main_config_without_include() {
  sed -i '/^[[:space:]]*Include[[:space:]]/d' /etc/ssh/sshd_config
  local before
  before=$(manifest)
  run_agent install --no-service
  check "no Include: install fails" status_is_nonzero
  check "no Include: message explains the missing Include" output_has "sshd_config.d"
  check "no Include: no file was touched" same_text "$(manifest)" "$before"
  check "no Include: no user was created" user_absent
  restore_config
}

test_listen_address_without_loopback() {
  sed -i '1i ListenAddress 192.0.2.1' /etc/ssh/sshd_config
  local before
  before=$(manifest)
  run_agent install --no-service
  check "ListenAddress 192.0.2.1 only: install fails" status_is_nonzero
  check "ListenAddress 192.0.2.1 only: message tells to add ListenAddress 127.0.0.1" output_has "ListenAddress 127.0.0.1"
  check "ListenAddress 192.0.2.1 only: no file was touched" same_text "$(manifest)" "$before"
  check "ListenAddress 192.0.2.1 only: no user was created" user_absent
  restore_config
}

test_state_dir_adoption_is_refused() {
  local before
  before=$(manifest)
  run_agent install --no-service --state-dir /etc/ssh
  check "state dir /etc/ssh: install fails" status_is_nonzero
  check "state dir /etc/ssh: message names the system directory" output_has "system directory"
  check "state dir /etc/ssh: nothing was touched, /etc/ssh keeps its mode and owner" same_text "$(manifest)" "$before"
  check "state dir /etc/ssh: no user was created" user_absent

  mkdir -p /opt/precious/state
  printf 'data\n' >/opt/precious/state/data
  chmod 755 /opt/precious/state
  before=$(manifest)
  run_agent install --no-service --state-dir /opt/precious/state
  check "existing non-empty state dir without inner-ca.pub: install fails" status_is_nonzero
  check "existing non-empty state dir without inner-ca.pub: message says it is not a Jaunt state directory" output_has "not a Jaunt state directory"
  check "existing non-empty state dir without inner-ca.pub: never chmod/chown-ed" same_text "$(manifest)" "$before"
  check "existing non-empty state dir without inner-ca.pub: no user was created" user_absent
  rm -rf /opt/precious
}

test_dry_run() {
  local before
  before=$(manifest)
  run_agent install --no-service --dry-run
  check "dry-run: exits zero" status_is_zero
  check "dry-run: prints the planned drop-in" output_has "plan: write $DROPIN"
  check "dry-run: changes no file" same_text "$(manifest)" "$before"
  check "dry-run: creates no user" user_absent
}

refuses_existing_trust() {
  local name=$1 before
  before=$(manifest)
  run_agent install --no-service
  check "pre-existing $name user CA: install fails" status_is_nonzero
  check "pre-existing $name user CA: message names the path" output_has "$FOREIGN_CA"
  check "pre-existing $name user CA: message names file and line" output_has "$FOREIGN_DROPIN:"
  check "pre-existing $name user CA: message states the requirement" output_has "trusts no user CA for outside connections"
  check "pre-existing $name user CA: nothing was changed" same_text "$(manifest)" "$before"
  check "pre-existing $name user CA: no user was created" user_absent
  check "pre-existing $name user CA: no state directory" absent "$STATE_DIR"
  check "pre-existing $name user CA: no /etc/jaunt" absent /etc/jaunt
  check "pre-existing $name user CA: no drop-in" absent "$DROPIN"
}

test_preexisting_user_ca_is_refused_before_any_change() {
  cp /tmp/test-ca.pub "$FOREIGN_CA"
  printf 'TrustedUserCAKeys %s\n' "$FOREIGN_CA" >"$FOREIGN_DROPIN"
  refuses_existing_trust global
  printf 'Match Address 127.0.0.1\n    TrustedUserCAKeys %s\n' "$FOREIGN_CA" >"$FOREIGN_DROPIN"
  refuses_existing_trust loopback
  printf 'Match Address 192.168.0.0/16\n    TrustedUserCAKeys %s\n' "$FOREIGN_CA" >"$FOREIGN_DROPIN"
  refuses_existing_trust "outside-subnet"
  printf 'Match User deploy\n    TrustedUserCAKeys %s\n' "$FOREIGN_CA" >"$FOREIGN_DROPIN"
  refuses_existing_trust "per-user"
  rm -f "$FOREIGN_DROPIN" "$FOREIGN_CA"
}

test_human_account_named_jaunt_blocks_install() {
  useradd -m -s /bin/bash jaunt
  local before
  before=$(manifest)
  run_agent install --no-service
  check "human account jaunt: install fails" status_is_nonzero
  check "human account jaunt: message says it is not a Jaunt service account" output_has "not a Jaunt service account"
  check "human account jaunt: nothing was changed" same_text "$(manifest)" "$before"
  check "human account jaunt: no state directory" absent "$STATE_DIR"
  check "human account jaunt: the account keeps its login shell" same_text "$(getent passwd jaunt | cut -d: -f7)" /bin/bash
  userdel -r jaunt >/dev/null 2>&1 || true
}

test_symlinked_state_dir_is_refused() {
  mkdir -p /opt/elsewhere
  chmod 755 /opt/elsewhere
  ln -s /opt/elsewhere "$STATE_DIR"
  local before
  before=$(manifest)
  run_agent install --no-service
  check "symlinked state dir: install fails" status_is_nonzero
  check "symlinked state dir: message says it is a symbolic link" output_has "symbolic link"
  check "symlinked state dir: nothing was changed, the link target keeps its mode and owner" same_text "$(manifest)" "$before"
  check "symlinked state dir: the link is still there" test -L "$STATE_DIR"
  check "symlinked state dir: no user was created" user_absent
  rm -f "$STATE_DIR"
  rmdir /opt/elsewhere
}

test_foreign_dropin_is_refused_and_kept() {
  printf '# my own sshd settings\nLogLevel INFO\n' >"$DROPIN"
  local before
  before=$(manifest)
  run_agent install --no-service
  check "foreign 50-jaunt.conf: install fails" status_is_nonzero
  check "foreign 50-jaunt.conf: message says it was not written by jaunt-agent" output_has "was not written by jaunt-agent"
  check "foreign 50-jaunt.conf: file left intact and nothing else changed" same_text "$(manifest)" "$before"
  check "foreign 50-jaunt.conf: no user was created" user_absent
  run_agent uninstall --no-service
  check "foreign 50-jaunt.conf: uninstall exits zero" status_is_zero
  check "foreign 50-jaunt.conf: uninstall warns that it keeps the file" output_has "not removing $DROPIN"
  check "foreign 50-jaunt.conf: uninstall leaves the file intact" same_text "$(manifest)" "$before"
  rm -f "$DROPIN"
}

test_foreign_config_is_refused_and_kept() {
  mkdir -p /etc/jaunt
  printf 'state_dir: /srv/mine/state\n' >"$CONFIG"
  local before
  before=$(manifest)
  run_agent install --no-service
  check "foreign agent.yaml: install fails" status_is_nonzero
  check "foreign agent.yaml: message says it was not written by jaunt-agent" output_has "was not written by jaunt-agent"
  check "foreign agent.yaml: message names the file" output_has "$CONFIG"
  check "foreign agent.yaml: file left intact and nothing else changed" same_text "$(manifest)" "$before"
  check "foreign agent.yaml: no user was created" user_absent
  check "foreign agent.yaml: no state directory" absent "$STATE_DIR"
  check "foreign agent.yaml: no drop-in" absent "$DROPIN"
  run_agent uninstall --no-service
  check "foreign agent.yaml: uninstall exits zero" status_is_zero
  check "foreign agent.yaml: uninstall warns that it keeps the file" output_has "not removing $CONFIG"
  check "foreign agent.yaml: uninstall leaves the file intact" same_text "$(manifest)" "$before"
  rm -rf /etc/jaunt
}

break_sshd_t() {
  mv "$SSHD" "$SSHD.real"
  cat >"$SSHD" <<'WRAPPER'
#!/bin/sh
case " $* " in
  *" -t "*)
    if [ -e /etc/ssh/sshd_config.d/50-jaunt.conf ]; then
      echo "simulated sshd -t failure" >&2
      exit 255
    fi
    ;;
esac
exec /usr/sbin/sshd.real "$@"
WRAPPER
  chmod 755 "$SSHD"
}

restore_sshd() { mv -f "$SSHD.real" "$SSHD"; }

test_failed_install_keeps_a_preexisting_group() {
  groupadd --system jaunt
  local gid before_all
  gid=$(getent group jaunt | cut -d: -f3)
  before_all=$(manifest)
  break_sshd_t
  run_agent install --no-service
  restore_sshd
  check "pre-existing group: the failed install fails" status_is_nonzero
  check "pre-existing group: the group survives the failed install" group_present jaunt
  check "pre-existing group: with the same gid" same_text "$(getent group jaunt | cut -d: -f3)" "$gid"
  check "pre-existing group: no user is left behind" user_absent
  check "pre-existing group: every watched directory is unchanged" same_text "$(manifest)" "$before_all"
  groupdel jaunt
}

test_validation_failure_rolls_back() {
  break_sshd_t
  local before_dump before_ssh before_all
  before_dump=$(effective_dump)
  before_ssh=$(manifest /etc/ssh)
  before_all=$(manifest)
  run_agent install --no-service
  check "failed validation: install fails" status_is_nonzero
  check "failed validation: message names the failed validation and the rollback" output_has "rollback"
  check "failed validation: new drop-in was removed" absent "$DROPIN"
  check "failed validation: unit was not written" absent "$UNIT"
  check "failed validation: /etc/ssh is byte-identical" same_text "$(manifest /etc/ssh)" "$before_ssh"
  check "failed validation: sshd -t passes after rollback" sshd_config_valid
  check "failed validation: effective sshd configuration unchanged" same_text "$(effective_dump)" "$before_dump"
  check "failed validation: the machine is clean again (no user)" user_absent
  check "failed validation: the machine is clean again (no state directory)" absent "$STATE_DIR"
  check "failed validation: the machine is clean again (no /etc/jaunt)" absent /etc/jaunt
  check "failed validation: every watched directory is unchanged" same_text "$(manifest)" "$before_all"
  restore_sshd
}

test_install() {
  capture_specs pre
  run_agent install --no-service
  if ! status_is_zero; then printf '%s\n' "$last_output"; fi
  capture_specs post
  check "install: exits zero" status_is_zero
  check "install: sshd -t passes" sshd_config_valid
  check "install: drop-in exists" present "$DROPIN"
  check "install: drop-in is 0644 root:root" mode_is 644 "$DROPIN"
  check "install: drop-in owner is root" owner_is root:root "$DROPIN"
  check "install: drop-in has the Match line" has_line "Match Address 127.0.0.1,::1" "$DROPIN"
  check "install: drop-in has the TrustedUserCAKeys line" has_line "    TrustedUserCAKeys $CA_FILE" "$DROPIN"
  check "install: unit has NoNewPrivileges=yes" has_line "NoNewPrivileges=yes" "$UNIT"
  check "install: unit has ProtectSystem=strict" has_line "ProtectSystem=strict" "$UNIT"
  check "install: unit is 0644 root:root" mode_is 644 "$UNIT"
  check "install: unit has LimitCORE=0" has_line "LimitCORE=0" "$UNIT"
  check "install: unit has MemorySwapMax=0" has_line "MemorySwapMax=0" "$UNIT"
  check "install: unit runs the agent with the config file" has_line "ExecStart=$AGENT run --config $CONFIG" "$UNIT"
  check "install: agent config exists" present "$CONFIG"
  check "install: agent config is 0644" mode_is 644 "$CONFIG"
  check "install: agent config owner is root" owner_is root:root "$CONFIG"
  check "install: agent config starts with the header" first_line_is "$HEADER" "$CONFIG"
  check "install: agent config has the state directory" has_line "state_dir: $STATE_DIR" "$CONFIG"
  check "install: agent config has the log level" has_line "log_level: info" "$CONFIG"
  run_agent_as_jaunt run --config "$CONFIG"
  check "install: run --config as user jaunt exits non-zero" status_is_nonzero
  check "install: run --config as user jaunt reports the state directory as not enrolled" output_has "$STATE_DIR holds no enrollment"
  check "install: /etc/jaunt is 0755 root:root" mode_is 755 /etc/jaunt
  check "install: state directory is 0700 jaunt:jaunt" mode_is 700 "$STATE_DIR"
  check "install: state directory owner is jaunt" owner_is jaunt:jaunt "$STATE_DIR"
  check "install: inner-ca.pub is empty" is_empty_file "$CA_FILE"
  check "install: inner-ca.pub is 0644 jaunt:jaunt" mode_is 644 "$CA_FILE"
  check "install: inner-ca.pub owner is jaunt" owner_is jaunt:jaunt "$CA_FILE"
  check "install: user jaunt exists" user_present
  check "install: user jaunt has a nologin shell" user_shell_is_nologin
  check "install: user jaunt home is the state directory" user_home_is_state_dir
  check "sshd -T -C ${SPECS[0]}: inner CA trusted" is_trusted "${SPECS[0]}"
  check "sshd -T -C ${SPECS[1]}: inner CA trusted" is_trusted "${SPECS[1]}"
  check "sshd -T -C ${SPECS[2]}: no user CA trusted" is_untrusted "${SPECS[2]}"
  check "sshd -T -C ${SPECS[3]}: no user CA trusted" is_untrusted "${SPECS[3]}"
  check "effective config without -C is byte-identical to the pre-install one" same_file /tmp/pre-plain.txt /tmp/post-plain.txt
  check "effective config for ${SPECS[2]} is byte-identical to the pre-install one" unchanged_spec 2
  check "effective config for ${SPECS[3]} is byte-identical to the pre-install one" unchanged_spec 3
  check "effective config for ${SPECS[0]} differs only in the trustedusercakeys line" changed_only_in_the_trust_line 0
  check "effective config for ${SPECS[1]} differs only in the trustedusercakeys line" changed_only_in_the_trust_line 1
}

test_second_install_changes_nothing() {
  cp /tmp/test-ca.pub "$CA_FILE"
  local before after managed_before
  before=$(manifest)
  managed_before=$(managed_checksums)
  run_agent install --no-service
  after=$(manifest)
  check "second install: exits zero" status_is_zero
  check "second install: checksums, modes and owners are unchanged" same_text "$after" "$before"
  check "second install: drop-in, unit and agent config checksums are unchanged" same_text "$(managed_checksums)" "$managed_before"
  check "second install: inner-ca.pub keeps its content" same_file /tmp/test-ca.pub "$CA_FILE"
  check "second install: sshd -T -C loopback still trusts the inner CA" is_trusted "${SPECS[0]}"
}

ssh_as_jtest() {
  ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -o IdentitiesOnly=yes -o PasswordAuthentication=no -o ConnectTimeout=10 \
    -i /tmp/login-user -o CertificateFile=/tmp/login-user-cert.pub "jtest@$1" true
}

login_is_refused_by_sshd() {
  local out status=0
  out=$(ssh_as_jtest "$1" 2>&1) || status=$?
  [ "$status" -ne 0 ] && grep -q 'Permission denied' <<<"$out"
}

start_sshd() {
  "$SSHD" -o PidFile=/tmp/sshd-test.pid -E /tmp/sshd-test.log
  for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/22) 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  return 1
}

stop_sshd() {
  if [ -f /tmp/sshd-test.pid ]; then
    kill "$(cat /tmp/sshd-test.pid)" || true
    rm -f /tmp/sshd-test.pid
  fi
}

test_real_login_is_trusted_only_from_loopback() {
  useradd -m -s /bin/bash jtest
  usermod -p '*' jtest
  ssh-keygen -q -t ed25519 -N '' -f /tmp/login-ca
  ssh-keygen -q -t ed25519 -N '' -f /tmp/login-user
  ssh-keygen -q -s /tmp/login-ca -I jaunt-login-proof -n jtest -V +10m /tmp/login-user.pub
  cp /tmp/login-ca.pub "$CA_FILE"
  check "login proof: sshd starts and listens on loopback" start_sshd
  local address
  address=$(non_loopback_address || true)
  check "login proof: the container has a non-loopback address" test -n "$address"
  check "login proof: certificate login from 127.0.0.1 succeeds" ssh_as_jtest 127.0.0.1
  if ! ssh_as_jtest 127.0.0.1 >/dev/null 2>&1; then
    tail -n 20 /tmp/sshd-test.log || true
  fi
  check "login proof: the same login from the non-loopback address ${address:-none} is refused by sshd" login_is_refused_by_sshd "${address:-203.0.113.1}"
  stop_sshd
  userdel -r jtest >/dev/null 2>&1 || true
}

test_uninstall() {
  run_agent uninstall --no-service
  check "uninstall: exits zero" status_is_zero
  check "uninstall: drop-in removed" absent "$DROPIN"
  check "uninstall: unit removed" absent "$UNIT"
  check "uninstall: agent config removed" absent "$CONFIG"
  check "uninstall: /etc/jaunt kept" present /etc/jaunt
  check "uninstall: sshd -t passes" sshd_config_valid
  check "uninstall: state directory kept" present "$STATE_DIR"
  check "uninstall: user kept" user_present
  check "uninstall: effective sshd configuration equals the one before install" same_text "$(effective_dump)" "$baseline"
  run_agent uninstall --no-service
  check "second uninstall is a no-op with exit 0" status_is_zero
  run_agent uninstall --purge --no-service
  check "uninstall --purge: exits zero" status_is_zero
  check "uninstall --purge: state directory removed" absent "$STATE_DIR"
  check "uninstall --purge: user removed" user_absent
  check "after purge: effective sshd configuration equals the original" same_text "$(effective_dump)" "$baseline"
}

test_purge_keeps_a_human_account() {
  useradd -m -s /bin/bash jaunt
  run_agent uninstall --purge --no-service
  check "purge with a human account named jaunt: exits zero" status_is_zero
  check "purge with a human account named jaunt: prints the warning" output_has "not removing user jaunt"
  check "purge with a human account named jaunt: the account is still there" user_present
  check "purge with a human account named jaunt: its home is still there" present /home/jaunt
  userdel -r jaunt >/dev/null 2>&1 || true
}

test_custom_state_dir_reaches_run() {
  run_agent install --no-service --state-dir "$CUSTOM_STATE_DIR"
  if ! status_is_zero; then printf '%s\n' "$last_output"; fi
  check "custom state dir: install exits zero" status_is_zero
  check "custom state dir: agent config has the custom state directory" has_line "state_dir: $CUSTOM_STATE_DIR" "$CONFIG"
  check "custom state dir: state directory owner is jaunt" owner_is jaunt:jaunt "$CUSTOM_STATE_DIR"
  run_agent_as_jaunt run --config "$CONFIG"
  check "custom state dir: run --config as user jaunt exits non-zero" status_is_nonzero
  check "custom state dir: run --config as user jaunt uses the state directory from the config" output_has "$CUSTOM_STATE_DIR holds no enrollment"
  run_agent uninstall --purge --no-service
  check "custom state dir: uninstall --purge exits zero" status_is_zero
  check "custom state dir: agent config removed" absent "$CONFIG"
  check "custom state dir: state directory removed" absent "$CUSTOM_STATE_DIR"
  check "custom state dir: user removed" user_absent
  check "custom state dir: effective sshd configuration equals the original" same_text "$(effective_dump)" "$baseline"
  rmdir /opt/jaunt-custom
}

test_custom_config_is_removed_only_with_the_same_flag() {
  local custom=/opt/jaunt-conf/agent.yaml
  run_agent install --no-service --config "$custom"
  if ! status_is_zero; then printf '%s\n' "$last_output"; fi
  check "custom config: install exits zero" status_is_zero
  check "custom config: written at the custom path" first_line_is "$HEADER" "$custom"
  check "custom config: nothing at the default path" absent "$CONFIG"
  check "custom config: unit runs the agent with the custom config" has_line "ExecStart=$AGENT run --config $custom" "$UNIT"
  run_agent uninstall --no-service
  check "custom config: uninstall without --config exits zero" status_is_zero
  check "custom config: uninstall without --config warns nothing is at the default path" output_has "no agent configuration was found at $CONFIG"
  check "custom config: uninstall without --config leaves the custom file" present "$custom"
  run_agent uninstall --purge --no-service --config "$custom"
  check "custom config: uninstall --config exits zero" status_is_zero
  check "custom config: uninstall --config removes the custom file" absent "$custom"
  check "custom config: user removed by the purge" user_absent
  check "custom config: effective sshd configuration equals the original" same_text "$(effective_dump)" "$baseline"
  rmdir /opt/jaunt-conf
}

helper_units_verify() {
  local out
  out=$(systemd-analyze verify "$HELPER_SOCKET" "$HELPER_SERVICE" 2>&1) || { printf '%s\n' "$out" >&2; return 1; }
  [ -z "$out" ] || { printf '%s\n' "$out" >&2; return 1; }
}

helper_checksums() { sha256sum "$HELPER_SOCKET" "$HELPER_SERVICE" "$CONFIG" "$UNIT" "$DROPIN"; }

write_helper_state() {
  install -d -o root -g root -m 0700 "$HELPER_STATE_DIR"
  printf '%s\n' '{"v":1,"accounts":[{"login":"alice","uid":30001,"gid":30001,"home":"/home/alice","created_at":1700000000,"ref":"H-0000ABCD","session":"s-9","state":"active"}],"attempts":[]}' >"$HELPER_STATE"
  chmod 0600 "$HELPER_STATE"
}

test_create_accounts() {
  install -o root -g root -m 0755 "$HELPER_STAGED" "$HELPER"
  local before
  chmod 0775 "$HELPER"
  before=$(manifest)
  run_agent install --no-service --create-accounts
  check "create accounts, group-writable helper: install fails" status_is_nonzero
  check "create accounts, group-writable helper: message names the helper and the fix" output_has "$HELPER is writable by group or others"
  check "create accounts, group-writable helper: nothing was changed" same_text "$(manifest)" "$before"
  check "create accounts, group-writable helper: no user was created" user_absent
  chmod 0755 "$HELPER"

  chmod 4755 "$HELPER"
  before=$(manifest)
  run_agent install --no-service --create-accounts
  check "create accounts, setuid helper: install fails" status_is_nonzero
  check "create accounts, setuid helper: message names the setuid bit" output_has "$HELPER has the setuid or setgid bit"
  check "create accounts, setuid helper: nothing was changed" same_text "$(manifest)" "$before"
  chmod 0755 "$HELPER"

  local usr_local_mode
  usr_local_mode=$(stat -c '%a' /usr/local)
  chmod 2775 /usr/local
  before=$(manifest)
  run_agent install --no-service --create-accounts
  check "create accounts, /usr/local 2775: install fails" status_is_nonzero
  check "create accounts, /usr/local 2775: message names the directory and its mode" output_has "/usr/local is writable by group or others (mode 2775)"
  check "create accounts, /usr/local 2775: message points to root-only places" output_has "for example /usr/bin"
  check "create accounts, /usr/local 2775: nothing was changed" same_text "$(manifest)" "$before"
  chmod "$usr_local_mode" /usr/local

  before=$(manifest)
  run_agent install --no-service --create-accounts --dry-run
  check "create accounts, dry-run: exits zero" status_is_zero
  check "create accounts, dry-run: plans the socket unit" output_has "plan: write $HELPER_SOCKET"
  check "create accounts, dry-run: changes no file" same_text "$(manifest)" "$before"

  run_agent install --no-service --create-accounts
  if ! status_is_zero; then printf '%s\n' "$last_output"; fi
  check "create accounts: install exits zero" status_is_zero
  check "create accounts: the helper was verified" output_has "verified: $HELPER is a regular file owned by root"
  check "create accounts: socket unit is 0644 root:root" mode_is 644 "$HELPER_SOCKET"
  check "create accounts: socket unit owner is root" owner_is root:root "$HELPER_SOCKET"
  check "create accounts: service unit is 0644 root:root" mode_is 644 "$HELPER_SERVICE"
  check "create accounts: service unit owner is root" owner_is root:root "$HELPER_SERVICE"
  check "create accounts: socket group is the agent account" has_line "SocketGroup=jaunt" "$HELPER_SOCKET"
  check "create accounts: service runs the helper next to the agent" has_line "ExecStart=$HELPER serve --config $CONFIG --agent-user jaunt" "$HELPER_SERVICE"
  check "create accounts: units have no unfilled placeholder" bash -c "! grep -q '{{' '$HELPER_SOCKET' '$HELPER_SERVICE'"
  check "create accounts: systemd-analyze verify accepts both units" helper_units_verify
  check "create accounts: agent config enables the section" has_line "  enabled: true" "$CONFIG"
  check "create accounts: agent config keeps the header" first_line_is "$HEADER" "$CONFIG"
  check "create accounts: the output says how to enable the socket" output_has "systemctl enable --now jaunt-host-users.socket"
  run_agent_as_jaunt run --config "$CONFIG"
  check "create accounts: run --config as user jaunt accepts the section and reports no enrollment" output_has "$STATE_DIR holds no enrollment"

  local after_first checksums
  after_first=$(manifest)
  checksums=$(helper_checksums)
  run_agent install --no-service --create-accounts
  check "create accounts, second install: exits zero" status_is_zero
  check "create accounts, second install: checksums, modes and owners are unchanged" same_text "$(manifest)" "$after_first"
  check "create accounts, second install: units, config, agent unit and drop-in checksums are unchanged" same_text "$(helper_checksums)" "$checksums"
  check "create accounts, second install: reports the socket unit unchanged" output_has "unchanged: $HELPER_SOCKET"

  sed -i 's/^  groups: \[\]$/  groups: [staff]/' "$CONFIG"
  after_first=$(manifest)
  checksums=$(helper_checksums)
  run_agent install --no-service
  check "create accounts, install without the flag: exits zero" status_is_zero
  check "create accounts, install without the flag: says the section is kept" output_has "kept: the host_users section of $CONFIG as it was (enabled: true)"
  check "create accounts, install without the flag: the edited section, the units and every file are unchanged" same_text "$(manifest)" "$after_first"
  check "create accounts, install without the flag: checksums are unchanged" same_text "$(helper_checksums)" "$checksums"
  check "create accounts, install without the flag: the edited groups survive" has_line "  groups: [staff]" "$CONFIG"

  install -d -o root -g root -m 0755 /srv/home
  sed -i 's|^  home_base: "/home"$|  home_base: /srv/home|' "$CONFIG"
  run_agent install --no-service --create-accounts
  check "create accounts, custom home_base: install exits zero" status_is_zero
  check "create accounts, custom home_base: the service unit writes there" has_line "ReadWritePaths=/etc /srv/home -/var/spool/mail /var/log" "$HELPER_SERVICE"
  check "create accounts, custom home_base: systemd-analyze verify accepts both units" helper_units_verify
  check "create accounts, custom home_base: no warning about a missing home_base" output_lacks "does not exist"

  useradd -m -s /bin/bash alice
  write_helper_state
  local state_sum
  state_sum=$(sha256sum "$HELPER_STATE")
  run_agent uninstall --no-service
  check "create accounts, uninstall: exits zero" status_is_zero
  check "create accounts, uninstall: socket unit removed" absent "$HELPER_SOCKET"
  check "create accounts, uninstall: service unit removed" absent "$HELPER_SERVICE"
  check "create accounts, uninstall: prints the number of kept accounts" output_has "kept: 1 account(s) listed in $HELPER_STATE"
  check "create accounts, uninstall: prints the list command" output_has "jaunt-host-users list"
  check "create accounts, uninstall: the helper state is kept" same_text "$(sha256sum "$HELPER_STATE")" "$state_sum"
  check "create accounts, uninstall: the created account is kept" user_present alice
  check "create accounts, uninstall: the helper binary is kept" present "$HELPER"
  run_agent uninstall --purge --no-service
  check "create accounts, uninstall --purge: exits zero" status_is_zero
  check "create accounts, uninstall --purge: the helper state is kept" same_text "$(sha256sum "$HELPER_STATE")" "$state_sum"
  check "create accounts, uninstall --purge: the created account is kept" user_present alice
  check "create accounts, uninstall --purge: its home is kept" present /home/alice
  check "create accounts, uninstall --purge: the service account is removed" user_absent
  check "create accounts: effective sshd configuration equals the original" same_text "$(effective_dump)" "$baseline"
  userdel -r alice >/dev/null 2>&1 || true
  rm -rf -- "${HELPER_STATE_DIR:?}"
  rm -f -- "$HELPER"
  rmdir /srv/home
}

inside() {
  prepare_image
  baseline=$(effective_dump)
  test_main_config_without_include
  test_listen_address_without_loopback
  test_state_dir_adoption_is_refused
  test_human_account_named_jaunt_blocks_install
  test_symlinked_state_dir_is_refused
  test_foreign_dropin_is_refused_and_kept
  test_foreign_config_is_refused_and_kept
  test_dry_run
  test_preexisting_user_ca_is_refused_before_any_change
  test_failed_install_keeps_a_preexisting_group
  test_validation_failure_rolls_back
  test_install
  test_second_install_changes_nothing
  test_real_login_is_trusted_only_from_loopback
  test_uninstall
  test_purge_keeps_a_human_account
  test_custom_state_dir_reaches_run
  test_custom_config_is_removed_only_with_the_same_flag
  test_create_accounts
  if [ "$failures" -ne 0 ]; then
    printf 'RESULT [%s]: %d assertion(s) failed\n' "$label" "$failures"
    exit 1
  fi
  printf 'RESULT [%s]: all assertions passed\n' "$label"
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

build_binary() {
  local rust_image
  rust_image=$(select_rust_image)
  echo "building the Linux agent binary in $rust_image"
  "$engine" run --rm --security-opt label=disable \
    -v "$repo:/src" -w /src \
    -v jaunt-installer-cargo-registry:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/src/target/installer-linux \
    "$rust_image" cargo build -p jaunt-agent -p jaunt-host-users --locked --release
}

run_image() {
  local image
  image=$(qualify_image "$1")
  echo "testing the installer on $image"
  "$engine" run --rm --security-opt label=disable \
    -e INSTALLER_IMAGE="$1" \
    -v "$binary:$AGENT:ro" \
    -v "$helper_binary:$HELPER_STAGED:ro" \
    -v "$script_path:/installer-test.sh:ro" \
    "$image" bash /installer-test.sh --inside
}

main() {
  if [ "$#" -lt 1 ]; then
    echo "usage: $0 <image>..." >&2
    exit 2
  fi
  engine=${CONTAINER_ENGINE:-podman}
  script_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
  repo=$(cd "$(dirname "$script_path")/.." && pwd)
  binary=$repo/target/installer-linux/release/jaunt-agent
  helper_binary=$repo/target/installer-linux/release/jaunt-host-users
  build_binary
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
