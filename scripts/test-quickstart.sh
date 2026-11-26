#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
engine=${CONTAINER_ENGINE:-podman}
project=${QS_PROJECT:-jaunt-qs}
binaries=${QS_BINARIES:-$repo/target/installer-linux/release}
doc=$repo/docs/quickstart.md
work=${QS_WORK:-$repo/target/quickstart}
image=localhost/$project-base:1
network=$project
step_deadline=${QS_STEP_DEADLINE:-300}
persisted="CA_PIN ENROLL_CODE SESSION_ID"

suffix=qs.test
web_host=jaunt.$suffix
idp_host=idp.$suffix
client_user=alice
env_file=/root/.qs-env

started=$(date +%s)

die() {
  echo "test-quickstart: $*" >&2
  exit 1
}

say() {
  printf '== %s\n' "$*"
}

container() {
  printf '%s-%s' "$project" "$1"
}

cleanup() {
  for role in control node client idp; do
    "$engine" rm -f "$(container "$role")" >/dev/null 2>&1 || true
  done
  "$engine" network rm "$network" >/dev/null 2>&1 || true
}

leave() {
  local status=$?
  if [ -z "${QS_KEEP:-}" ]; then
    cleanup
  fi
  exit "$status"
}

require_inputs() {
  case $work in
    *..*) die "QS_WORK must not contain '..': $work" ;;
    /?*/?*) ;;
    *) die "QS_WORK must be an absolute path at least two levels deep: $work" ;;
  esac
  command -v "$engine" >/dev/null || die "$engine is not installed"
  [ -f "$doc" ] || die "missing $doc"
  for binary in jauntd jaunt-agent jaunt jaunt-fake-idp; do
    [ -x "$binaries/$binary" ] || die "missing $binaries/$binary: run e2e/build-binaries.sh"
  done
}

write_containerfile() {
  mkdir -p "$work/image"
  cat >"$work/image/Containerfile" <<'EOF'
FROM docker.io/library/debian:13
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    systemd systemd-sysv dbus openssh-server openssh-client curl ca-certificates socat openssl sudo procps iproute2 rsync python3 findutils \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash -p '*' deploy \
 && useradd -m -s /bin/bash -p '*' alice
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
}

build_image() {
  write_containerfile
  "$engine" build -q -t "$image" -f "$work/image/Containerfile" "$work/image" >/dev/null
}

write_certificate_script() {
  mkdir -p "$work/image"
  cat >"$work/image/mkcerts.sh" <<'EOF'
set -eu
cd /certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.pem -days 2 \
  -subj "/CN=jaunt quickstart test-only CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
for name in "$@"; do
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$name.key" -out "$name.csr" \
    -subj "/CN=$name" 2>/dev/null
  printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" "$name" >"$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$name.crt" -days 2 -extfile "$name.ext" 2>/dev/null
  cat "$name.crt" ca.pem >"$name.pem"
done
rm -f ca.key ca.srl ./*.csr ./*.ext ./*.crt
chmod 0644 ./*.pem
chmod 0600 ./*.key
EOF
}

make_certs() {
  rm -rf -- "${work:?}/certs"
  mkdir -p "$work/certs"
  write_certificate_script
  "$engine" run --rm --security-opt label=disable -v "$work/certs:/certs" -v "$work/image:/mk:ro" "$image" \
    sh /mk/mkcerts.sh "$web_host" "$idp_host"
}

start_containers() {
  "$engine" network create "$network" >/dev/null
  local certs="$work/certs"
  "$engine" run -d --name "$(container control)" --hostname control --network "$network" --network-alias "$web_host" \
    --systemd=always --cap-add SYS_ADMIN --security-opt label=disable -v "$certs:/certs:ro" "$image" >/dev/null
  "$engine" run -d --name "$(container node)" --hostname web-01 --network "$network" \
    --systemd=always --cap-add SYS_ADMIN --security-opt label=disable -v "$certs:/certs:ro" "$image" >/dev/null
  "$engine" run -d --name "$(container client)" --hostname laptop --network "$network" \
    --security-opt label=disable -v "$certs:/certs:ro" "$image" sleep infinity >/dev/null
  "$engine" run -d --name "$(container idp)" --hostname idp --network "$network" --network-alias "$idp_host" \
    --security-opt label=disable -v "$certs:/certs:ro" "$image" sleep infinity >/dev/null
}

on() {
  local role=$1
  shift
  "$engine" exec "$(container "$role")" "$@"
}

on_as() {
  local role=$1 user=$2
  shift 2
  "$engine" exec --user "$user" -e "HOME=/home/$user" -e "SSH_AUTH_SOCK=/tmp/ssh-agent.sock" "$(container "$role")" "$@"
}

wait_for() {
  local what=$1 seconds=$2
  shift 2
  local deadline=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      die "timed out after $seconds s waiting for: $what"
    fi
    sleep 1
  done
}

system_ready() {
  [[ "$("$engine" exec "$(container "$1")" systemctl is-system-running 2>/dev/null || true)" =~ ^(running|degraded)$ ]]
}

install_binary() {
  local role=$1 binary=$2
  "$engine" cp "$binaries/$binary" "$(container "$role"):/usr/local/bin/$binary"
  on "$role" chmod 0755 "/usr/local/bin/$binary"
}

prepare_idp() {
  local secret=quickstart-client-secret
  on idp sh -ec "
    mkdir -p /etc/idp
    printf '%s\n' '$secret' >/etc/idp/client-secret
    cat >/etc/idp/users.json <<'JSON'
[{\"login_hint\": \"alice\", \"subject\": \"qs-alice\", \"email\": \"alice@$suffix\", \"username\": \"alice\", \"name\": \"Alice Operator\", \"groups\": []}]
JSON
  "
  install_binary idp jaunt-fake-idp
  "$engine" exec -d "$(container idp)" /usr/local/bin/jaunt-fake-idp --listen 127.0.0.1:8080 \
    --issuer "https://$idp_host" --client-id jaunt --client-secret-file /etc/idp/client-secret \
    --redirect-uri "https://$web_host/v1/login/callback" --users /etc/idp/users.json
  "$engine" exec -d "$(container idp)" socat \
    "OPENSSL-LISTEN:443,bind=0.0.0.0,reuseaddr,fork,cert=/certs/$idp_host.pem,key=/certs/$idp_host.key,verify=0" TCP:127.0.0.1:8080
  QS_SECRET=$secret
}

prepare_control() {
  install_binary control jauntd
  "$engine" exec -d "$(container control)" socat \
    "OPENSSL-LISTEN:443,bind=0.0.0.0,reuseaddr,fork,cert=/certs/$web_host.pem,key=/certs/$web_host.key,verify=0" TCP:127.0.0.1:8443
}

prepare_node() {
  install_binary node jaunt-agent
  on node sh -ec '
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -A >/dev/null
    systemctl enable --now ssh >/dev/null 2>&1
  '
  "$engine" exec -d "$(container node)" socat TCP-LISTEN:7001,bind=127.0.0.1,fork,reuseaddr "OPENSSL:$web_host:443,cafile=/certs/ca.pem"
}

prepare_client() {
  install_binary client jaunt
  on client sh -ec "
    printf '%s\n' '#!/bin/sh' 'exec curl -sS -L --max-redirs 10 --max-time 30 --cacert /certs/ca.pem -b /home/$client_user/.idp-cookies -c /home/$client_user/.idp-cookies -o /dev/null \"\$1&login_hint=$client_user\"' >/usr/local/bin/xdg-open
    chmod 0755 /usr/local/bin/xdg-open
  "
  "$engine" exec -d "$(container client)" socat TCP-LISTEN:7002,bind=127.0.0.1,fork,reuseaddr "OPENSSL:$web_host:443,cafile=/certs/ca.pem"
  "$engine" exec -d --user "$client_user" "$(container client)" ssh-agent -D -a /tmp/ssh-agent.sock
  wait_for "the ssh-agent of $client_user" 20 on_as client "$client_user" test -S /tmp/ssh-agent.sock
}

seed_env() {
  local role=$1 url=$2 path=$3 owner=$4
  "$engine" exec -i "$(container "$role")" sh -ec "cat >'$path'; chown '$owner' '$path'" <<EOF
export JAUNT_HOST=$web_host
export JAUNT_URL=$url
export JAUNT_SUFFIX=nodes.$suffix
export OIDC_ISSUER=https://$idp_host
export OIDC_CLIENT_ID=jaunt
export OIDC_CLIENT_SECRET=$QS_SECRET
export ADMIN_EMAIL=alice@$suffix
export NODE_NAME=web-01
export NODE_LOGIN=deploy
export DEPLOY_BASE=file:///deploy
EOF
}

seed_envs() {
  seed_env control "http://127.0.0.1:8443" "$env_file" root
  seed_env node "http://127.0.0.1:7001" "$env_file" root
  seed_env client "http://127.0.0.1:7002" "/home/$client_user/.qs-env" "$client_user"
}

env_path() {
  if [ "$1" = client ]; then
    printf '/home/%s/.qs-env' "$client_user"
  else
    printf '%s' "$env_file"
  fi
}

share_persisted() {
  local source=$1 lines target
  lines=$("$engine" exec "$(container "$source")" sh -c "grep -E '^export ($(printf '%s' "$persisted" | tr ' ' '|'))=' '$(env_path "$source")' || true")
  [ -n "$lines" ] || return 0
  for target in control node client; do
    [ "$target" = "$source" ] && continue
    printf '%s\n' "$lines" | "$engine" exec -i "$(container "$target")" sh -c "cat >>'$(env_path "$target")'"
  done
}

split_steps() {
  rm -rf -- "${work:?}/steps"
  mkdir -p "$work/steps"
  awk -v dir="$work/steps" '
    /^```sh quickstart-step / {
      count++
      role = $3
      name = $4
      flags = ""
      for (i = 5; i <= NF; i++) flags = flags " " $i
      file = sprintf("%s/%02d-%s-%s", dir, count, role, name)
      printf "%s\n", flags > (file ".flags")
      inside = 1
      next
    }
    /^```$/ && inside { inside = 0; close(file); close(file ".flags"); next }
    inside { print > (file ".sh") }
  ' "$doc"
  ls "$work/steps"/*.sh >/dev/null 2>&1 || die "no quickstart-step blocks found in $doc"
}

run_step() {
  local file=$1 role=$2 name=$3 flags=$4
  local container_name path user_args=() script=/tmp/qs-step.sh
  container_name=$(container "$role")
  path=$(env_path "$role")
  if [ "$role" = client ]; then
    user_args=(--user "$client_user" -e "HOME=/home/$client_user" -e "SSH_AUTH_SOCK=/tmp/ssh-agent.sock")
  fi
  "$engine" cp "$file" "$container_name:$script"
  if [ "$role" = client ]; then
    "$engine" exec -u root "$container_name" chown "$client_user" "$script"
  fi
  local wrapper
  wrapper=". '$path'; set -eu; . $script; for v in $persisted; do if [ -n \"\${!v+x}\" ]; then printf 'export %s=%q\\n' \"\$v\" \"\${!v}\"; fi; done >>'$path'"
  if [[ "$flags" == *background* ]]; then
    "$engine" exec -d ${user_args[@]+"${user_args[@]}"} "$container_name" bash -c "($wrapper) >/tmp/qs-$name.log 2>&1; echo \$? >/tmp/qs-$name.rc"
    return 0
  fi
  if ! "$engine" exec ${user_args[@]+"${user_args[@]}"} "$container_name" timeout "$step_deadline" bash -c "$wrapper" </dev/null; then
    die "step $role/$name failed"
  fi
}

after_step() {
  local role=$1 name=$2 flags=$3
  if [[ "$flags" == *background* ]]; then
    wait_for "the enrolment code of $name" 60 "$engine" exec "$(container "$role")" grep -q '^code:' "/tmp/qs-$name.log"
    local code
    code=$("$engine" exec "$(container "$role")" sh -c "sed -n 's/^code: *//p' /tmp/qs-$name.log | head -n 1")
    [ -n "$code" ] || die "no enrolment code printed by $name"
    for target in control node client; do
      printf 'export ENROLL_CODE=%s\n' "$code" | "$engine" exec -i "$(container "$target")" sh -c "cat >>'$(env_path "$target")'"
    done
    "$engine" exec "$(container "$role")" cat "/tmp/qs-$name.log"
    return 0
  fi
  share_persisted "$role"
  if [ "$role" = control ] && [ "$name" = approve ]; then
    wait_for "the node enrolment to finish" 120 "$engine" exec "$(container node)" test -f /tmp/qs-enroll.rc
    [ "$("$engine" exec "$(container node)" cat /tmp/qs-enroll.rc)" = 0 ] || {
      "$engine" exec "$(container node)" cat /tmp/qs-enroll.log >&2
      die "jaunt-agent enroll failed"
    }
  fi
}

copy_deploy() {
  "$engine" exec "$(container control)" mkdir -p /deploy
  "$engine" cp "$repo/deploy/." "$(container control):/deploy/"
}

wait_steps_ready() {
  wait_for "systemd on the control host" 90 system_ready control
  wait_for "systemd on the node" 90 system_ready node
}

wait_agent_connected() {
  local deadline=$((SECONDS + 60))
  until on control sh -c "journalctl -u jauntd --no-pager | grep -q agent.connected"; do
    [ "$SECONDS" -lt "$deadline" ] || die "the agent did not connect within 60 s"
    sleep 1
  done
}

run_all() {
  local file base role name flags
  for file in "$work"/steps/*.sh; do
    base=$(basename "$file" .sh)
    role=$(printf '%s' "$base" | cut -d- -f2)
    name=$(printf '%s' "$base" | cut -d- -f3-)
    flags=$(cat "${file%.sh}.flags")
    if [ "$name" = undo ] && [ -n "${QS_SKIP_UNDO:-}" ]; then
      continue
    fi
    say "$role: $name"
    cat "$file"
    run_step "$file" "$role" "$name" "$flags"
    after_step "$role" "$name" "$flags"
    if [ "$role" = control ] && [ "$name" = config ]; then
      on control sed -i '/client_secret_file:/a\  extra_root_certificates_file: /certs/ca.pem' /etc/jaunt/jauntd.yaml
    fi
    if [ "$role" = node ] && [ "$name" = start ]; then
      wait_agent_connected
    fi
  done
}

main() {
  require_inputs
  trap leave EXIT
  cleanup
  mkdir -p "$work"
  say "building the base image"
  build_image
  make_certs
  start_containers
  wait_steps_ready
  prepare_idp
  prepare_control
  prepare_node
  prepare_client
  copy_deploy
  seed_envs
  split_steps
  say "running the quickstart blocks"
  run_all
  say "quickstart passed in $(( $(date +%s) - started )) s"
}

main "$@"
