#!/bin/sh
set -eu
mkdir -p /run/sshd /run/e2e
rm -f /etc/ssh/ssh_host_*
ssh-keygen -A >/dev/null
jaunt-agent install --no-service >/run/e2e/install.log 2>&1
/usr/sbin/sshd -E /var/log/sshd.log
socat TCP-LISTEN:7001,bind=127.0.0.1,fork,reuseaddr TCP:jauntd:8443 &
forwarder=$!
touch /run/e2e/ready
stopping() {
  /e2e/agentctl.sh stop >/dev/null 2>&1 || true
  kill "$forwarder" 2>/dev/null || true
  if [ -f /run/sshd.pid ]; then
    kill "$(cat /run/sshd.pid)" 2>/dev/null || true
  fi
  exit 0
}
trap stopping TERM INT
while :; do
  sleep 1 &
  wait $!
done
