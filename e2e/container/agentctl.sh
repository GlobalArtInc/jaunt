#!/bin/sh
set -eu
AGENT=/usr/local/bin/jaunt-agent
STATE=/var/lib/jaunt
LOG=/tmp/agent.log
EXIT=/tmp/agent.exit
PIDFILE=/tmp/agent.pid
run_as_agent() {
  setpriv --reuid=jaunt --regid=jaunt --init-groups -- "$@"
}
case "${1:-}" in
  enroll)
    name=$2
    labels=$3
    pin=$4
    run_as_agent sh -c "exec '$AGENT' enroll --server http://127.0.0.1:7001 --name '$name' --labels '$labels' --ca-pin '$pin' --state-dir '$STATE' >/tmp/enroll.log 2>&1" &
    echo $! >/tmp/enroll.pid
    ;;
  start)
    rm -f "$EXIT"
    : >"$LOG"
    chmod 0666 "$LOG"
    run_as_agent sh -c "'$AGENT' run --config /etc/jaunt/agent.yaml >>'$LOG' 2>&1 & echo \$! >'$PIDFILE'; wait \$!; echo \$? >'$EXIT'" &
    ;;
  stop)
    if [ -f "$PIDFILE" ]; then
      kill -TERM "$(cat "$PIDFILE")" 2>/dev/null || true
    fi
    n=0
    while [ ! -f "$EXIT" ] && [ "$n" -lt 150 ]; do
      sleep 0.2
      n=$((n + 1))
    done
    if [ -f "$EXIT" ]; then cat "$EXIT"; else echo timeout; exit 1; fi
    ;;
  *)
    echo "usage: agentctl.sh enroll NAME LABELS PIN | start | stop" >&2
    exit 2
    ;;
esac
