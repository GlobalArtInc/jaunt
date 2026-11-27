import json
import re
import time

from stand.engine import exec_detached, exec_in
from stand.layout import container
from stand.report import StepFailed
from stand.stand import HELPER_DIST, HELPER_LOG

BIN_DIR = "/opt/jaunt/bin"
AGENT_BIN = BIN_DIR + "/jaunt-agent"
HELPER_BIN = BIN_DIR + "/jaunt-host-users"
SOCKET = "/run/jaunt/host-users.sock"
STATE_FILE = "/var/lib/jaunt-host-users/accounts.json"
CONFIG = "/etc/jaunt/agent.yaml"
MANAGED_HEAD = "# Managed by jaunt-agent. Do not edit.\nstate_dir: /var/lib/jaunt\nlog_level: info\n"
HELPER_PID = "/run/e2e/helper.pid"
USERADD = "/usr/sbin/useradd"
USERADD_REAL = USERADD + ".real"
GROUP = "jaunt-users"
UID_MIN = 30000
UID_MAX = 30999
REF = re.compile(r"\bH-[0-9A-F]{8}\b")
REQUEST = '{{"v":1,"op":"ensure","login":"{login}","ref":"H-0000ABCD","session":"e2e-direct"}}'
START_HELPER = """#!/bin/sh
set -eu
mkdir -p /run/jaunt /run/e2e
chmod 0755 /run/jaunt
rm -f /run/jaunt/host-users.sock
echo $$ >/run/e2e/helper.pid
exec systemd-socket-activate --listen=/run/jaunt/host-users.sock --accept --inetd \\
  {binary} serve --config /etc/jaunt/agent.yaml --agent-user jaunt >>{log} 2>&1
"""
DELAY_USERADD = """#!/bin/sh
sleep {seconds}
exec {real} "$@"
"""
HOLD_USERADD = """#!/bin/sh
: >/run/e2e/useradd-entered
n=0
while [ ! -e /run/e2e/useradd-release ] && [ "$n" -lt 80 ]; do
  sleep 0.1
  n=$((n + 1))
done
exec {real} "$@"
"""


def sh(stand, node, script, user=None, timeout=120):
    return stand.on_node(node, ["sh", "-c", script], user=user, timeout=timeout)


def write_file(stand, node, path, text, mode="0644"):
    done = exec_in(container(node), [
        "sh", "-c", 'printf "%s" "$0" >"$1" && chmod "$2" "$1"', text, path, mode,
    ])
    if not done.ok:
        raise StepFailed("cannot write {} on {}: {}".format(path, node, done.text()))


def section_text(enabled=True, groups=(GROUP,), deny=("hu-denied",), uid_min=UID_MIN, uid_max=UID_MAX,
                 max_users=100, home_mode="0750", allow_with_directory=False):
    return "\n".join([
        "host_users:",
        "  enabled: {}".format("true" if enabled else "false"),
        "  groups: [{}]".format(", ".join('"{}"'.format(group) for group in groups)),
        "  privileged_groups: []",
        '  shell: "/bin/bash"',
        '  home_base: "/home"',
        '  home_mode: "{}"'.format(home_mode),
        "  uid_min: {}".format(uid_min),
        "  uid_max: {}".format(uid_max),
        "  max_users: {}".format(max_users),
        "  names:",
        "    deny: [{}]".format(", ".join('"{}"'.format(name) for name in deny)),
        "    deny_prefixes: []",
        "    allow_prefixes: []",
        "  allow_with_directory: {}".format("true" if allow_with_directory else "false"),
        "",
    ])


def write_section(stand, node, **settings):
    write_file(stand, node, CONFIG, MANAGED_HEAD + section_text(**settings))


def install_creating(stand, node):
    prepared = sh(stand, node, "set -e; install -d -m 0755 -o root -g root {d}; "
                  "install -m 0755 -o root -g root /usr/local/bin/jaunt-agent {a}; "
                  "install -m 0755 -o root -g root {dist} {h}".format(d=BIN_DIR, a=AGENT_BIN, dist=HELPER_DIST, h=HELPER_BIN))
    if not prepared.ok:
        raise StepFailed("cannot place the binaries on {}: {}".format(node, prepared.text()))
    return install_again(stand, node)


def install_again(stand, node):
    flags = [] if stand.nodes[node].get("systemd") else ["--no-service"]
    return stand.on_node(node, [AGENT_BIN, "install", "--create-accounts", *flags, "--binary", AGENT_BIN], timeout=180)


def prepare_host(stand, node):
    done = sh(stand, node, "set -e; getent group {g} >/dev/null || groupadd {g}; "
                "install -d -m 0700 -o root -g root /var/lib/jaunt-host-users".format(g=GROUP))
    if not done.ok:
        raise StepFailed("cannot prepare {}: {}".format(node, done.text()))


def helper_script(stand, node):
    write_file(stand, node, "/run/e2e/start-helper.sh", START_HELPER.format(binary=HELPER_BIN, log=HELPER_LOG), "0755")


def start_helper(stand, node):
    helper_script(stand, node)
    started = exec_detached(container(node), ["sh", "/run/e2e/start-helper.sh"])
    if not started.ok:
        raise StepFailed("cannot start the helper on {}: {}".format(node, started.text()))
    stand.wait_until("the helper socket on {}".format(node), lambda: stand.on_node(node, ["test", "-S", SOCKET]).ok, 20)
    shared = sh(stand, node, "chown root:jaunt {s} && chmod 0660 {s}".format(s=SOCKET))
    if not shared.ok:
        raise StepFailed("cannot share the helper socket on {}: {}".format(node, shared.text()))


def stop_helper(stand, node):
    sh(stand, node, 'if [ -f {pid} ]; then kill "$(cat {pid})" 2>/dev/null || true; fi; rm -f {s}'.format(pid=HELPER_PID, s=SOCKET))


def socket_facts(stand, node):
    return stand.on_node(node, ["stat", "-c", "%U:%G %a %F", SOCKET]).out.strip()


def helper_log(stand, node):
    return stand.on_node(node, ["sh", "-c", "cat {} 2>/dev/null || true".format(HELPER_LOG)]).out


def helper_lines(stand, node, login):
    return [line for line in helper_log(stand, node).splitlines() if " login={} ".format(login) in line + " "]


def helper_contacts(stand, node):
    return helper_log(stand, node).count("Communication attempt")


def agent_log(stand, node):
    if stand.nodes[node].get("systemd"):
        return stand.on_node(node, ["journalctl", "-u", "jaunt-agent", "-o", "cat", "--no-pager"], timeout=60).out
    return stand.on_node(node, ["sh", "-c", "cat /tmp/agent-saved-*.log /tmp/agent.log 2>/dev/null || true"]).out


def agent_events(stand, node):
    text = agent_log(stand, node)
    events = []
    for line in text.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        fields = dict(entry.get("fields", {}))
        fields["timestamp"] = entry.get("timestamp")
        if "login" in fields:
            fields["login"] = fields["login"].strip('"')
        if "event" in fields:
            events.append(fields)
    return events


def agent_events_of(stand, node, event, login):
    return [fields for fields in agent_events(stand, node) if fields["event"] == event and fields.get("login") == login]


def restart_agent(stand, node):
    if stand.nodes[node].get("systemd"):
        stand.on_node(node, ["systemctl", "reset-failed", "jaunt-agent"])
        restarted = stand.on_node(node, ["systemctl", "restart", "jaunt-agent"], timeout=90)
        if not restarted.ok:
            raise StepFailed("cannot restart the agent on {}: {}".format(node, restarted.text()))
        return
    stopped = stand.agent_stop(node)
    if stopped != "0":
        raise StepFailed("the agent on {} stopped with {}".format(node, stopped))
    stand.agent_start(node)


def creates_accounts(stand, node):
    status, listed = stand.api("GET", "/v1/admin/nodes")
    if status != 200 or not listed:
        raise StepFailed("the node list answered {}".format(status))
    for entry in listed["nodes"]:
        if entry["name"] == node:
            return entry.get("creates_accounts") is True
    raise StepFailed("{} is not in the node list".format(node))


def wait_creates_accounts(stand, node, expected, timeout=90):
    started = time.monotonic()
    stand.wait_until("{} reports creates_accounts={}".format(node, str(expected).lower()),
                     lambda: creates_accounts(stand, node) is expected, timeout, interval=1)
    return time.monotonic() - started


def account_facts(stand, node, login):
    shown = stand.on_node(node, ["sh", "-c", "getent passwd {l} && id -u {l} && stat -c '%a %U %G' /home/{l}".format(l=login)])
    return shown.out.strip().splitlines() if shown.ok else None


def managed_accounts(stand, node):
    shown = stand.on_node(node, [HELPER_BIN, "list", "--json"])
    if not shown.ok:
        raise StepFailed("jaunt-host-users list failed on {}: {}".format(node, shown.text()))
    return json.loads(shown.out)["accounts"]


def attempts_in_window(stand, node):
    state = stand.on_node(node, ["sh", "-c", "cat {} 2>/dev/null || true".format(STATE_FILE)]).out
    if not state.strip():
        return 0
    now = int(stand.on_node(node, ["date", "+%s"]).out.strip())
    return len([at for at in json.loads(state).get("attempts", []) if now - at < 60])


def wait_rate_window_clear(stand, node):
    stand.wait_until("the creation rate window of {} to empty".format(node),
                     lambda: attempts_in_window(stand, node) == 0, 75, interval=2)


def set_use_pam(stand, node, value):
    write_file(stand, node, "/etc/ssh/sshd_config.d/00-e2e-pam.conf", "UsePAM {}\n".format(value))
    reload_sshd(stand, node)
    shown = stand.on_node(node, ["sshd", "-T"]).out
    if "usepam {}".format(value) not in shown:
        raise StepFailed("sshd on {} does not show usepam {}".format(node, value))


def reload_sshd(stand, node):
    checked = stand.on_node(node, ["/usr/sbin/sshd", "-t"])
    if not checked.ok:
        raise StepFailed("sshd -t failed on {}: {}".format(node, checked.text()))
    signalled = sh(stand, node, 'kill -HUP "$(cat /run/sshd.pid)"')
    if not signalled.ok:
        raise StepFailed("cannot signal sshd on {}: {}".format(node, signalled.text()))
    stand.wait_until("sshd on {} to answer".format(node), lambda: sshd_answers(stand, node), 20, interval=0.5)


def sshd_answers(stand, node):
    return stand.on_node(node, ["sh", "-c", "ssh-keyscan -T 3 -p 22 127.0.0.1 2>/dev/null | grep -q ssh-"]).ok


def wrap_useradd(stand, node, script):
    done = sh(stand, node, "set -e; mv {u} {r}".format(u=USERADD, r=USERADD_REAL))
    if not done.ok:
        raise StepFailed("cannot wrap useradd on {}: {}".format(node, done.text()))
    write_file(stand, node, USERADD, script.format(real=USERADD_REAL, seconds=0), "0755")


def hold_useradd(stand, node):
    sh(stand, node, "rm -f /run/e2e/useradd-entered /run/e2e/useradd-release")
    wrap_useradd(stand, node, HOLD_USERADD)


def delay_useradd(stand, node, seconds):
    wrap_useradd(stand, node, DELAY_USERADD.replace("{seconds}", str(seconds)))


def release_useradd(stand, node):
    sh(stand, node, "touch /run/e2e/useradd-release")


def restore_useradd(stand, node):
    sh(stand, node, "if [ -f {r} ]; then mv -f {r} {u}; fi; rm -f /run/e2e/useradd-entered /run/e2e/useradd-release".format(r=USERADD_REAL, u=USERADD))

