import re

from stand.engine import exec_detached
from stand.layout import container
from scenarios import host_users_kit as kit
from scenarios.host_users import control_created, only_denial

NODE = "node-a"
LOGIN = "hu-sd1"
DIRECTORY_LOGIN = "hu-sd2"
ALLOWED_LOGIN = "hu-sd3"
UNITS = "'jaunt-host-users@*'"
PROBE_WARNING = "outcome=failed stage=request"
SANDBOX_FILE = "/var/log/e2e-sandbox.txt"
SANDBOX_PROBE = """#!/bin/sh
{{
  grep -E '^(CapBnd|NoNewPrivs|Seccomp):' /proc/$$/status
  printf 'usr: '; touch /usr/e2e-probe 2>&1 || true
  printf 'net: '; tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\\n' ' '; echo
  printf 'tmp: '; ls -A /tmp | wc -l
  printf 'id: '; id -u
}} >/var/log/e2e-sandbox.txt 2>&1
exec {real} "$@"
"""
SSSD_CONF = "[sssd]\ndomains = e2e\n\n[domain/e2e]\nid_provider = proxy\nproxy_lib_name = files\n"


def systemctl(stand, *args, timeout=120):
    return stand.on_node(NODE, ["systemctl", *args], timeout=timeout)


def journal(stand, tag):
    return stand.on_node(NODE, ["journalctl", "-t", tag, "-o", "cat", "--no-pager"], timeout=60).out


def helper_journal(stand):
    return journal(stand, "jaunt-host-users")


def failed_units(stand):
    listed = systemctl(stand, "--failed", "--no-legend", "--plain")
    return [line.split()[0] for line in listed.out.splitlines() if line.strip()]


def helper_instances(stand):
    listed = systemctl(stand, "list-units", "--all", "--no-legend", "--plain", "jaunt-host-users@*")
    return [line.split()[0] for line in listed.out.splitlines() if line.strip()]


def tunnels(stand):
    return kit.agent_log(stand, NODE).count("the tunnel is connected")


def probes(stand):
    return len([line for line in helper_journal(stand).splitlines() if PROBE_WARNING in line])


def ask_helper(stand, login):
    request = kit.REQUEST.format(login=login)
    shown = kit.sh(stand, NODE, "printf '%s\\n' '{}' | setpriv --reuid=jaunt --regid=jaunt --init-groups "
                   "socat -t 15 - UNIX-CONNECT:{}".format(request, kit.SOCKET))
    return shown.out.strip()


def overall(shown):
    found = re.search(r"Overall exposure level for (\S+): ([0-9.]+) (\S+)", shown)
    return "{} {} {}".format(found.group(2), found.group(3), found.group(1)) if found else None


def run(stand, report):
    stand.admin_login()

    with report.step("the node boots with systemd as PID 1 and sshd runs as a unit") as step:
        done = kit.sh(stand, NODE, "set -e; rm -f /etc/ssh/ssh_host_*; ssh-keygen -A >/dev/null; "
                      "if systemctl cat ssh.service >/dev/null 2>&1; then unit=ssh; else unit=sshd; fi; "
                      "systemctl enable --now $unit; systemctl is-active $unit")
        step.expect(done.ok and done.out.strip().endswith("active"), done.text())
        version = kit.sh(stand, NODE, "systemctl --version | head -n 1").out.strip()
        step.note(version)
        step.expect(stand.on_node(NODE, ["cat", "/proc/1/comm"]).out.strip() == "systemd", "PID 1 is not systemd")

    with report.step("the real installer enables the helper socket and the agent unit; the socket is root:jaunt 0660") as step:
        kit.prepare_host(stand, NODE)
        done = kit.install_creating(stand, NODE)
        step.expect(done.ok, "install --create-accounts: {}".format(done.text()))
        step.expect("warning:" not in done.text().lower(), done.text())
        enabled = systemctl(stand, "is-enabled", "jaunt-host-users.socket", "jaunt-agent.service")
        step.expect(enabled.out.split() == ["enabled", "enabled"], "enabled: {}".format(enabled.text()))
        active = systemctl(stand, "is-active", "jaunt-host-users.socket")
        step.expect(active.out.strip() == "active", "the socket is {}".format(active.text()))
        step.expect(kit.socket_facts(stand, NODE) == "root:jaunt 660 socket", kit.socket_facts(stand, NODE))
        step.expect(not helper_instances(stand), "helper instances before any connection: {}".format(helper_instances(stand)))
        step.expect(not failed_units(stand), "failed units after the install: {}".format(failed_units(stand)))

    with report.step("the node enrols and the agent unit, under its own sandbox, connects its tunnel and the helper socket") as step:
        forwarder = exec_detached(container(NODE), ["socat", "TCP-LISTEN:7001,bind=127.0.0.1,fork,reuseaddr", "TCP:jauntd:8443"])
        step.expect(forwarder.ok, forwarder.text())
        code = stand.enrol_start(NODE)
        approved = stand.jauntd("node", "approve", code, "--yes")
        step.expect(approved.ok, approved.text())
        stand.node_ids[NODE] = stand.enrol_wait(NODE)
        started = systemctl(stand, "start", "jaunt-agent")
        step.expect(started.ok, started.text())
        waited = kit.wait_creates_accounts(stand, NODE, True)
        if waited > 15:
            step.note("the creates_accounts flag appeared {:.0f} s after the agent started".format(waited))
        step.expect(systemctl(stand, "is-active", "jaunt-agent").out.strip() == "active", "the agent unit is not active")
        users = stand.on_node(NODE, ["ps", "-o", "user=", "-C", "jaunt-agent"]).out.split()
        step.expect(users == ["jaunt"], "the agent runs as {}".format(users))
        step.expect(probes(stand) == 1, "helper journal probe lines after the first connection: {}".format(probes(stand)))
        step.expect(not helper_instances(stand), "instances left after the probe: {}".format(helper_instances(stand)))
        step.expect(not failed_units(stand), "failed units after the probe: {}".format(failed_units(stand)))

    with report.step("one probe per tunnel connection: three agent restarts add three journal lines and no failed unit") as step:
        before = probes(stand)
        for done in range(1, 4):
            kit.restart_agent(stand, NODE)
            stand.wait_until("probe {} in the helper journal".format(done), lambda done=done: probes(stand) - before >= done, 30, interval=0.5)
        step.expect(probes(stand) - before == 3, "probe lines added: {}".format(probes(stand) - before))
        step.expect(not failed_units(stand), "failed units after three probes: {}".format(failed_units(stand)))
        step.expect(not helper_instances(stand), "instances after three probes: {}".format(helper_instances(stand)))

    with report.step("failed requests leave no failed unit behind: CollectMode collects the instances") as step:
        for _ in range(5):
            answer = kit.sh(stand, NODE, "printf '{{}}\\n' | setpriv --reuid=jaunt --regid=jaunt --init-groups "
                            "socat -t 15 - UNIX-CONNECT:{}".format(kit.SOCKET), timeout=60).out.strip()
            step.expect('"result":"failed"' in answer, "answer {}".format(answer))
        stand.wait_until("the helper instances to be collected", lambda: not helper_instances(stand), 20, interval=1)
        step.expect(not failed_units(stand), "failed units after five failed requests: {}".format(failed_units(stand)))
        stranger = kit.sh(stand, NODE, "useradd --system --no-create-home --shell /usr/sbin/nologin e2e-stranger")
        step.expect(stranger.ok, stranger.text())
        refused = kit.sh(stand, NODE, "printf '{}\\n' | setpriv --reuid=e2e-stranger --regid=e2e-stranger --clear-groups "
                         "socat -t 15 - UNIX-CONNECT:{}".format(kit.REQUEST.format(login="hu-sd9"), kit.SOCKET))
        step.expect(not refused.out.strip() and "ermission denied" in refused.err, "another user got through: {}".format(refused.text()))
        step.expect(kit.account_facts(stand, NODE, "hu-sd9") is None, "an account was created for a user outside the group")

    with report.step("the first login under the helper sandbox creates the account and fills the home from skel") as step:
        status, output, browser = stand.login("alice")
        step.expect(status == 0, "jaunt login exited {}: {}".format(status, output))
        kit.wrap_useradd(stand, NODE, SANDBOX_PROBE)
        try:
            shown = stand.ssh("alice", NODE, 'echo "$(id -un) $(id -u)"', login=LOGIN, timeout=120)
        finally:
            kit.restore_useradd(stand, NODE)
        step.expect(shown.ok and shown.out.split()[0] == LOGIN, "the first login: {} {}".format(shown.out, shown.err))
        uid = int(shown.out.split()[1])
        step.expect(kit.UID_MIN <= uid <= kit.UID_MAX, "uid {}".format(uid))
        skel = set(kit.sh(stand, NODE, "ls -A /etc/skel").out.split())
        home = set(kit.sh(stand, NODE, "ls -A /home/{}".format(LOGIN)).out.split())
        step.expect(skel and skel <= home, "skel {} home {}".format(sorted(skel), sorted(home)))
        step.expect(kit.sh(stand, NODE, "stat -c '%a %U' /home/{}".format(LOGIN)).out.strip() == "750 {}".format(LOGIN), "home mode")
        lines = [line for line in helper_journal(stand).splitlines() if " login={} ".format(LOGIN) in line + " "]
        step.expect(len(lines) == 1 and "outcome=created uid={} exit=0".format(uid) in lines[0], lines)
        step.expect(len(control_created(stand, LOGIN)) >= 1, "no host_user.created in the control audit")
        facts = kit.sh(stand, NODE, "cat {}".format(SANDBOX_FILE)).out
        step.note("the sandbox seen by useradd: {}".format(facts.replace("\n", " | ")))
        step.expect("NoNewPrivs:\t1" in facts and "Seccomp:\t2" in facts, facts)
        step.expect("CapBnd:\t000000000000001b" in facts, "the capability bounding set is not the four configured capabilities: {}".format(facts))
        step.expect("Read-only file system" in facts, "/usr is writable inside the helper: {}".format(facts))
        ignored = "PrivateNetwork=yes is configured, but" in kit.sh(stand, NODE, "journalctl -u 'jaunt-host-users@*' -o cat --no-pager").out
        if ignored:
            step.note("PrivateNetwork=yes is ignored by systemd inside this container (no network namespace can be created): not proven here, check it on a virtual machine")
        else:
            step.expect("net: lo " in facts, "the helper sees a network interface other than lo: {}".format(facts))
        step.expect("tmp: 0" in facts, "the private /tmp is not empty: {}".format(facts))
        step.expect("id: 0" in facts, "the helper does not run as root: {}".format(facts))

    with report.step("systemd-analyze security: the exposure levels of the helper and the agent unit are recorded") as step:
        helper = systemctl(stand, "cat", "jaunt-host-users@probe.service")
        score = kit.sh(stand, NODE, "systemd-analyze security --no-pager jaunt-host-users@probe.service 2>&1 | tail -n 3")
        agent = kit.sh(stand, NODE, "systemd-analyze security --no-pager jaunt-agent.service 2>&1 | tail -n 3")
        helper_level, agent_level = overall(score.out), overall(agent.out)
        step.note("helper unit: {}".format(helper_level))
        step.note("agent unit: {}".format(agent_level))
        step.expect(helper.ok and helper_level and agent_level, "no exposure level: {} / {}".format(score.text(), agent.text()))

    with report.step("a network user directory: the agent does not announce the capability and the helper answers disabled") as step:
        done = kit.sh(stand, NODE, "set -e; cp /etc/nsswitch.conf /root/nsswitch.conf.orig; "
                      "sed -i 's/^passwd:.*/passwd: files sss/' /etc/nsswitch.conf; mkdir -p /etc/sssd; "
                      "printf '%s' '{}' >/etc/sssd/sssd.conf; chmod 0600 /etc/sssd/sssd.conf; grep '^passwd' /etc/nsswitch.conf".format(SSSD_CONF))
        step.expect(done.ok and "files sss" in done.out, done.text())
        kit.restart_agent(stand, NODE)
        kit.wait_creates_accounts(stand, NODE, False)
        step.expect(ask_helper(stand, DIRECTORY_LOGIN) == '{"v":1,"result":"disabled"}', "the helper answered {}".format(ask_helper(stand, DIRECTORY_LOGIN)))
        shown = stand.ssh("alice", NODE, "id -un", login=DIRECTORY_LOGIN, timeout=90)
        step.expect(shown.status != 0 and only_denial(shown), "{!r} {!r}".format(shown.out, shown.err))
        missing = kit.agent_events_of(stand, NODE, "agent.host_user.missing", DIRECTORY_LOGIN)
        step.expect(missing and missing[-1].get("cause") == "directory", "agent.host_user.missing: {}".format(missing))
        step.expect(kit.account_facts(stand, NODE, DIRECTORY_LOGIN) is None, "an account was created next to a directory")

    with report.step("allow_with_directory: true with sssd-common installed: what sss_cache does under ProtectSystem=strict") as step:
        installed = kit.sh(stand, NODE, "export DEBIAN_FRONTEND=noninteractive; if command -v apt-get >/dev/null 2>&1; then "
                           "apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends sssd-common sssd-tools >/dev/null; "
                           "else dnf install -y -q sssd-common sssd-tools >/dev/null; fi; ls /usr/sbin/sss_cache", timeout=600)
        step.expect(installed.ok, "cannot install sssd-common: {}".format(installed.text()[-400:]))
        kit.sh(stand, NODE, "printf '%s' '{}' >/etc/sssd/sssd.conf; chmod 0600 /etc/sssd/sssd.conf".format(SSSD_CONF))
        started = systemctl(stand, "start", "sssd")
        step.note("sssd start (its proxy domain is not meant to run, only its databases are needed): {}".format("started" if started.ok else "exit {}".format(started.status)))
        kit.write_section(stand, NODE, allow_with_directory=True)
        connected = tunnels(stand)
        kit.restart_agent(stand, NODE)
        stand.wait_until("the agent to reconnect", lambda: tunnels(stand) > connected, 30)
        shown = stand.ssh("alice", NODE, "id -un", login=ALLOWED_LOGIN, timeout=120)
        lines = [line for line in helper_journal(stand).splitlines() if " login={} ".format(ALLOWED_LOGIN) in line + " "]
        step.note("helper journal: {}".format(" || ".join(lines)))
        step.note("the login answered: status {} out {!r} err {!r}".format(shown.status, shown.out.strip(), shown.err.strip()))
        step.expect(len(lines) == 1 and "outcome=created" in lines[0] and "exit=0" in lines[0], "helper journal lines for {}: {}".format(ALLOWED_LOGIN, lines))
        step.expect(kit.account_facts(stand, NODE, ALLOWED_LOGIN) is not None, "the account {} is absent".format(ALLOWED_LOGIN))
        outside = kit.sh(stand, NODE, "sss_cache -E 2>&1; echo exit=$?")
        step.note("the same sss_cache run by root outside the unit: {}".format(outside.out.strip().replace("\n", " | ")[-200:]))
