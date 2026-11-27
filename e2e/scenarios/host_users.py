import re
from datetime import datetime

from scenarios import host_users_kit as kit
from stand import audit

NODE_PAM_YES = "node-a"
NODE_PAM_NO = "node-b"
NODES = (NODE_PAM_YES, NODE_PAM_NO)
SQUATTER_FIRST = 31500
SQUATTER_LAST = 31509
DENIAL = "Permission denied (publickey)"
LATE_ANNOUNCE_SECS = 15
PARALLEL_DELAY_SECS = 3
CREATED_OUTPUT = re.compile(r"^(\S+) (\d+) (\d+)$")


def parse_time(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def only_denial(shown):
    lines = [line.strip() for line in shown.err.splitlines() if line.strip()]
    return bool(lines) and all(DENIAL in line for line in lines) and not kit.REF.search(shown.err) and not shown.out.strip()


def audit_events(stand):
    return stand.audit_events(type="host_user.")


def control_created(stand, login):
    return [event for event in audit_events(stand) if event["type"] == "host_user.created" and event["fields"].get("login") == login]


def control_refused(stand, ref):
    return [event for event in audit_events(stand) if event["type"] == "host_user.refused" and event["fields"].get("ref") == ref]


def helper_ref_lines(stand, node, ref):
    return [line for line in kit.helper_log(stand, node).splitlines() if " ref={} ".format(ref) in line + " "]


def auth_denials(stand, node, login, reason):
    return [fields for fields in kit.agent_events_of(stand, node, "agent.ssh.auth", login) if fields.get("reason") == reason]


def first_login(stand, step, node, login):
    shown = stand.ssh("alice", node, 'echo shell-$((6*7)); echo "$(id -un) $(id -u) $(stat -c %a "$HOME")"', login=login,
                      tty=True, extra=("-tt",), timeout=120)
    step.expect(shown.ok, "the first login of {} failed: {} {}".format(login, shown.out, shown.err))
    rows = [line.strip() for line in shown.out.splitlines() if line.strip()]
    step.expect("shell-42" in rows, "the shell of {} did not run: {}".format(login, rows))
    facts = [CREATED_OUTPUT.match(row) for row in rows]
    facts = [found.groups() for found in facts if found]
    step.expect(facts and facts[0][0] == login, "id of {} showed {}".format(login, rows))
    uid, mode = int(facts[0][1]), facts[0][2]
    step.expect(kit.UID_MIN <= uid <= kit.UID_MAX, "uid {} is outside {}-{}".format(uid, kit.UID_MIN, kit.UID_MAX))
    step.expect(mode == "750", "the home mode is {}".format(mode))
    return uid


def refused_login(stand, step, node, login, reason, helper_side):
    contacts = kit.helper_contacts(stand, node)
    shown = stand.ssh("alice", node, "true", login=login, timeout=90)
    step.expect(shown.status != 0 and only_denial(shown), "{}: out {!r} err {!r}".format(login, shown.out, shown.err))
    refused = kit.agent_events_of(stand, node, "agent.host_user.refused", login)
    step.expect(refused and refused[-1].get("reason") == reason, "{}: the agent audit shows {}".format(login, refused))
    ref = refused[-1]["ref"]
    step.expect(kit.REF.fullmatch(ref), "{}: reference {}".format(login, ref))
    step.expect(auth_denials(stand, node, login, "account_refused"), "{}: no agent.ssh.auth denied account_refused".format(login))
    lines = helper_ref_lines(stand, node, ref)
    if helper_side:
        step.expect(len(lines) == 1 and "outcome=refused reason={}".format(reason) in lines[0] and " login={} ".format(login) in lines[0],
                    "{}: the helper journal has {}".format(login, lines))
    else:
        step.expect(not lines and not kit.helper_lines(stand, node, login), "{}: the helper was contacted: {}".format(login, lines))
        step.expect(kit.helper_contacts(stand, node) == contacts, "{}: the helper socket saw a connection".format(login))
    step.expect(kit.account_facts(stand, node, login) is None, "{} exists after a refusal".format(login))
    return ref


def run(stand, report):
    stand.admin_login()

    with report.step("the installer sets up account creation on both nodes: helper next to the agent, units, section") as step:
        for node in NODES:
            kit.prepare_host(stand, node)
            done = kit.install_creating(stand, node)
            step.expect(done.ok, "install --create-accounts on {}: {}".format(node, done.text()))
            step.expect("verified: {} is a regular file owned by root".format(kit.HELPER_BIN) in done.out, done.text())
            step.expect("wrote: /etc/systemd/system/jaunt-host-users.socket" in done.out, done.text())
            step.expect("warning:" not in done.text().lower(), "the installer warned on {}: {}".format(node, done.text()))
            written = kit.sh(stand, node, "cat /etc/systemd/system/jaunt-host-users@.service; grep -c 'enabled: true' {}; "
                             "stat -c '%U:%G %a' {} {}".format(kit.CONFIG, kit.BIN_DIR, kit.HELPER_BIN))
            step.expect("ExecStart={} serve --config {} --agent-user jaunt".format(kit.HELPER_BIN, kit.CONFIG) in written.out, written.out)
            step.expect("CollectMode=inactive-or-failed" in written.out and "SystemCallFilter=@system-service" in written.out, written.out)
            step.expect(written.out.rstrip().endswith("1\nroot:root 755\nroot:root 755"), written.out[-120:])

    with report.step("the helper starts per connection with the real peer credentials: socket root:jaunt 0660") as step:
        for node in NODES:
            kit.start_helper(stand, node)
            facts = kit.socket_facts(stand, node)
            step.expect(facts == "root:jaunt 660 socket", "{}: {}".format(node, facts))

    with report.step("creation off (the default): a login without an account is refused with the generic denial and the helper is not contacted") as step:
        for node in NODES:
            kit.write_section(stand, node, enabled=False)
            kit.restart_agent(stand, node)
            kit.wait_creates_accounts(stand, node, False)
        before = kit.helper_contacts(stand, NODE_PAM_YES)
        shown = stand.ssh("alice", NODE_PAM_YES, "id", login="hu-off", timeout=90)
        step.expect(shown.status != 0 and only_denial(shown), "out {!r} err {!r}".format(shown.out, shown.err))
        step.expect(kit.helper_contacts(stand, NODE_PAM_YES) == before, "the helper was contacted while creation is off")
        step.expect(not kit.helper_lines(stand, NODE_PAM_YES, "hu-off"), "the helper journal names hu-off")
        denied = auth_denials(stand, NODE_PAM_YES, "hu-off", "no_account")
        step.expect(len(denied) == 1, "agent.ssh.auth denied reason=no_account: {}".format(denied))
        missing = kit.agent_events_of(stand, NODE_PAM_YES, "agent.host_user.missing", "hu-off")
        step.expect(len(missing) == 1 and missing[0].get("cause") == "disabled", "agent.host_user.missing: {}".format(missing))
        step.expect(kit.REF.fullmatch(missing[0]["ref"]), "reference {}".format(missing[0]["ref"]))
        step.expect(kit.account_facts(stand, NODE_PAM_YES, "hu-off") is None, "hu-off was created")
        step.expect(not [event for event in audit_events(stand) if event["fields"].get("login") == "hu-off"],
                    "the control audit has a host_user event for hu-off")

    with report.step("creation on: both agents announce it after the restart and probe the helper once per tunnel connection") as step:
        for node in NODES:
            before = kit.helper_contacts(stand, node)
            kit.write_section(stand, node)
            kit.restart_agent(stand, node)
            waited = kit.wait_creates_accounts(stand, node, True)
            if waited > LATE_ANNOUNCE_SECS:
                step.note("{}: the creates_accounts flag appeared {:.0f} s after the restart".format(node, waited))
            step.expect(kit.helper_contacts(stand, node) - before == 1,
                        "{}: {} helper connections for one tunnel connection".format(node, kit.helper_contacts(stand, node) - before))
        probes = [line for line in kit.helper_log(stand, NODE_PAM_YES).splitlines() if "outcome=failed stage=request" in line]
        step.expect(probes, "the probe left no warning in the helper journal")

    with report.step("UsePAM yes and UsePAM no: the first login creates the account, the shell opens, the second creates nothing") as step:
        kit.set_use_pam(stand, NODE_PAM_YES, "yes")
        kit.set_use_pam(stand, NODE_PAM_NO, "no")
        for node, login in ((NODE_PAM_YES, "hu-yes"), (NODE_PAM_NO, "hu-no")):
            uid = first_login(stand, step, node, login)
            facts = kit.account_facts(stand, node, login)
            step.expect(facts and facts[0].startswith("{}:x:{}:".format(login, uid)) and facts[0].endswith(":/home/{0}:/bin/bash".format(login)), facts)
            step.expect(facts[2] == "750 {0} {0}".format(login), "the home is {}".format(facts[2]))
            groups = kit.sh(stand, node, "id -nG {}".format(login)).out.split()
            step.expect(kit.GROUP in groups, "groups {}".format(groups))
            listed = [row for row in kit.managed_accounts(stand, node) if row["login"] == login]
            step.expect(len(listed) == 1 and listed[0]["state"] == "active" and listed[0]["uid"] == uid and listed[0]["account"] == "present", listed)
            ref = listed[0]["ref"]
            lines = kit.helper_lines(stand, node, login)
            step.expect(len(lines) == 1 and "ref={} ".format(ref) in lines[0] and "outcome=created uid={} exit=0".format(uid) in lines[0], lines)
            created = kit.agent_events_of(stand, node, "agent.host_user.created", login)
            step.expect(len(created) == 1 and created[0]["ref"] == ref and created[0]["uid"] == uid, created)
            stand.wait_until("host_user.created of {} in the control audit".format(login), lambda: len(control_created(stand, login)) == 1, 20, interval=1)
            event = control_created(stand, login)[0]
            step.expect(event["fields"].get("ref") == ref and event["fields"].get("uid") == uid, event)
            contacts = kit.helper_contacts(stand, node)
            second = stand.ssh("alice", node, "id -un", login=login, timeout=90)
            step.expect(second.ok and second.out.strip() == login, "the second login: {} {}".format(second.out, second.err))
            step.expect(kit.helper_contacts(stand, node) == contacts, "the second login contacted the helper")
            step.expect(len(kit.helper_lines(stand, node, login)) == 1, "the second login left a helper line")
            step.expect(len(kit.agent_events_of(stand, node, "agent.host_user.created", login)) == 1, "a second agent created event")
            step.expect(len(control_created(stand, login)) == 1, "a second control created event")
            accepted = kit.sh(stand, node, "grep -c 'Accepted publickey for {} ' /var/log/sshd.log".format(login))
            step.expect(accepted.out.strip() == "2", "sshd accepted {} logins of {}".format(accepted.out.strip(), login))

    with report.step("refusals decided by the node rules never reach the helper: reserved name and name rule") as step:
        refused_login(stand, step, NODE_PAM_NO, "postgres", "reserved_name", False)
        refused_login(stand, step, NODE_PAM_NO, "hu-denied", "name_rule", False)

    with report.step("refusals decided by the helper: group collision, existing home, full quota") as step:
        node = NODE_PAM_YES
        kit.sh(stand, node, "groupadd hu-group; mkdir /home/hu-home")
        group_ref = refused_login(stand, step, node, "hu-group", "group_collision", True)
        stand.wait_until("host_user.refused of hu-group in the control audit", lambda: control_refused(stand, group_ref), 20, interval=1)
        step.expect(control_refused(stand, group_ref)[0]["fields"].get("reason") == "group_collision", control_refused(stand, group_ref))
        contacts = kit.helper_contacts(stand, node)
        again = stand.ssh("alice", node, "true", login="hu-group", timeout=90)
        step.expect(again.status != 0 and only_denial(again), "repeat: {!r}".format(again.err))
        step.expect(kit.helper_contacts(stand, node) == contacts, "the repeated refusal called the helper again")
        step.expect(len(kit.agent_events_of(stand, node, "agent.host_user.refused", "hu-group")) == 1, "a second refused audit line for the same attempt")
        step.expect(len(auth_denials(stand, node, "hu-group", "account_refused")) == 2, "the repeat was not denied")
        refused_login(stand, step, node, "hu-home", "home_exists", True)
        count = len(kit.managed_accounts(stand, node))
        kit.write_section(stand, node, max_users=count)
        refused_login(stand, step, node, "hu-full", "max_users", True)
        kit.write_section(stand, node)

    with report.step("a range without a free uid is refused as uid_range and leaves nothing behind") as step:
        node = NODE_PAM_YES
        squatters = "; ".join("useradd --uid {0} --user-group --no-create-home squatter{0}".format(uid)
                              for uid in range(SQUATTER_FIRST, SQUATTER_LAST + 1))
        made = kit.sh(stand, node, squatters)
        step.expect(made.ok, made.text())
        kit.write_section(stand, node, uid_min=SQUATTER_FIRST, uid_max=SQUATTER_LAST, max_users=10)
        kit.restart_agent(stand, node)
        refused_login(stand, step, node, "hu-uid", "uid_range", True)
        step.expect(not kit.sh(stand, node, "getent group hu-uid").ok, "the group hu-uid was left behind")
        step.expect(not kit.sh(stand, node, "test -e /home/hu-uid").ok, "the home of hu-uid was left behind")
        kit.write_section(stand, node)
        kit.restart_agent(stand, node)

    with report.step("the sixth creation within a minute is refused with a reference found in both journals") as step:
        node = NODE_PAM_NO
        created = 0
        for login in ("hu-r1", "hu-r2", "hu-r3", "hu-r4", "hu-r5"):
            if kit.attempts_in_window(stand, node) >= 5:
                break
            shown = stand.ssh("alice", node, "id -un", login=login, timeout=90)
            step.expect(shown.ok and shown.out.strip() == login, "{}: {} {}".format(login, shown.out, shown.err))
            created += 1
        step.expect(kit.attempts_in_window(stand, node) >= 5, "only {} attempts in the window".format(kit.attempts_in_window(stand, node)))
        refused_login(stand, step, node, "hu-r6", "rate_limit", True)
        step.note("{} creations before the limit, the helper counted five attempts in the minute".format(created))

    with report.step("eight parallel first logins of one name create one account, one audit line and eight shells") as step:
        node = NODE_PAM_YES
        marker = stand.marker()
        kit.delay_useradd(stand, node, PARALLEL_DELAY_SECS)
        try:
            streams = [stand.ssh_stream("alice", node, "id -un", login="hu-race") for _ in range(8)]
            results = [(stream.finish(120), stream.output().strip()) for stream in streams]
        finally:
            kit.restore_useradd(stand, node)
        step.expect(all(status == 0 and out.splitlines()[-1] == "hu-race" for status, out in results), results)
        step.expect(kit.sh(stand, node, "grep -c '^hu-race:' /etc/passwd").out.strip() == "1", "passwd entries of hu-race")
        lines = kit.helper_lines(stand, node, "hu-race")
        step.expect(len(lines) == 1 and "outcome=created" in lines[0], lines)
        created = kit.agent_events_of(stand, node, "agent.host_user.created", "hu-race")
        step.expect(len(created) == 1, "agent created audit lines: {}".format(len(created)))
        landed = parse_time(created[0]["timestamp"])
        routed = [parse_time(event["time"]) for event in audit.after(stand.audit_events(), marker)
                  if event["type"] == "session.start" and event["fields"].get("login") == "hu-race"]
        step.expect(len(routed) == 8, "sessions of hu-race in the control audit: {}".format(len(routed)))
        step.expect(all(started < landed for started in routed),
                    "a session started after the account was created, so the logins did not overlap")
        stand.wait_until("host_user.created of hu-race in the control audit", lambda: control_created(stand, "hu-race"), 20, interval=1)
        step.note("the control audit holds {} host_user.created event(s) for the eight sessions".format(len(control_created(stand, "hu-race"))))

    with report.step("the agent restarted while the helper holds the creation: the next login finds the account through getent") as step:
        node = NODE_PAM_YES
        try:
            kit.hold_useradd(stand, node)
            stream = stand.ssh_stream("alice", node, "id -un", login="hu-restart")
            stand.wait_until("useradd to be entered for hu-restart", lambda: stand.on_node(node, ["test", "-e", "/run/e2e/useradd-entered"]).ok, 30)
            kit.restart_agent(stand, node)
            step.expect(kit.sh(stand, node, "test ! -e /run/e2e/useradd-release && ps -eo args= | grep -q '[/]usr/sbin/useradd'").ok,
                        "the held useradd did not outlast the restart of the agent")
            step.expect(kit.account_facts(stand, node, "hu-restart") is None, "the account appeared before useradd was released")
            kit.release_useradd(stand, node)
            step.expect(stream.finish(60) != 0, "the session of the stopped agent ended normally")
            stand.wait_until("the account hu-restart to appear", lambda: kit.account_facts(stand, node, "hu-restart") is not None, 30)
        finally:
            kit.restore_useradd(stand, node)
        listed = [row for row in kit.managed_accounts(stand, node) if row["login"] == "hu-restart"]
        step.expect(len(listed) == 1 and listed[0]["state"] == "active", listed)
        contacts = kit.helper_contacts(stand, node)
        shown = stand.ssh("alice", node, "id -un", login="hu-restart", timeout=90)
        step.expect(shown.ok and shown.out.strip() == "hu-restart", "{} {}".format(shown.out, shown.err))
        step.expect(kit.helper_contacts(stand, node) == contacts, "the next login contacted the helper")
        step.expect(not kit.agent_events_of(stand, node, "agent.host_user.created", "hu-restart"),
                    "the agent that never saw the answer logged a created line")
        step.expect(len(kit.helper_lines(stand, node, "hu-restart")) == 1, kit.helper_lines(stand, node, "hu-restart"))

    with report.step("AllowUsers blocks a created account, the installer warns about it and keeps the section, then the account works") as step:
        node = NODE_PAM_YES
        kit.write_file(stand, node, "/etc/ssh/sshd_config.d/10-e2e-allow.conf", "AllowUsers deploy alice\n")
        kit.reload_sshd(stand, node)
        kit.sh(stand, node, "printf 'recording:\\n  session_queue_bytes: 2097152\\n' >>{}".format(kit.CONFIG))
        done = kit.install_again(stand, node)
        step.expect(done.ok, done.text())
        step.expect("`sshd -T` shows that AllowUsers is set" in done.text(), "no AllowUsers warning: {}".format(done.text()))
        kept = kit.sh(stand, node, "cat {}".format(kit.CONFIG)).out
        step.expect('groups: ["jaunt-users"]' in kept and 'deny: ["hu-denied"]' in kept, "the section did not survive the reinstall: {}".format(kept))
        step.expect("recording:" not in kept, "a hand-added top-level key survived the reinstall")
        blocked = stand.ssh("alice", node, "id -un", login="hu-allow", timeout=90)
        step.expect(blocked.status != 0 and only_denial(blocked), "{!r} {!r}".format(blocked.out, blocked.err))
        step.expect(kit.account_facts(stand, node, "hu-allow") is not None, "the account was not created")
        logged = kit.sh(stand, node, "grep 'hu-allow' /var/log/sshd.log | grep -c 'not allowed because not listed in AllowUsers'")
        step.expect(logged.out.strip() != "0", "sshd did not log the AllowUsers refusal")
        step.expect(kit.agent_events_of(stand, node, "agent.ssh.inner_login", "hu-allow"), "no inner login failure in the agent audit")
        kit.sh(stand, node, "rm -f /etc/ssh/sshd_config.d/10-e2e-allow.conf")
        kit.reload_sshd(stand, node)

    with report.step("sshd takes logins from the agent again and the blocked account now logs in") as step:
        stand.wait_until("sshd to accept the inner login of hu-allow", lambda: stand.ssh("alice", NODE_PAM_YES, "id -un", login="hu-allow", timeout=60).ok, 90, interval=3)
        shown = stand.ssh("alice", NODE_PAM_YES, "id -un", login="deploy", timeout=60)
        step.expect(shown.ok and shown.out.strip() == "deploy", "{} {}".format(shown.out, shown.err))
        kit.sh(stand, NODE_PAM_NO, "rm -f /etc/ssh/sshd_config.d/00-e2e-pam.conf")
        kit.reload_sshd(stand, NODE_PAM_NO)
        kit.sh(stand, NODE_PAM_YES, "rm -f /etc/ssh/sshd_config.d/00-e2e-pam.conf")
        kit.reload_sshd(stand, NODE_PAM_YES)
        shown = stand.ssh("alice", NODE_PAM_NO, "id -un", login="hu-no", timeout=60)
        step.expect(shown.ok and shown.out.strip() == "hu-no", "{} {}".format(shown.out, shown.err))

    with report.step("a bad host_users section: a semantic error only switches creation off, an unknown key stops the agent at load") as step:
        node = NODE_PAM_NO
        kit.write_section(stand, node, uid_min=5)
        kit.restart_agent(stand, node)
        invalid = [fields for fields in kit.agent_events(stand, node) if fields["event"] == "agent.host_user.config_invalid"]
        step.expect(invalid, "no agent.host_user.config_invalid warning after a semantic error")
        kit.wait_creates_accounts(stand, node, False)
        shown = stand.ssh("alice", node, "id", login="hu-repeat", timeout=90)
        step.expect(shown.status != 0 and only_denial(shown), "{!r} {!r}".format(shown.out, shown.err))
        missing = kit.agent_events_of(stand, node, "agent.host_user.missing", "hu-repeat")
        step.expect(len(missing) == 1 and missing[0].get("cause") == "invalid_config", missing)
        asked = kit.sh(stand, node, "printf '%s\\n' '{}' | setpriv --reuid=jaunt --regid=jaunt --init-groups socat -t 15 - UNIX-CONNECT:{}"
                       .format(kit.REQUEST.format(login="hu-repeat"), kit.SOCKET))
        step.expect(asked.out.strip() == '{"v":1,"result":"disabled"}', "the helper answered {}".format(asked.out.strip()))
        step.expect(kit.account_facts(stand, node, "hu-repeat") is None, "an account was created under an invalid section")
        kit.write_file(stand, node, kit.CONFIG, kit.MANAGED_HEAD + "host_users:\n  enabled: true\n  bogus_key: 1\n")
        stopped = kit.sh(stand, node, "setpriv --reuid=jaunt --regid=jaunt --init-groups /usr/local/bin/jaunt-agent run --config {} 2>&1; echo exit=$?"
                         .format(kit.CONFIG))
        step.expect("not a valid agent configuration" in stopped.out and "exit=0" not in stopped.out, "the agent did not stop at load: {}".format(stopped.out[-300:]))
        kit.write_section(stand, node)
        kit.restart_agent(stand, node)

    with report.step("helper journal: no ERROR line, and every created line carries a reference found in the agent audit") as step:
        for node in NODES:
            text = kit.helper_log(stand, node)
            step.expect("<3>ERROR" not in text, "{}: {}".format(node, [line for line in text.splitlines() if "<3>ERROR" in line][:3]))
            created = re.findall(r"ref=(H-[0-9A-F]{8}) \S+ login=(\S+) outcome=created", text)
            agent = {fields["ref"] for fields in kit.agent_events(stand, node) if fields["event"] == "agent.host_user.created"}
            seen = {ref for ref, login in created if login != "hu-restart"}
            step.expect(seen and seen <= agent, "{}: helper refs {} agent refs {}".format(node, sorted(seen), sorted(agent)))

