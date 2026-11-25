from stand import audit


def run(stand, report):
    marker = stand.marker()
    with report.step("ssh deploy@node-a runs a command through the gate") as step:
        shown = stand.ssh("alice", "node-a", "echo through-the-gate; id -un")
        step.expect(shown.ok, shown.text())
        step.expect(shown.out.split() == ["through-the-gate", "deploy"], "output {!r}".format(shown.out))

    with report.step("the exit status 7 travels back") as step:
        shown = stand.ssh("alice", "node-a", "exit 7")
        step.expect(shown.status == 7, "status {} {}".format(shown.status, shown.err))

    with report.step("a pty shell works") as step:
        shown = stand.ssh("alice", "node-a", "echo pty-$((6*7))", tty=True, extra=("-tt",))
        step.expect(shown.ok and "pty-42" in shown.out, shown.text())

    with report.step("sshd on node-a recorded inner logins with the Jaunt key id") as step:
        logged = stand.on_node("node-a", ["grep", "Accepted publickey for deploy ", "/var/log/sshd.log"])
        step.expect(logged.ok and "ID jaunt:" in logged.out and "alice@e2e.test" in logged.out, logged.out[-400:])

    with report.step("alice reaches node-b as well") as step:
        shown = stand.ssh("alice", "node-b", "hostname")
        step.expect(shown.ok and shown.out.strip() == "node-b", shown.text())

    with report.step("audit: session.routed, session.start, session.end for a session of alice") as step:
        events = audit.after(stand.audit_events(), marker)
        alice = stand.certs["alice"]["principal"]
        ends = [event for event in audit.by_actor(events, alice) if event["type"] == "session.end"]
        step.expect(ends, "no session.end for alice: {}".format(audit.kinds(events)))
        session = audit.of_session(events, ends[0]["session_id"])
        step.expect(audit.appears_in_order(session, ["session.routed", "session.start", "session.end"]), audit.kinds(session))
        gate = audit.of_type(audit.by_actor(events, alice), "gate.auth")
        step.expect(gate, "no gate.auth for alice")
