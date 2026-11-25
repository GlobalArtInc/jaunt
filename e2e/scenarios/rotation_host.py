import time

from .rotation_kit import fingerprint_text, keys_of, step_of
from .rotation_user import LAST_LINE, RELOAD_DEADLINE, added_key

NODES = ("node-a", "node-b", "node-c")
GATE_DEADLINE = 30
RENEW_DEADLINE = 420
EXPIRY_DEADLINE = 240
NEW_NODE_DEADLINE = 90


def reloaded_host(stand, trust_id):
    return [event for event in stand.audit_events(type="ca.reloaded")
            if event["fields"].get("kind") == "host" and event["fields"].get("trust_id") == trust_id]


def reaches_everything(kit, step, client, phase):
    kit.fresh(kit.frozen[client]["user"], 50)
    accepted, shown = kit.gate_accepts(client)
    step.expect(accepted, "{} cannot verify the gate {}: {}".format(client, phase, shown.err[-300:]))
    for node in NODES:
        shown = kit.frozen_ssh(client, node, "echo reached-$(hostname)")
        step.expect(shown.ok and shown.out.strip() == "reached-{}".format(node),
                    "{} cannot reach {} {}: {}".format(client, node, phase, shown.text()[-300:]))


def run(stand, report):
    kit = stand.kit
    started = time.monotonic()
    key_a = kit.fingerprints["host-a"]

    with report.step("host CA: K1 signs in before add-next and knows only A") as step:
        kit.sign_in("alice")
        keys = kit.known_host_keys("alice")
        step.expect(keys == [fingerprint_text(key_a)], "known_hosts of K1 holds {}".format(keys))
        kit.freeze("alice", "k1")
        accepted, shown = kit.gate_accepts("k1")
        step.expect(accepted, "K1 cannot verify the gate: {}".format(shown.err[-300:]))

    with report.step("host CA: add-next prints the fingerprint and the daemon reloads") as step:
        kit.keep_session("node-a", "before the host add-next")
        done = kit.change("host", "add-next")
        step.expect(done.status == 0, "exit {}: {}".format(done.status, done.text()))
        added = added_key(done)
        step.expect(added and added != key_a, done.out)
        step.expect(done.out.strip().splitlines()[-1] == LAST_LINE, done.out)
        kit.fingerprints["host-b"] = added
        trust_id = kit.status()["host"]["trust_id"]
        kit.record_trust_id("host", trust_id)
        took, _ = kit.wait("host add-next: ca.reloaded names the new trust id", lambda: reloaded_host(stand, trust_id), RELOAD_DEADLINE, interval=1)
        step.note("the daemon applied add-next after {:.1f} s".format(took))
        kit.check_session(step, "the host add-next")

    with report.step("host CA: K2 signs in after add-next and learns both keys") as step:
        kit.sign_in("alice")
        keys = kit.known_host_keys("alice")
        step.expect(sorted(keys) == sorted([fingerprint_text(key_a), fingerprint_text(kit.fingerprints["host-b"])]),
                    "known_hosts of K2 holds {}".format(keys))
        kit.freeze("alice", "k2")

    with report.step("host CA: promote is refused with exit 3 while a certificate issued before add-next is unexpired") as step:
        status = kit.status()["host"]
        step.expect(keys_of(status) == {"active": key_a, "next": kit.fingerprints["host-b"]}, "keys {}".format(status["keys"]))
        done = kit.change("host", "promote")
        step.expect(done.status == 3, "exit {}: {}".format(done.status, done.text()))
        step.expect("promote: blocked:" in done.out and "issued before the current host keys were published" in done.out, done.text())
        step.expect(keys_of(kit.status()["host"]).get("active") == key_a, "the refused promote changed the active key")
        step.expect(status["old_host_trust_certificates"]["count"] >= 1, "{}".format(status["old_host_trust_certificates"]))

    with report.step("host CA: K1 and K2 reach the gate and every node, which still present A") as step:
        reaches_everything(kit, step, "k2", "after add-next")
        reaches_everything(kit, step, "k1", "after add-next")
        step.expect(kit.presented_ca("k2", "gate")[0] == fingerprint_text(key_a), "the gate no longer presents A")

    with report.step("host CA: promote becomes ready when the certificates issued before add-next have expired") as step:
        def ready():
            entry = step_of(kit.status()["host"], "promote")
            return entry if entry and entry["allowed"] else None

        took, _ = kit.wait("host promote: certificates issued before add-next expire", ready, EXPIRY_DEADLINE, interval=5)
        step.note("promote became ready {:.1f} s after the connectivity checks".format(took))

    with report.step("host CA: promote applies (exit 0)") as step:
        kit.keep_session("node-a", "before the host promotion", min_left=60)
        kit.promote_started = time.monotonic()
        done = kit.change("host", "promote")
        step.expect(done.status == 0, "exit {}: {}".format(done.status, done.text()))
        step.expect(done.out.strip().splitlines()[-1] == LAST_LINE, done.out)
        status = kit.status()["host"]
        step.expect(keys_of(status)["active"] == kit.fingerprints["host-b"], "keys {}".format(status["keys"]))
        step.expect(keys_of(status)["previous"] == key_a, "keys {}".format(status["keys"]))

    with report.step("host CA: the gate presents a host certificate signed by B within {} s".format(GATE_DEADLINE)) as step:
        kit.fresh("alice", 60)

        def gate_on_b():
            kit.fresh("alice", 15)
            return kit.presented_ca("k2", "gate")[0] == fingerprint_text(kit.fingerprints["host-b"])

        took, _ = kit.wait("host promote: the gate presents B", gate_on_b, GATE_DEADLINE, interval=1)
        step.note("the gate presented B {:.1f} s after the promotion".format(time.monotonic() - kit.promote_started))
        kit.check_session(step, "the host promotion")

    with report.step("host CA: the nodes still present A; the artificial client K1 with only A is refused by the gate itself") as step:
        kit.fresh("alice", 30)
        step.note("the nodes present: " + ", ".join(
            "{} {}".format(node, "A" if kit.presented_ca("k2", node)[0] == fingerprint_text(key_a) else "other") for node in NODES))
        kit.fresh("alice", 30)
        accepted, shown = kit.gate_accepts("k1")
        step.expect(not accepted, "K1 still verifies the gate after the promotion")
        step.expect("Host key verification failed" in shown.err and "Authenticated to" not in shown.err,
                    "K1 after the promotion: {}".format(shown.err[-400:]))
        step.expect("gate.e2e.test" in shown.err, "the failure does not name the gate: {}".format(shown.err[-400:]))

    with report.step("host CA: K2 reaches the gate and every node after the promotion") as step:
        reaches_everything(kit, step, "k2", "after promote")

    with report.step("host CA: node-a and node-b renew their host certificates to B within {} s".format(RENEW_DEADLINE)) as step:
        seen = {}
        origin = time.monotonic()

        def renewed():
            kit.fresh("alice", 40)
            kit.keep_session("node-a", "while the nodes renew", min_left=45)
            for node in ("node-a", "node-b"):
                if node not in seen and kit.presented_ca("k2", node)[0] == fingerprint_text(kit.fingerprints["host-b"]):
                    seen[node] = time.monotonic() - kit.promote_started
            return len(seen) == 2

        kit.wait("host promote: node-a and node-b renew their host certificates", renewed, RENEW_DEADLINE, interval=8)
        step.note("host certificates on B, seconds after the promotion: " + ", ".join(
            "{} {:.0f}".format(node, secs) for node, secs in sorted(seen.items())))
        step.expect(kit.presented_ca("k2", "node-c")[0] == fingerprint_text(key_a), "node-c (old protocol) already renewed")
        kit.check_session(step, "the renewals of the nodes")

    with report.step("host CA: retire is refused with exit 3 naming node-c, the old-protocol agent") as step:
        def only_old():
            status = kit.status()["host"]
            return status if status["nodes_on_previous_host_keys"]["names"] == ["node-c"] else None

        kit.wait("host retire: only node-c is left on the previous host key", only_old, 60, interval=3)
        done = kit.change("host", "retire")
        step.expect(done.status == 3, "exit {}: {}".format(done.status, done.text()))
        step.expect("retire: blocked:" in done.out and "node-c" in done.out and "previous host key" in done.out, done.text())
        step.expect(keys_of(kit.status()["host"]).get("previous") == key_a, "A is no longer previous")

    with report.step("host CA: node-c re-enrols with --replace and presents a certificate signed by B") as step:
        step.note("the old agent renews at half of the seven day lifetime; the documented way to renew earlier is enrol --replace")
        stand.agent_stop("node-c")
        code = stand.enrol_start("node-c", replace=True)
        done = stand.jauntd("node", "approve", code, "--yes")
        step.expect(done.ok, done.text())
        stand.node_ids["node-c"] = stand.enrol_wait("node-c")
        stand.agent_start("node-c")

        def node_c_on_b():
            kit.fresh("alice", 25)
            return kit.presented_ca("k2", "node-c")[0] == fingerprint_text(kit.fingerprints["host-b"])

        took, _ = kit.wait("host retire: node-c presents B after re-enrolment", node_c_on_b, NEW_NODE_DEADLINE, interval=3)
        step.note("node-c presented B {:.1f} s after the agent started".format(took))

    with report.step("host CA: retire succeeds, status shows [B], API equals CLI") as step:
        status = kit.status()["host"]
        entry = step_of(status, "retire")
        step.expect(entry["allowed"], "retire is still blocked: {}".format(entry))
        kit.keep_session("node-a", "before the host retirement")
        done = kit.change("host", "retire")
        step.expect(done.status == 0, "exit {}: {}".format(done.status, done.text()))
        step.expect("host key {} retired".format(key_a) in done.out, done.out)
        step.expect(done.out.strip().splitlines()[-1] == LAST_LINE, done.out)
        cli, _ = kit.status_pair()
        step.expect(keys_of(cli["host"]) == {"active": kit.fingerprints["host-b"]}, "keys {}".format(cli["host"]["keys"]))
        kit.record_trust_id("host", cli["host"]["trust_id"])
        took, _ = kit.wait("host retire: ca.reloaded reports the single key",
                           lambda: reloaded_host(stand, cli["host"]["trust_id"]), RELOAD_DEADLINE, interval=1)
        step.note("the daemon applied the retirement after {:.1f} s".format(took))
        kit.check_session(step, "the host retirement")

    with report.step("host CA: K2 still connects everywhere, K4 signs in and holds only B") as step:
        reaches_everything(kit, step, "k2", "after retire")
        kit.sign_in("alice")
        keys = kit.known_host_keys("alice")
        step.expect(keys == [fingerprint_text(kit.fingerprints["host-b"])], "known_hosts of K4 holds {}".format(keys))
        kit.freeze("alice", "k4")
        reaches_everything(kit, step, "k4", "after retire")
        step.expect(kit.presented_ca("k4", "gate")[0] == fingerprint_text(kit.fingerprints["host-b"]), "the gate does not present B")

    kit.phase("host CA A to B", started)
