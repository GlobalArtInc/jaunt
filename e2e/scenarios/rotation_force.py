import time

from .rotation_kit import fingerprint_text, keys_of, step_of
from .rotation_user import LAST_LINE, RELOAD_DEADLINE, added_key, reloaded, reloaded_trust

NODE = "node-b"
BEHIND_DEADLINE = 35
RECOVERY_DEADLINE = 90
DENIAL_DEADLINE = 20
REFUSAL = "Permission denied (publickey)"
RESTART_CERT_TTL_SECS = 900
RECONNECT_DEADLINE = 120


def run(stand, report):
    try:
        scenario(stand, report)
    finally:
        stand.kit.release_blocks()


def scenario(stand, report):
    kit = stand.kit
    started = time.monotonic()
    key_b = kit.fingerprints["user-b"]
    state = {}

    with report.step("the daemon restarts with a {} s certificate lifetime so that the forced steps do not race the clock".format(RESTART_CERT_TTL_SECS)) as step:
        stand.restart_jauntd(RESTART_CERT_TTL_SECS)
        kit.sessions.clear()
        stand.admin_login()
        kit.sign_in("alice")

        def reachable():
            return all(kit.connects("alice", node) for node in ("node-a", "node-b", "node-c"))

        took, _ = kit.wait("daemon restart: the three nodes are reachable again", reachable, RECONNECT_DEADLINE, interval=3)
        step.expect(keys_of(kit.status()["user"]) == {"active": key_b}, "the user keys changed across the restart")

    with report.step("stale agent: node-b may not open new connections to the agent API, its tunnel stays up") as step:
        before = kit.tunnel_connections(NODE)
        state["pid"] = kit.agent_pid(NODE)
        kit.block_api(NODE)
        step.expect(kit.tunnel_connections(NODE) > before, "the tunnel of node-b did not reconnect")
        step.note("tunnel connections of node-b: {} then {}".format(before, kit.tunnel_connections(NODE)))

    with report.step("stale agent: add-next of the second rotation leaves node-b behind, the others current") as step:
        done = kit.change("user", "add-next")
        step.expect(done.status == 0, "exit {}: {}".format(done.status, done.text()))
        key_c = added_key(done)
        step.expect(key_c and key_c not in (key_b, kit.fingerprints["user-a"]), done.out)
        kit.fingerprints["user-c"] = key_c

        def behind():
            status = kit.status()["user"]
            nodes = status["nodes"]
            return status if nodes["behind_names"] == [NODE] and nodes["current"] == 2 else None

        took, status = kit.wait("second add-next: only node-b is behind", behind, BEHIND_DEADLINE, interval=1)
        step.note("node-a and node-c were current and node-b behind after {:.1f} s".format(took))
        kit.record_trust_id("user", status["trust_id"])
        promote = step_of(status, "promote")
        step.expect(not promote["allowed"] and "node-b" in promote["line"], "promote entry {}".format(promote))

    with report.step("stale agent: promote is refused with exit 3 naming node-b") as step:
        done = kit.change("user", "promote")
        step.expect(done.status == 3, "exit {}: {}".format(done.status, done.text()))
        step.expect("promote: blocked: 1 node behind (node-b)" in done.out, done.text())
        step.expect(keys_of(kit.status()["user"])["active"] == key_b, "the refused promote changed the active key")

    with report.step("emergency path: bob signs in under B and opens a session before the forced promotion") as step:
        kit.sign_in("bob")
        step.expect(kit.signer_of("bob") == fingerprint_text(key_b), "bob's certificate is not signed by B")
        kit.freeze("bob", "bob-b")
        kit.open_session("bob", "node-a", "bob under B")

    with report.step("emergency path: promote --force exits 0 and the daemon applies it") as step:
        done = kit.change("user", "promote", force=True)
        step.expect(done.status == 0, "exit {}: {}".format(done.status, done.text()))
        step.expect("forced past the check" in done.out, done.out)
        step.expect(done.out.strip().splitlines()[-1] == LAST_LINE, done.out)
        took, _ = kit.wait("forced promote: ca.reloaded names the new active key",
                           lambda: reloaded(stand, "user", key_c), RELOAD_DEADLINE, interval=1)
        step.note("the daemon applied the forced promotion after {:.1f} s".format(took))

    with report.step("emergency path: retire is refused while bob's certificate signed by B is unexpired, retire --force applies") as step:
        done = kit.change("user", "retire")
        step.expect(done.status == 3, "exit {}: {}".format(done.status, done.text()))
        step.expect("retire: blocked:" in done.out and "unexpired user certificate" in done.out, done.text())
        control = kit.frozen_ssh("bob-b", "node-a", "echo before-$(hostname)")
        step.expect(control.ok and control.out.strip() == "before-node-a",
                    "bob's certificate signed by B does not work before the retirement: {}".format(control.text()[-300:]))
        done = kit.change("user", "retire", force=True)
        step.expect(done.status == 0, "exit {}: {}".format(done.status, done.text()))
        step.expect("forced past the check" in done.out and "user key {} retired".format(key_b) in done.out, done.out)
        step.expect(done.out.strip().splitlines()[-1] == LAST_LINE, done.out)
        cli, _ = kit.status_pair()
        step.expect(keys_of(cli["user"]) == {"active": key_c}, "keys {}".format(cli["user"]["keys"]))
        kit.record_trust_id("user", cli["user"]["trust_id"])
        kit.wait("forced retire: ca.reloaded reports the single key",
                 lambda: reloaded_trust(stand, "user", cli["user"]["trust_id"]), RELOAD_DEADLINE, interval=1)

    with report.step("emergency path: the gate refuses the unexpired certificate signed by the retired key B, the open session survives") as step:
        kit.check_session(step, "the forced retirement")
        left = kit.seconds_left("bob")
        step.expect(left > 5, "bob's certificate has {} s left: too late to tell retirement from expiry".format(left))
        shown = kit.frozen_ssh("bob-b", "node-a", "true")
        step.expect(shown.status != 0, "the retired key B still opens node-a")
        step.expect("jaunt@gate.e2e.test: {}".format(REFUSAL) in shown.err,
                    "the refusal does not come from the gate: {}".format(shown.err[-300:]))
        step.note("bob's certificate signed by B ({} s of validity left) is refused: {}".format(
            left, " | ".join(line for line in shown.err.splitlines() if line.strip())[-200:]))

    with report.step("stale agent: a certificate signed by C works on node-a and node-c and is refused by node-b") as step:
        kit.sign_in("alice")
        step.expect(kit.signer_of("alice") == fingerprint_text(key_c), "the new certificate is not signed by C")
        for node in ("node-a", "node-c"):
            step.expect(kit.connects("alice", node), "alice cannot reach {} with a certificate signed by C".format(node))
        denials = kit.count_in_agent_log(NODE, '"reason":"untrusted_ca"')
        state["refused_at"] = time.monotonic()
        shown = stand.ssh("alice", NODE, "true")
        step.expect(shown.status != 0, "node-b accepted a certificate signed by a key it does not know")
        step.expect("deploy@node-b.e2e.test: {}".format(REFUSAL) in shown.err, "refusal text: {}".format(shown.err[-300:]))
        step.expect("untrusted" not in shown.err and "trust" not in shown.err.lower(),
                    "the refusal names the cause: {}".format(shown.err[-300:]))
        step.note("node-b refused with: {}".format(" | ".join(line for line in shown.err.splitlines() if line.strip())[-200:]))
        kit.wait("node-b logs a new denial with the reason untrusted_ca",
                 lambda: kit.count_in_agent_log(NODE, '"reason":"untrusted_ca"') > denials, DENIAL_DEADLINE, interval=1)

    with report.step("stale agent: the block is lifted once the refusal is seen") as step:
        state["loads"] = kit.trust_loads(NODE)
        kit.unblock_api(NODE)
        state["unblocked_at"] = time.monotonic()

    with report.step("stale agent: node-b recovers without a restart within {} s of the block being lifted and accepts C".format(RECOVERY_DEADLINE)) as step:
        loads = state["loads"]
        remaining = max(5, RECOVERY_DEADLINE - (time.monotonic() - state["unblocked_at"]))
        kit.wait("stale agent: node-b loads the trust set after the block is lifted",
                 lambda: kit.trust_loads(NODE) > loads, remaining, interval=1)
        since_unblock = time.monotonic() - state["unblocked_at"]
        since_refusal = time.monotonic() - state["refused_at"]
        step.note("node-b loaded the new trust set at most {:.0f} s after the block was lifted ({:.0f} s after the first refusal)".format(
            since_unblock, since_refusal))
        step.expect(since_unblock <= RECOVERY_DEADLINE, "the recovery took {:.0f} s".format(since_unblock))
        kit.fresh("alice", 25)
        step.expect(kit.connects("alice", NODE), "node-b still refuses a certificate signed by C")
        step.expect(kit.agent_pid(NODE) == state["pid"], "the agent of node-b was restarted")

        def current():
            nodes = kit.status()["user"]["nodes"]
            return nodes["behind"] == 0 and nodes["current"] == 3

        kit.wait("node-b reports the current trust id after recovering", current, 30, interval=2)

    with report.step("emergency path: status and the admin API agree") as step:
        kit.status_pair()

    kit.phase("user CA stale agent and --force", started)
