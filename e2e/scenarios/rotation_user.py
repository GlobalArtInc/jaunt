import re
import time

from .rotation_kit import fingerprint_text, keys_of, step_of

LAST_LINE = "applied within 10 s"
TRUST_DEADLINE = 25
RELOAD_DEADLINE = 30
EXPIRY_DEADLINE = 240
START_DEADLINE = 40


def reloaded(stand, kind, active_fp):
    events = stand.audit_events(type="ca.reloaded")
    return [event for event in events
            if event["fields"].get("kind") == kind and event["fields"].get("active_fp") == active_fp]


def reloaded_trust(stand, kind, trust_id):
    events = stand.audit_events(type="ca.reloaded")
    return [event for event in events
            if event["fields"].get("kind") == kind and event["fields"].get("trust_id") == trust_id]


def added_key(done):
    found = re.search(r"^(user|host) key ([0-9a-f]{64}) added as next$", done.out, re.M)
    return found.group(2) if found else None


def run(stand, report):
    kit = stand.kit
    started = time.monotonic()
    key_a = kit.fingerprints["user-a"]

    with report.step("user CA: add-next prints the new fingerprint and exits 0") as step:
        kit.keep_session("node-a", "before the first rotation")
        done = kit.change("user", "add-next")
        step.expect(done.status == 0, "exit {}: {}".format(done.status, done.text()))
        added = added_key(done)
        step.expect(added, "no fingerprint line:\n{}".format(done.out))
        step.expect(added != key_a, "the next key equals the active key")
        step.expect(done.out.strip().splitlines()[-1] == LAST_LINE, "last line {!r}".format(done.out.strip().splitlines()[-1]))
        kit.fingerprints["user-b"] = added
        step.note("the new user key is {}".format(added))

    with report.step("user CA: node-a and node-c report the new trust id within {} s, node-b is offline and does not block".format(TRUST_DEADLINE)) as step:
        def current():
            status = kit.status()["user"]
            nodes = status["nodes"]
            ready = nodes["current"] == 2 and nodes["behind"] == 0 and step_of(status, "promote")
            return status if ready else None

        took, status = kit.wait("user add-next: both live nodes report the new trust id", current, TRUST_DEADLINE, interval=1)
        step.note("both live nodes reported after {:.1f} s".format(took))
        kit.record_trust_id("user", status["trust_id"])
        step.expect(status["nodes"]["offline_names"] == ["node-b"], "offline: {}".format(status["nodes"]))
        promote = step_of(status, "promote")
        step.expect(promote["allowed"], "promote is not allowed: {}".format(promote))
        step.expect(promote["line"] == "promote: ready", promote["line"])
        keys = keys_of(status)
        step.expect(keys == {"active": key_a, "next": kit.fingerprints["user-b"]}, "keys {}".format(keys))
        kit.check_session(step, "the user add-next")

    with report.step("user CA: status and the admin API agree after add-next") as step:
        kit.status_pair()

    with report.step("user CA: bob signs in before promote: a certificate signed by A that stays in his profile") as step:
        kit.sign_in("bob")
        signer = kit.signer_of("bob")
        step.expect(signer == fingerprint_text(key_a), "signed by {}".format(signer))
        kit.freeze("bob", "old-a")

    with report.step("user CA: promote applies (exit 0) and the watcher reloads within {} s".format(RELOAD_DEADLINE)) as step:
        kit.keep_session("node-a", "before the user promotion")
        done = kit.change("user", "promote")
        step.expect(done.status == 0, "exit {}: {}".format(done.status, done.text()))
        step.expect(done.out.strip().splitlines()[-1] == LAST_LINE, done.out)
        step.expect("promote: ready" in done.out, done.out)
        took, _ = kit.wait(
            "user promote: ca.reloaded names the new active key",
            lambda: reloaded(stand, "user", kit.fingerprints["user-b"]), RELOAD_DEADLINE, interval=1)
        step.note("the daemon applied the promotion after {:.1f} s".format(took))
        kit.check_session(step, "the user promotion")

    with report.step("user CA: retire is refused with exit 3 while certificates signed by A are unexpired") as step:
        status = kit.status()["user"]
        step.expect(keys_of(status).get("previous") == key_a, "keys {}".format(status["keys"]))
        done = kit.change("user", "retire")
        step.expect(done.status == 3, "exit {}: {}".format(done.status, done.text()))
        step.expect("retire: blocked:" in done.out and "unexpired user certificate" in done.out, done.text())
        step.expect(not done.out.strip().endswith(LAST_LINE), "the refusal claims it applied: {}".format(done.out))
        step.expect(keys_of(kit.status()["user"]).get("previous") == key_a, "A is no longer previous")

    with report.step("user CA: the older certificate signed by A (bob) still works until retire, on node-a and node-c") as step:
        left = kit.seconds_left("bob")
        for node in ("node-a", "node-c"):
            shown = kit.frozen_ssh("old-a", node, "echo old-$(hostname)")
            step.expect(shown.ok and shown.out.strip() == "old-{}".format(node), "{}: {}".format(node, shown.text()[-300:]))
        step.note("the certificate of bob had {} s left when it was tried".format(left))

    with report.step("user CA: a new login is signed by B and works on node-a and node-c") as step:
        kit.sign_in("alice")
        signer = kit.signer_of("alice")
        step.expect(signer == fingerprint_text(kit.fingerprints["user-b"]), "signed by {}, expected B".format(signer))
        for node in ("node-a", "node-c"):
            shown = stand.ssh("alice", node, "echo reached-$(hostname)")
            step.expect(shown.ok and shown.out.strip() == "reached-{}".format(node), "{}: {}".format(node, shown.text()))

    with report.step("user CA: node-b starts and accepts a certificate signed by B") as step:
        stand.agent_start("node-b")
        kit.fresh("alice", 30)
        took, _ = kit.wait("node-b serves a B certificate after it starts", lambda: kit.connects("alice", "node-b"), START_DEADLINE, interval=2)
        step.note("node-b answered {:.1f} s after the tunnel connected".format(took))
        step.expect(kit.signer_of("alice") == fingerprint_text(kit.fingerprints["user-b"]), "the certificate is not signed by B")

    with report.step("user CA: waiting until the certificates signed by A have expired makes retire ready") as step:
        def ready():
            status = kit.status()["user"]
            entry = step_of(status, "retire")
            return status if entry and entry["allowed"] else None

        took, status = kit.wait("user retire: certificates signed by A expire", ready, EXPIRY_DEADLINE, interval=5)
        step.note("retire became ready {:.1f} s after the start of the wait".format(took))
        step.expect(status["old_certificates"]["count"] == 0, "{}".format(status["old_certificates"]))

    with report.step("user CA: retire succeeds, status shows [B], API equals CLI") as step:
        kit.keep_session("node-a", "before the user retirement")
        done = kit.change("user", "retire")
        step.expect(done.status == 0, "exit {}: {}".format(done.status, done.text()))
        step.expect("user key {} retired".format(key_a) in done.out, done.out)
        step.expect(done.out.strip().splitlines()[-1] == LAST_LINE, done.out)
        cli, _ = kit.status_pair()
        step.expect(keys_of(cli["user"]) == {"active": kit.fingerprints["user-b"]}, "keys {}".format(cli["user"]["keys"]))
        kit.record_trust_id("user", cli["user"]["trust_id"])
        took, _ = kit.wait("user retire: ca.reloaded reports the single key",
                           lambda: reloaded_trust(stand, "user", cli["user"]["trust_id"]), RELOAD_DEADLINE, interval=1)
        step.note("the daemon applied the retirement after {:.1f} s".format(took))
        kit.check_session(step, "the user retirement")

    with report.step("user CA: after retire a new certificate signed by B works on every node") as step:
        kit.sign_in("alice")
        step.expect(kit.signer_of("alice") == fingerprint_text(kit.fingerprints["user-b"]), "the certificate is not signed by B")
        for node in ("node-a", "node-b", "node-c"):
            step.expect(kit.connects("alice", node), "alice cannot reach {} with a B certificate".format(node))
        step.note("the certificates signed by A have expired and the agent drops their keys, so the gate cannot be asked about them; "
                  "the gate refusing a retired key is shown in the forced retirement")

    kit.phase("user CA A to B", started)
