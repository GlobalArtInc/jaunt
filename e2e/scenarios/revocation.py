import re
import time

from stand import audit
from stand.texts import GENERIC_REFUSAL, refusal_texts

LIVE_LIMIT_SECS = 5.0
REVOKED_SIGN_IN = "the sign-in request is no longer valid"
DENIED_SIGN_IN = "sign-in was denied"


def start_session(stand, user, node):
    baseline = stand.accepted_logins(node)
    stream = stand.ssh_stream(user, node, "sleep 600")

    def running():
        return stand.accepted_logins(node) > baseline and stand.on_node(node, ["pgrep", "-u", "deploy", "-f", "sleep 600"]).ok

    stand.wait_until("the long session of {} on {}".format(user, node), running, 30)
    return stream


def cut_session(stand, step, stream, cut):
    started = time.monotonic()
    cut()
    returned = time.monotonic()
    deadline = started + 30
    while stream.running() and time.monotonic() < deadline:
        time.sleep(0.05)
    ended = time.monotonic()
    step.note("the session ended {:.2f} s after the revocation call started, {:.2f} s after it returned".format(
        ended - started, ended - returned))
    step.expect(not stream.running(), "the session is still alive after 30 s")
    step.expect(ended - started <= LIVE_LIMIT_SECS,
                "the session needed {:.2f} s from the start of the call, the limit is {} s".format(ended - started, LIVE_LIMIT_SECS))
    step.expect(stream.finish(5) != 0, "ssh exited 0 although the session was cut")


def sign_in_again(stand, step, user):
    status, output, browser = stand.login(user)
    step.expect(status == 0, "jaunt login: {}\nbrowser: {}".format(output, browser.text()))
    stand.certs[user] = stand.certificate_info(user)


def node_clean(stand, node):
    return not stand.on_node(node, ["pgrep", "-f", "^sshd(-session)?: deploy"]).ok


def sweep_leftovers(stand, node):
    stand.on_node(node, ["pkill", "-u", "deploy", "-f", "sleep 600"])


def expect_refused(stand, step, user, node):
    before = stand.accepted_logins(node)
    shown = stand.ssh(user, node, "true")
    step.expect(shown.status != 0, "ssh succeeded for a revoked user")
    step.expect(refusal_texts(shown.err) == [GENERIC_REFUSAL], "stderr: {}".format(shown.err.strip()))
    step.expect(stand.accepted_logins(node) == before, "sshd on {} logged a login".format(node))


def session_order(step, events, user_id):
    terminated = [event for event in audit.by_actor(audit.of_type(events, "session.terminated"), user_id)]
    step.expect(len(terminated) == 1, "session.terminated events of the user: {}".format(len(terminated)))
    session = audit.of_session(events, terminated[0]["session_id"])
    step.expect(audit.appears_in_order(session, ["session.routed", "session.start", "session.terminated", "session.end"]),
                "events of the cut session: {}".format(audit.kinds(session)))
    created = [event for event in audit.of_type(events, "revoke.created") if event["fields"].get("subject") == user_id]
    step.expect(len(created) == 1, "revoke.created events for the user: {}".format(len(created)))
    step.expect((created[0]["time"], created[0]["id"]) <= (terminated[0]["time"], terminated[0]["id"]),
                "the session was terminated before the revocation was recorded")
    removed = [event for event in audit.of_type(events, "revoke.removed") if event["fields"].get("subject") == user_id]
    step.expect(len(removed) == 1 and (removed[0]["time"], removed[0]["id"]) > (terminated[0]["time"], terminated[0]["id"]),
                "revoke.removed events after the termination: {}".format(len(removed)))


def run(stand, report):
    alice = stand.certs["alice"]["principal"]

    marker = stand.marker()
    with report.step("revoke user through jauntd: the live session of alice ends within {} s".format(LIVE_LIMIT_SECS)) as step:
        stream = start_session(stand, "alice", "node-a")
        done = {}

        def cut():
            done["result"] = stand.jauntd("revoke", "user", alice, "--reason", "e2e revoke through the CLI")

        cut_session(stand, step, stream, cut)
        step.expect(done["result"].ok, done["result"].text())
        stand.cli_revocation = done["result"].out

    with report.step("sshd on node-a closed the cut session") as step:
        stand.wait_until("the node to drop the session", lambda: node_clean(stand, "node-a"), 10)
        leftover = stand.on_node("node-a", ["pgrep", "-u", "deploy", "-f", "sleep 600"]).ok
        step.note("the remote command 'sleep 600' is {}".format("still running (OpenSSH keeps commands without a terminal)" if leftover else "gone"))
        sweep_leftovers(stand, "node-a")

    with report.step("a new connection of the revoked user gets the generic refusal and sshd sees no login") as step:
        expect_refused(stand, step, "alice", "node-a")

    with report.step("a revoked user cannot sign in, and the refusal differs from an unknown identity") as step:
        status, output, browser = stand.login("alice")
        step.expect(status != 0, "jaunt login succeeded for a revoked user")
        step.expect(REVOKED_SIGN_IN in output, "output: {}".format(output.strip()))
        status, output, browser = stand.login("alice", hint="mallory")
        step.expect(status != 0, "jaunt login succeeded for an unknown identity")
        step.expect(DENIED_SIGN_IN in output and REVOKED_SIGN_IN not in output, "output: {}".format(output.strip()))

    with report.step("jauntd revocations rm lifts the revocation and a new sign-in restores access") as step:
        found = re.search(r"\(revocation (\S+)\)", stand.cli_revocation)
        step.expect(found, "no revocation id in: {}".format(stand.cli_revocation))
        listed = stand.jauntd("revocations", "list")
        step.expect(found.group(1) in listed.out, "the revocation is not listed:\n{}".format(listed.out))
        removed = stand.jauntd("revocations", "rm", found.group(1))
        step.expect(removed.ok, removed.text())
        sign_in_again(stand, step, "alice")
        shown = stand.ssh("alice", "node-a", "id -un")
        step.expect(shown.ok and shown.out.strip() == "deploy", shown.text())

    with report.step("audit: the cut session shows routed, start, terminated, end after revoke.created and before revoke.removed") as step:
        events = audit.after(stand.audit_events(), marker)
        session_order(step, events, alice)

    marker = stand.marker()
    with report.step("revoke user through the admin API: the live session of alice ends within {} s".format(LIVE_LIMIT_SECS)) as step:
        stream = start_session(stand, "alice", "node-a")
        done = {}

        def cut():
            done["answer"] = stand.api("POST", "/v1/admin/revocations", {
                "kind": "user", "subject": alice, "reason": "e2e revoke through the admin API"})

        cut_session(stand, step, stream, cut)
        status, body = done["answer"]
        step.expect(status in (200, 201) and body, "the API answered {} {}".format(status, body))
        stand.revocation = body["revocation"]["id"]
        step.expect(body["terminated_sessions"] >= 1, "terminated_sessions {}".format(body["terminated_sessions"]))

    with report.step("a new connection gets the generic refusal while the API revocation stands") as step:
        expect_refused(stand, step, "alice", "node-a")

    with report.step("DELETE /v1/admin/revocations lifts it and a new sign-in restores access") as step:
        status, body = stand.api("DELETE", "/v1/admin/revocations/{}".format(stand.revocation))
        step.expect(status in (200, 204), "delete answered {} {}".format(status, body))
        sign_in_again(stand, step, "alice")
        shown = stand.ssh("alice", "node-a", "id -un")
        step.expect(shown.ok and shown.out.strip() == "deploy", shown.text())

    with report.step("audit: the API revocation cut one session in order and was recorded by the admin") as step:
        events = audit.after(stand.audit_events(), marker)
        session_order(step, events, alice)
        created = audit.of_type(events, "revoke.created")
        step.expect(created and created[0]["actor"] == "web:" + stand.admin["user_id"], "revoke.created actor: {}".format(created))
        sweep_leftovers(stand, "node-a")
