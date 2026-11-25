import base64
import hashlib
import json

from stand import audit, cast, recordings
from stand.interactive import Interactive
from stand.recordings import StepFailed, fetch, session_detail, wait_recording

SHELL_MARKER = " shell start"
EXEC_MARKER = " exec bash"
INERT_POLICY = "default-src 'none'; sandbox"
UPLOAD_BYTES = 300000


def shell(stand, user, node, command=None, flag="-tt"):
    return Interactive(stand.ssh_argv(node, command, extra=(flag,)), user, stand.user_env(user))


def type_script(session, lines, expected):
    for line in lines:
        if isinstance(line, tuple):
            if not session.expect(line[1], 30):
                return False
        else:
            session.send(line + "\n")
    return session.expect(expected, 30)


def finished(session):
    status = session.wait(30)
    session.close()
    return status


def served_cast(stand, session, session_id, name):
    got = fetch(stand, session, "/v1/admin/sessions/{}/recording".format(session_id), name)
    if got.status != 200:
        raise StepFailed("the recording answered {}".format(got.status))
    return got


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def record_shell(stand, user, node, lines, expected, command=None, flag="-tt"):
    marker = stand.marker()
    session = shell(stand, user, node, command, flag)
    try:
        ran = type_script(session, lines, expected)
        status = finished(session)
        output = session.text()
    finally:
        session.close()
    return marker, ran, status, output


def secret_check(stand, session_id, secret, expect_input):
    served = served_cast(stand, stand.admin, session_id, "secret-{}.cast".format(session_id)).body()
    stored = recordings.stored_cast(stand, session_id)
    header, events = cast.parse(served)
    stored_manifest = recordings.stored_manifest(stand, session_id)
    status, api_manifest = stand.api("GET", "/v1/admin/sessions/{}/recording/manifest".format(session_id))
    inputs = cast.joined(events, "i")
    outputs = cast.joined(events, "o")
    problems = []
    if served != stored:
        problems.append("the served cast differs from the stored file")
    if secret in outputs:
        problems.append("the secret is in the output events")
    if expect_input:
        if secret not in inputs:
            problems.append("the secret is missing from the input events")
        if not (stored_manifest["input_recorded"] and api_manifest["input_recorded"]):
            problems.append("the manifest does not say input_recorded")
    else:
        if secret in served.decode("utf-8") or secret in stored.decode("utf-8"):
            problems.append("the secret is in the cast")
        if inputs or stored_manifest["input_recorded"] or api_manifest["input_recorded"]:
            problems.append("input events or input_recorded without the role permission")
    if secret in json_text(stored_manifest) or secret in json_text(api_manifest):
        problems.append("the secret is in a manifest")
    return problems


def json_text(value):
    return json.dumps(value)


def logs_with(stand, secret):
    texts = recordings.logs_of(stand, ["jauntd", "node-a", "node-b"])
    return recordings.occurrences(texts, secret)


def hidden_input(secret):
    return ["stty -echo; echo ready-$((3*3)); cat >/dev/null", ("expect", "ready-9"), secret, "\x04", "stty echo", "echo typed-$((2+3))"]


def viewer_session(stand):
    if stand.viewer is None:
        raise StepFailed("the sessions.read web session of the first step is missing")
    return stand.viewer


def needs(state, key):
    if key not in state:
        raise StepFailed("this step needs the result of an earlier step that did not finish: {}".format(key))
    return state[key]


def run(stand, report):
    state = {}
    with report.step("the admin API can be used by a viewer with only sessions.read") as step:
        stand.viewer = stand.web_login("viewer", "/tmp/viewer-cookies")
        step.expect(stand.viewer["permissions"] == ["sessions.read"], "permissions {}".format(stand.viewer["permissions"]))

    with report.step("an interactive ssh -tt session through the gate runs typed commands") as step:
        marker, ran, status, output = record_shell(
            stand, "alice", "node-a", ["echo rec-$((6*7))", "exit"], "rec-42")
        step.expect(ran and status == 0, "typed commands: ran={} status={}\n{}".format(ran, status, output[-400:]))
        state["shell"] = recordings.last_session(stand, marker, "alice", "node-a")

    with report.step("the recording completes: the session detail says complete and the manifest agrees") as step:
        detail = wait_recording(stand, needs(state, "shell"), ("complete", "incomplete"))
        step.expect(detail["recording"] == "complete", "recording: {}".format(detail["recording"]))
        status, manifest = stand.api("GET", "/v1/admin/sessions/{}/recording/manifest".format(needs(state, "shell")))
        step.expect(status == 200 and manifest["state"] == "complete", "manifest {} {}".format(status, manifest))
        step.expect(manifest["kind"] == "shell" and manifest["chunks"] >= 1 and manifest["has_cast"], str(manifest))
        step.expect(not manifest["incomplete"] and manifest["dropped_chunks"] == 0 and not manifest["input_recorded"], str(manifest))
        state["shell_manifest"] = manifest

    with report.step("an admin with recordings.read gets the manifest and the cast, a sessions.read admin gets 403") as step:
        base = "/v1/admin/sessions/{}/recording".format(needs(state, "shell"))
        step.expect(fetch(stand, stand.admin, base, "admin.cast").status == 200, "the cast was refused for the admin")
        step.expect(fetch(stand, stand.admin, base + "/manifest", "admin.manifest").status == 200, "the manifest was refused")
        for suffix, name in (("", "viewer.cast"), ("/manifest", "viewer.manifest")):
            refused = fetch(stand, viewer_session(stand), base + suffix, name)
            step.expect(refused.status == 403, "viewer got {} for {}".format(refused.status, base + suffix))
        step.expect(session_detail_for(stand, viewer_session(stand), needs(state, "shell")) == 200, "the viewer cannot read the session detail")
        anonymous = fetch(stand, {"jar": "/tmp/no-cookies"}, base, "anonymous.cast")
        step.expect(anonymous.status == 401, "no cookie got {}".format(anonymous.status))

    with report.step("jauntd recordings verify exits 0 for the stored recording") as step:
        verified = stand.jauntd("recordings", "verify", needs(state, "shell"))
        step.expect(verified.ok, verified.text())

    with report.step("the cast passes a strict asciicast v2 reader, holds the typed output and equals the stored file") as step:
        served = served_cast(stand, stand.admin, needs(state, "shell"), "shell.cast").body()
        header, events = cast.parse(served)
        step.expect("rec-42" in cast.joined(events, "o"), "the typed output is missing")
        step.expect(any(marker.endswith(SHELL_MARKER) for marker in cast.markers(events)), str(cast.markers(events)))
        step.expect(not cast.joined(events, "i"), "input events without the role permission")
        step.expect(needs(state, "shell_manifest")["raw_bytes"] == len(served), "raw_bytes {} against {} served".format(
            needs(state, "shell_manifest")["raw_bytes"], len(served)))
        step.expect(sha(served) == sha(recordings.stored_cast(stand, needs(state, "shell"))), "served and stored casts differ")

    secret = recordings.unique_token("secret")
    with report.step("record_input off: a typed secret is nowhere in the cast, the manifests or the logs") as step:
        marker, ran, status, output = record_shell(
            stand, "alice", "node-a", hidden_input(secret) + ["exit"], "typed-5")
        step.expect(ran and status == 0, "session: ran={} status={}\n{}".format(ran, status, output[-300:]))
        session_id = recordings.last_session(stand, marker, "alice", "node-a")
        step.expect(wait_recording(stand, session_id, ("complete", "incomplete"))["recording"] == "complete", "not complete")
        step.expect(secret not in output, "the secret was echoed to the client terminal")
        problems = secret_check(stand, session_id, secret, False)
        step.expect(not problems, "; ".join(problems))
        step.expect(not logs_with(stand, secret), "the secret is in the logs: {}".format(logs_with(stand, secret)))

    with report.step("record_input on: the same secret is stored as input events and the manifest says so") as step:
        status_, output_, browser = stand.login("dave")
        step.expect(status_ == 0, "dave could not sign in: {}".format(output_))
        stand.certs["dave"] = stand.certificate_info("dave")
        marker, ran, status, output = record_shell(
            stand, "dave", "node-a", hidden_input(secret) + ["exit"], "typed-5")
        step.expect(ran and status == 0, "session: ran={} status={}\n{}".format(ran, status, output[-300:]))
        session_id = recordings.last_session(stand, marker, "dave", "node-a")
        step.expect(wait_recording(stand, session_id, ("complete", "incomplete"))["recording"] == "complete", "not complete")
        problems = secret_check(stand, session_id, secret, True)
        step.expect(not problems, "; ".join(problems))
        step.expect(secret not in logs_with_text(stand), "the secret reached a log")

    with report.step("ssh -t host bash (exec with a PTY) is recorded as a cast with the command marker") as step:
        marker, ran, status, output = record_shell(
            stand, "alice", "node-a", ["echo ptyexec-$((6*7))", "exit"], "ptyexec-42", command="bash", flag="-t")
        step.expect(ran and status == 0, "session: ran={} status={}\n{}".format(ran, status, output[-300:]))
        session_id = recordings.last_session(stand, marker, "alice", "node-a")
        wait_recording(stand, session_id, ("complete",))
        raw = served_cast(stand, stand.admin, session_id, "ptyexec.cast").body()
        header, events = cast.parse(raw)
        step.expect("ptyexec-42" in cast.joined(events, "o"), "the output is missing")
        step.expect(any(m.endswith(EXEC_MARKER) for m in cast.markers(events)), str(cast.markers(events)))

    with report.step("ssh host cmd without a PTY is a metadata-only recording with the command, status and counts") as step:
        marker = stand.marker()
        shown = stand.ssh("alice", "node-a", "echo exec-$((6*7)); exit 7")
        step.expect(shown.status == 7 and "exec-42" in shown.out, shown.text())
        session_id = recordings.last_session(stand, marker, "alice", "node-a")
        wait_recording(stand, session_id, ("complete",))
        metadata_only(stand, step, session_id, "exec", expect_command="echo exec-$((6*7)); exit 7", exit_status=7, min_out=1)

    for label, argv_flags, kind in (("scp (sftp protocol)", [], "sftp"), ("scp -O (legacy protocol)", ["-O"], "exec")):
        with report.step("{} is a metadata-only recording with byte counts".format(label)) as step:
            marker = stand.marker()
            sent = stand.on_client(["sh", "-c", "head -c {} /dev/urandom >/tmp/e2e-small && scp -o BatchMode=yes {} /tmp/e2e-small deploy@node-a.e2e.test:small-scp".format(UPLOAD_BYTES, " ".join(argv_flags))],
                                   user="alice", timeout=120)
            step.expect(sent.ok, sent.text())
            session_id = recordings.last_session(stand, marker, "alice", "node-a")
            wait_recording(stand, session_id, ("complete",))
            metadata_only(stand, step, session_id, kind, min_in=UPLOAD_BYTES)
            stand.on_node("node-a", ["rm", "-f", "/home/deploy/small-scp"])

    with report.step("sftp is a metadata-only recording with byte counts") as step:
        marker = stand.marker()
        sent = stand.on_client(["sh", "-c", "printf 'put /tmp/e2e-small sftp-small\\nget sftp-small /tmp/e2e-sftp-back\\n' >/tmp/e2e-batch && sftp -o BatchMode=yes -b /tmp/e2e-batch deploy@node-a.e2e.test"],
                               user="alice", timeout=120)
        step.expect(sent.ok, sent.text())
        session_id = recordings.last_session(stand, marker, "alice", "node-a")
        wait_recording(stand, session_id, ("complete",))
        metadata_only(stand, step, session_id, "sftp", min_in=UPLOAD_BYTES, min_out=UPLOAD_BYTES)
        stand.on_node("node-a", ["rm", "-f", "/home/deploy/sftp-small"])
        stand.on_client(["rm", "-f", "/tmp/e2e-small", "/tmp/e2e-sftp-back", "/tmp/e2e-batch"], user="alice")

    hostile(stand, report)
    viewed(stand, report)


def session_detail_for(stand, session, session_id):
    status, _ = stand.api("GET", "/v1/admin/sessions/{}".format(session_id), session=session)
    return status


def logs_with_text(stand):
    return "".join(recordings.logs_of(stand, ["jauntd", "node-a"]).values())


def metadata_only(stand, step, session_id, kind, expect_command=None, exit_status=None, min_in=None, min_out=None):
    status, manifest = stand.api("GET", "/v1/admin/sessions/{}/recording/manifest".format(session_id))
    step.expect(status == 200, "manifest answered {}".format(status))
    step.expect(manifest["kind"] == kind, "kind {} is not {}: {}".format(manifest["kind"], kind, manifest))
    step.expect(manifest["chunks"] == 0 and not manifest["has_cast"] and not manifest["incomplete"], str(manifest))
    stored = recordings.stored_manifest(stand, session_id)
    step.expect(stored["chunks"] == 0 and stored["kind"] == kind, str(stored))
    if expect_command is not None:
        step.expect(manifest["command"] == expect_command and stored["command"] == expect_command, str(manifest))
    if exit_status is not None:
        step.expect(stored["exit_status"] == exit_status, "stored exit status {}".format(stored["exit_status"]))
    if min_in is not None:
        step.expect(stored["bytes_in"] >= min_in, "bytes_in {} is below {}".format(stored["bytes_in"], min_in))
    if min_out is not None:
        step.expect(stored["bytes_out"] >= min_out, "bytes_out {} is below {}".format(stored["bytes_out"], min_out))
    detail = session_detail(stand, session_id)
    step.expect(detail["bytes_out"] is not None and detail["bytes_in"] is not None, str(detail))
    step.note("kind={} command={!r} exit={} bytes_in={} bytes_out={}".format(
        stored["kind"], stored["command"], stored["exit_status"], stored["bytes_in"], stored["bytes_out"]))
    gone = fetch(stand, stand.admin, "/v1/admin/sessions/{}/recording".format(session_id), "none-{}.cast".format(session_id))
    step.expect(gone.status == 404, "a metadata-only recording served a cast: {}".format(gone.status))


def hostile(stand, report):
    pasted = base64.b64encode(b"e2e-clipboard-marker").decode()
    sequences = [
        "\x1b]52;c;{}\x07".format(pasted),
        "\x1b]0;e2e-window-title\x07",
        "\x1b[999999999C\x1b[999999999A\x1b[2147483647B\x1b[999999999;999999999H",
    ]
    command = "printf '\\033]52;c;{}\\a\\033]0;e2e-window-title\\a\\033[999999999C\\033[999999999A\\033[2147483647B\\033[999999999;999999999H'; echo; echo end-hostile".format(pasted)
    with report.step("hostile output (OSC 52, OSC 0, huge CSI counts) is stored and served byte for byte with inert headers") as step:
        marker, ran, status, output = record_shell(stand, "alice", "node-a", [command, "exit"], "end-hostile")
        step.expect(ran and status == 0, "session: ran={} status={}".format(ran, status))
        session_id = recordings.last_session(stand, marker, "alice", "node-a")
        wait_recording(stand, session_id, ("complete",))
        got = served_cast(stand, stand.admin, session_id, "hostile.cast")
        raw = got.body()
        header, events = cast.parse(raw)
        text = cast.joined(events, "o")
        for sequence in sequences:
            step.expect(sequence in text, "the sequence {!r} did not survive in the cast".format(sequence))
        step.expect(sha(raw) == sha(recordings.stored_cast(stand, session_id)), "served and stored differ")
        step.expect(got.headers.get("content-type", "").startswith("application/x-asciicast"), str(got.headers))
        step.expect(got.headers.get("x-content-type-options") == "nosniff", str(got.headers))
        step.expect(got.headers.get("content-security-policy") == INERT_POLICY, str(got.headers))
        step.expect(got.headers.get("content-disposition", "").startswith("attachment"), str(got.headers))
        step.expect(got.headers.get("cache-control") == "no-store", str(got.headers))
        manifest = fetch(stand, stand.admin, "/v1/admin/sessions/{}/recording/manifest".format(session_id), "hostile.manifest")
        step.expect(manifest.headers.get("content-security-policy") == INERT_POLICY, str(manifest.headers))


def viewed(stand, report):
    marker, ran, status, output = record_shell(stand, "alice", "node-a", ["echo viewed-$((6*7))", "exit"], "viewed-42")
    session_id = recordings.last_session(stand, marker, "alice", "node-a")
    wait_recording(stand, session_id, ("complete",))
    base = "/v1/admin/sessions/{}/recording".format(session_id)
    admin = stand.admin["user_id"]
    marker = stand.marker()

    def views(kind):
        events = audit.after(stand.audit_events(), marker)
        return [event for event in audit.of_type(events, "recording.viewed")
                if event["actor"] == admin and event.get("session_id") == session_id and event["fields"].get("kind") == kind]

    with report.step("recording.viewed is audited once per minute per actor, session and kind") as step:
        recordings.burst(stand, stand.admin, [base, base + "/manifest"] * 3 + [base + "?download=1"])
        stand.wait_until("the first views to reach the audit log", lambda: all(
            views(kind) for kind in ("stream", "manifest", "download")), 30, interval=1)
        for kind in ("stream", "manifest", "download"):
            step.expect(len(views(kind)) == 1, "{} views: {}".format(kind, len(views(kind))))
        viewer_marker = stand.marker()
        refused = fetch(stand, viewer_session(stand), base, "viewer-again.cast")
        step.expect(refused.status == 403, "the viewer got {}".format(refused.status))
        events = audit.after(stand.audit_events(), viewer_marker)
        step.expect(not audit.of_type(events, "recording.viewed"), "a refused viewer left a recording.viewed event")

    with report.step("a view after the one-minute window is audited again") as step:
        def again():
            fetch(stand, stand.admin, base, "viewed-later.cast")
            return len(views("stream")) >= 2

        stand.wait_until("a second recording.viewed after the window", again, 90, interval=5)
