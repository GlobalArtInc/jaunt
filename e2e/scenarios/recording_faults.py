import re
import time

from stand import audit, cast, engine, recordings
from stand.layout import NETWORK, container
from stand.recordings import fetch, session_detail, wait_recording
from scenarios.recording import finished, shell, type_script

LINE = re.compile(r"line-(\d+)-x{8}")
SMALL_QUEUE = "recording:\n  session_queue_bytes: 1048576\n  memory_budget_bytes: 1048576\n"
TUNNEL_KEEPALIVE_INTERVAL_SECS = 20
TUNNEL_KEEPALIVE_TIMEOUT_SECS = 10
DETECTION_MARGIN_SECS = 30
OUTAGE_SECS = TUNNEL_KEEPALIVE_INTERVAL_SECS + TUNNEL_KEEPALIVE_TIMEOUT_SECS + DETECTION_MARGIN_SECS
TUNNEL_ALPN = "jaunt-tunnel/1"
BREAK_AUDIT_SECS = 30
RECONNECT_SECS = 120
CLIENT_END_SECS = 120
FLOODS = 3


def numbers(text):
    return [int(match) for match in LINE.findall(text)]


def cut_network(stand, node):
    cut = engine.engine("network", "disconnect", NETWORK, container(node))
    if not cut.ok:
        raise recordings.StepFailed("cannot disconnect {}: {}".format(node, cut.text()))
    return time.monotonic()


def restore_network(stand, node):
    back = engine.engine("network", "connect", "--alias", node, NETWORK, container(node))
    if not back.ok:
        raise recordings.StepFailed("cannot reconnect {}: {}".format(node, back.text()))


def outage(stand, node, seconds):
    marker = stand.marker()
    started = cut_network(stand, node)
    try:
        stand.wait_until("{} s without a network".format(seconds), lambda: time.monotonic() - started >= seconds, seconds + 20, interval=1)
    finally:
        restore_network(stand, node)
    return started, marker


def tunnel_events(stand, node, marker, kind):
    events = audit.after(stand.audit_events(), marker)
    return [event for event in audit.of_type(events, kind)
            if event.get("node") == stand.node_ids[node] and event["fields"].get("alpn") == TUNNEL_ALPN]


def require_tunnel_break(stand, node, marker):
    try:
        stand.wait_until("agent.disconnected for the tunnel of {}".format(node),
                         lambda: tunnel_events(stand, node, marker, "agent.disconnected"), BREAK_AUDIT_SECS, interval=2)
    except recordings.StepFailed:
        raise recordings.StepFailed(
            "the tunnel did not break on this engine: no agent.disconnected for the tunnel of {} within {} s "
            "after a {} s outage".format(node, BREAK_AUDIT_SECS, OUTAGE_SECS)) from None
    try:
        stand.wait_until("agent.connected for the tunnel of {} after the outage".format(node),
                         lambda: tunnel_events(stand, node, marker, "agent.connected"), RECONNECT_SECS, interval=2)
    except recordings.StepFailed:
        raise recordings.StepFailed(
            "the agent of {} did not connect its tunnel again within {} s after the network came back".format(
                node, RECONNECT_SECS)) from None


def run(stand, report):
    tunnel_break(stand, report)
    queue_overflow(stand, report)
    recording_disabled(stand, report)


def tunnel_break(stand, report):
    with report.step("a tunnel break in the middle of a long output session: the recording still completes whole") as step:
        marker = stand.marker()
        session = shell(stand, "alice", "node-a")
        try:
            session.send("for i in $(seq 1 300); do echo line-$i-xxxxxxxx; sleep 0.1; done; echo finished-$((6*7))\n")
            step.expect(session.expect("line-40-xxxxxxxx", 60), "the output did not start")
            started, cut_marker = outage(stand, "node-a", OUTAGE_SECS)
            require_tunnel_break(stand, "node-a", cut_marker)
            status = session.wait(CLIENT_END_SECS)
            received = numbers(session.text())
        finally:
            session.close()
        if status is None:
            step.note("the client session survived the tunnel break and was still open {} s after the network came back; "
                      "the test closed it; it had seen lines 1..{}".format(CLIENT_END_SECS, max(received or [0])))
        else:
            step.note("the client exited {} after {:.0f} s and had seen lines 1..{}".format(
                status, time.monotonic() - started, max(received or [0])))
            step.expect(status != 0, "the client exited {} after a broken tunnel".format(status))
        step.expect(received, "the client saw no lines: {}".format(received[:3]))
        step.expect(received == list(range(1, len(received) + 1)), "the client saw a gap: {}".format(received[:60]))
        started_ids = recordings.started_since(stand, marker, "alice", "node-a")
        step.expect(len(started_ids) == 1, "sessions started: {}".format(started_ids))
        session_id = started_ids[0]
        recordings.wait_ended(stand, started_ids)
        detail = wait_recording(stand, session_id, ("complete", "incomplete"), 180)
        step.expect(detail["recording"] == "complete", "recording after the reconnect: {}".format(detail["recording"]))
        raw = recordings.stored_cast(stand, session_id)
        header, events = cast.parse(raw)
        stored = numbers(cast.joined(events, "o"))
        step.note("the cast holds lines {}..{}".format(stored[0], stored[-1]))
        step.expect(stored == list(range(1, len(stored) + 1)), "the cast has a gap")
        step.expect(stored[:len(received)] == received, "the cast does not begin with what the client received")
        step.expect(len(stored) >= len(received), "the cast is shorter than what the client saw")
        status_, manifest = stand.api("GET", "/v1/admin/sessions/{}/recording/manifest".format(session_id))
        step.expect(not manifest["incomplete"] and manifest["dropped_chunks"] == 0, str(manifest))
        step.expect(stand.jauntd("recordings", "verify", session_id).ok, "recordings verify failed")
        events_after = audit.after(stand.audit_events(), marker)
        completed = [event for event in audit.of_type(events_after, "recording.completed") if event.get("session_id") == session_id]
        step.expect(len(completed) == 1 and completed[0]["fields"]["incomplete"] is False, str(completed))
        step.expect(not audit.of_type(events_after, "recording.mismatch"), "a recording.mismatch event")
        stand.wait_until("the shell of the cut session to be gone from the node", lambda: not stand.on_node(
            "node-a", ["pgrep", "-u", "deploy", "-x", "bash"]).ok, 30)


def queue_overflow(stand, report):
    flood = "sleep 4; head -c 8000000 /dev/urandom | base64 -w 200; echo flood-done-$((6*7))"
    with report.step("tiny recording limits and floods while the server is unreachable: recordings are incomplete") as step:
        restart_agent(stand, "node-a", SMALL_QUEUE)
        marker = stand.marker()
        sessions = [shell(stand, "alice", "node-a") for _ in range(FLOODS)]
        try:
            for session in sessions:
                session.send("echo ready-$((4*4))\n")
            for session in sessions:
                step.expect(session.expect("ready-16", 30), "a shell did not start")
            beginning = recordings.started_since(stand, marker, "alice", "node-a")
            step.expect(len(beginning) == FLOODS, "sessions started: {}".format(beginning))
            for session_id in beginning:
                wait_recording(stand, session_id, ("receiving",), 60)
            for session in sessions:
                session.send(flood + "\n")
            cut_marker = outage(stand, "node-a", OUTAGE_SECS)[1]
            require_tunnel_break(stand, "node-a", cut_marker)
            for session in sessions:
                session.wait(CLIENT_END_SECS)
        finally:
            for session in sessions:
                session.close()
        ended = recordings.started_since(stand, marker, "alice", "node-a")
        step.expect(len(ended) == FLOODS, "sessions started: {}".format(ended))
        recordings.wait_ended(stand, ended)
        manifests = {}
        for session_id in ended:
            wait_recording(stand, session_id, ("complete", "incomplete"), 180)
            manifests[session_id] = stand.api("GET", "/v1/admin/sessions/{}/recording/manifest".format(session_id))[1]
        incomplete = [session_id for session_id in ended if manifests[session_id]["incomplete"]]
        step.note("{} of {} recordings are incomplete; dropped chunks {}".format(
            len(incomplete), len(ended), [manifests[session_id]["dropped_chunks"] for session_id in ended]))
        step.expect(incomplete, "no recording is incomplete although the memory budget was 1 MiB and {} floods ran".format(FLOODS))
        session_id = incomplete[0]
        manifest = manifests[session_id]
        step.expect(manifest["state"] == "incomplete" and manifest["dropped_chunks"] > 0, str(manifest))
        step.expect(session_detail(stand, session_id)["recording"] == "incomplete", "the session detail does not say incomplete")
        listed = stand.api("GET", "/v1/admin/sessions?limit=50")[1]["sessions"]
        row = [entry for entry in listed if entry["id"] == session_id]
        step.expect(row and row[0]["recording"] == "incomplete", "the session list row: {}".format(row))
        events = audit.after(stand.audit_events(), marker)
        completed = [event for event in audit.of_type(events, "recording.completed") if event.get("session_id") == session_id]
        step.expect(len(completed) == 1 and completed[0]["fields"]["incomplete"] is True, str(completed))
        step.expect(not audit.of_type(events, "recording.mismatch"), "a recording.mismatch event")
        raw = recordings.stored_cast(stand, session_id)
        header, cast_events = cast.parse(raw)
        step.expect("ready-16" in cast.joined(cast_events, "o"), "the beginning of the session is not in the cast")
        served = fetch(stand, stand.admin, "/v1/admin/sessions/{}/recording".format(session_id), "incomplete.cast")
        step.expect(served.status == 200 and served.body() == raw, "the incomplete cast was not served as stored ({})".format(served.status))
        step.expect(stand.jauntd("recordings", "verify", session_id).ok, "recordings verify refused the incomplete recording")


def restart_agent(stand, node, config):
    stand.agent_config(node, config)
    stand.agent_stop(node)
    stand.agent_start(node)
    stand.wait_until("{} to be reachable".format(node), lambda: stand.agent_reconnected(node), 60)


def recording_disabled(stand, report):
    with report.step("recordings.dir removed: sessions keep working, the agent pauses uploads, the detail says none") as step:
        restart_agent(stand, "node-a", "")
        stand.restart_jauntd(recordings=False)
        stand.wait_until("node-a to be reachable", lambda: stand.agent_reconnected("node-a"), 90)
        marker = stand.marker()
        session = shell(stand, "alice", "node-a")
        try:
            ran = type_script(session, ["echo disabled-$((6*7))", "exit"], "disabled-42")
            status = finished(session)
        finally:
            session.close()
        step.expect(ran and status == 0, "the session failed while recording was off")
        stand.wait_until("the agent to log that uploads pause", lambda: "agent.ssh.recording_disabled" in stand.on_node(
            "node-a", ["cat", "/tmp/agent.log"]).out, 60, interval=2)
        session_id = recordings.started_since(stand, marker, "alice", "node-a")[-1]
        recordings.wait_ended(stand, [session_id])
        step.expect(session_detail(stand, session_id)["recording"] == "none", "the detail says {}".format(
            session_detail(stand, session_id)["recording"]))
        gone = fetch(stand, stand.admin, "/v1/admin/sessions/{}/recording/manifest".format(session_id), "disabled.manifest")
        step.expect(gone.status == 404, "the manifest answered {} with recording off".format(gone.status))
        plain = stand.ssh("alice", "node-a", "echo plain-$((6*7))")
        step.expect(plain.ok and "plain-42" in plain.out, plain.text())

    with report.step("recordings.dir back: after the agent restarts the next session is recorded again") as step:
        stand.restart_jauntd(recordings=True)
        stand.wait_until("node-a to be reachable", lambda: stand.agent_reconnected("node-a"), 90)
        marker = stand.marker()
        session = shell(stand, "alice", "node-a")
        try:
            type_script(session, ["echo paused-$((6*7))", "exit"], "paused-42")
            finished(session)
        finally:
            session.close()
        paused = recordings.started_since(stand, marker, "alice", "node-a")[-1]
        recordings.wait_ended(stand, [paused])
        step.note("a session started before the agent restarted: recording={}".format(session_detail(stand, paused)["recording"]))
        agent_log = stand.on_node("node-a", ["cat", "/tmp/agent.log"]).out
        step.note("agent recording events while paused: {}".format(sorted({
            match for match in re.findall(r'"event":"(agent\.ssh\.recording_[a-z_]+)"', agent_log)})))
        restart_agent(stand, "node-a", "")
        marker = stand.marker()
        session = shell(stand, "alice", "node-a")
        try:
            ran = type_script(session, ["echo resumed-$((6*7))", "exit"], "resumed-42")
            finished(session)
        finally:
            session.close()
        step.expect(ran, "the session did not run")
        resumed = recordings.started_since(stand, marker, "alice", "node-a")[-1]
        recordings.wait_ended(stand, [resumed])
        detail = wait_recording(stand, resumed, ("complete", "incomplete"), 60)
        step.expect(detail["recording"] == "complete", "the session after the restart: {}".format(detail["recording"]))
        header, cast_events = cast.parse(fetch(stand, stand.admin, "/v1/admin/sessions/{}/recording".format(resumed), "resumed.cast").body())
        step.expect("resumed-42" in cast.joined(cast_events, "o"), "the new recording lacks the typed output")
