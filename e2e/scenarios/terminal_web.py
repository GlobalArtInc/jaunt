import json
import os

from stand.layout import OUT

OPERATOR = "operator"
IDLE_USER = "dave"
IDLE_TIMEOUT_SECS = 180
RESULT_FILE = os.path.join(OUT, "web-workspace.json")
DENIAL_REFERENCE_PREFIX = "D-"


def environment():
    return {
        "E2E_WS_OPERATOR": OPERATOR,
        "E2E_WS_IDLE_USER": IDLE_USER,
        "E2E_WS_OUT": RESULT_FILE,
    }


def prepare():
    if os.path.exists(RESULT_FILE):
        os.remove(RESULT_FILE)


def events_of(stand, session_id, event_type):
    return [event for event in stand.audit_events(type=event_type) if event.get("session_id") == session_id]


def verify(stand, step):
    step.expect(os.path.exists(RESULT_FILE), "the browser run wrote no results")
    with open(RESULT_FILE) as handle:
        results = json.load(handle)["results"]
    closed = [row for row in results if row["kind"] == "closed_by_user"]
    step.expect(len(closed) == 2, "tabs closed with the confirmation: {}".format(closed))
    for row in closed:
        session_id = row["session"]
        stand.wait_until("terminal.closed of {}".format(session_id), lambda session_id=session_id: events_of(stand, session_id, "terminal.closed"), 30, interval=1)
        reason = events_of(stand, session_id, "terminal.closed")[0]["fields"].get("reason")
        step.expect(reason == "client_closed", "the tab {} closed with the reason {}".format(session_id[:8], reason))
    refs = [row for row in results if row["kind"] in ("limit", "limit_raw")]
    step.expect(len(refs) == 4, "limit references: {}".format(refs))
    for row in refs:
        ref = row["ref"]
        step.expect(ref.startswith(DENIAL_REFERENCE_PREFIX), "reference {}".format(ref))
        status, page = stand.api("GET", "/v1/admin/audit?ref={}".format(ref))
        found = page["events"] if status == 200 and page else []
        step.expect(len(found) == 1, "GET /v1/admin/audit?ref={} answered {} with {} events".format(ref, status, len(found)))
        if found:
            step.expect(found[0]["type"] == "terminal.denied" and found[0]["fields"].get("reason") == "limit",
                        "the audit event of {} is {}".format(ref, found[0]))
    terminated = [row for row in results if row["kind"] == "terminated"]
    step.expect(len(terminated) == 2, "terminated sessions: {}".format(terminated))
    for row in terminated:
        session_id = row["session"]
        stand.wait_until("session.terminated of {}".format(session_id), lambda session_id=session_id: events_of(stand, session_id, "session.terminated"), 30, interval=1)
        event = events_of(stand, session_id, "session.terminated")[0]
        step.expect(event["fields"].get("reason") == row["reason"], "session.terminated of {}: {}".format(session_id[:8], event))
        stand.wait_until("terminal.closed of {}".format(session_id), lambda session_id=session_id: events_of(stand, session_id, "terminal.closed"), 30, interval=1)
        reason = events_of(stand, session_id, "terminal.closed")[0]["fields"].get("reason")
        step.expect(reason == "terminated", "the terminated session {} closed with the reason {}".format(session_id[:8], reason))
        status, detail = stand.api("GET", "/v1/admin/sessions/{}".format(session_id))
        step.expect(status == 200 and detail.get("origin") == "web" and detail.get("end_reason") == "terminated",
                    "the session {} reads {} {}".format(session_id[:8], status, detail))
    idle = [row for row in results if row["kind"] == "idle"]
    step.expect(len(idle) == 2, "idle runs: {}".format(idle))
    for row in idle:
        step.note("idle warning of {} after {} ms".format(row["session"][:8], row.get("warned_after_ms")))
