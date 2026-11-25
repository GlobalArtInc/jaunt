import json
import os

from . import engine
from .layout import CA_PEM, OUT, PROJECT, WEB_ORIGIN, container
from .report import StepFailed

ARTIFACTS = os.path.join(OUT, "artifacts", PROJECT)
RECORDINGS_ROOT = "/var/lib/jaunt/recordings"


class Fetched:
    def __init__(self, status, headers, path):
        self.status = status
        self.headers = headers
        self.path = path

    def body(self):
        with open(self.path, "rb") as handle:
            return handle.read()


def fetch(stand, session, path, name):
    remote = "/tmp/fetch-{}".format(name)
    shown = stand.on_client([
        "curl", "-sS", "--max-time", "60", "--cacert", CA_PEM, "-b", session["jar"],
        "-D", remote + ".headers", "-o", remote, "-w", "%{http_code}", "{}{}".format(WEB_ORIGIN, path),
    ], timeout=90)
    if not shown.out.strip().isdigit():
        raise StepFailed("fetching {} failed: {}".format(path, shown.text()))
    raw = stand.on_client(["cat", remote + ".headers"]).out
    headers = {}
    for line in raw.splitlines():
        if ":" in line and not line.startswith("HTTP/"):
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    os.makedirs(ARTIFACTS, exist_ok=True)
    local = os.path.join(ARTIFACTS, name)
    copied = engine.engine("cp", "{}:{}".format(container("client"), remote), local)
    if not copied.ok:
        raise StepFailed("copying {} out of the client failed: {}".format(remote, copied.text()))
    return Fetched(int(shown.out.strip()), headers, local)


def burst(stand, session, paths):
    script = 'for path in "$@"; do curl -sS --max-time 30 --cacert {} -b {} -o /dev/null "{}$path" || exit 1; done'.format(
        CA_PEM, session["jar"], WEB_ORIGIN)
    shown = stand.on_client(["sh", "-c", script, "sh"] + list(paths), timeout=120)
    if not shown.ok:
        raise StepFailed("a burst of requests failed: {}".format(shown.text()))


def session_detail(stand, session_id):
    status, body = stand.api("GET", "/v1/admin/sessions/{}".format(session_id))
    if status != 200 or not body:
        raise StepFailed("the session detail answered {} {}".format(status, body))
    return body


def wait_recording(stand, session_id, states, timeout=60):
    seen = {}

    def reached():
        seen["detail"] = session_detail(stand, session_id)
        return seen["detail"]["recording"] in states

    stand.wait_until("the recording of {} to be one of {}".format(session_id, list(states)), reached, timeout, interval=1)
    return seen["detail"]


def ended_since(stand, marker, user_key, node):
    from . import audit
    events = audit.after(stand.audit_events(), marker)
    ends = [event for event in audit.by_actor(events, stand.certs[user_key]["principal"])
            if event["type"] == "session.end" and event.get("node") == stand.node_ids[node]]
    return [event["session_id"] for event in ends]


def started_since(stand, marker, user_key, node):
    from . import audit
    events = audit.after(stand.audit_events(), marker)
    starts = [event for event in audit.by_actor(events, stand.certs[user_key]["principal"])
              if event["type"] == "session.start" and event.get("node") == stand.node_ids[node]]
    return [event["session_id"] for event in starts]


def wait_ended(stand, session_ids, timeout=120):
    def all_ended():
        return all(session_detail(stand, session_id)["state"] == "ended" for session_id in session_ids)

    stand.wait_until("sessions {} to be reported as ended".format([i[:8] for i in session_ids]), all_ended, timeout, interval=2)


def last_session(stand, marker, user_key, node, timeout=60):
    found = {}

    def reported():
        found["ids"] = ended_since(stand, marker, user_key, node)
        return bool(found["ids"])

    stand.wait_until("a session of {} on {} to be reported as ended".format(user_key, node), reported, timeout, interval=1)
    return found["ids"][-1]


def stored_paths(stand, session_id):
    shown = stand.on_server(["find", RECORDINGS_ROOT, "-name", "{}.*".format(session_id)])
    paths = [line for line in shown.out.split() if line]
    cast = [path for path in paths if path.endswith(".cast")]
    manifest = [path for path in paths if path.endswith(".manifest.json")]
    return (cast[0] if cast else None), (manifest[0] if manifest else None)


def stored_manifest(stand, session_id):
    _, manifest = stored_paths(stand, session_id)
    if not manifest:
        raise StepFailed("no stored manifest for {}".format(session_id))
    return json.loads(stand.on_server(["cat", manifest]).out)


def stored_cast(stand, session_id):
    cast, _ = stored_paths(stand, session_id)
    if not cast:
        raise StepFailed("no stored cast for {}".format(session_id))
    os.makedirs(ARTIFACTS, exist_ok=True)
    local = os.path.join(ARTIFACTS, "stored-{}.cast".format(session_id))
    copied = engine.engine("cp", "{}:{}".format(container("jauntd"), cast), local)
    if not copied.ok:
        raise StepFailed("copying the stored cast out of jauntd failed: {}".format(copied.text()))
    with open(local, "rb") as handle:
        return handle.read()


def logs_of(stand, roles):
    texts = {}
    for role in roles:
        if role.startswith("node-"):
            texts[role] = stand.on_node(role, ["cat", "/tmp/agent.log"]).out + "".join(stand.saved_agent_logs(role).values())
        else:
            logged = engine.engine("logs", container(role))
            texts[role] = logged.out + logged.err
    return texts


def occurrences(texts, needle):
    return {name: text.count(needle) for name, text in texts.items() if needle in text}


def unique_token(prefix):
    return "{}-{}".format(prefix, os.urandom(8).hex())
