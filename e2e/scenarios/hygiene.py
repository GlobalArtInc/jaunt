import json
import os
import re

from stand import engine
from stand.layout import FIXTURES, container
from stand.stand import SECRET_PATTERNS

ALLOWED_ERRORS_FILE = "allowed-errors.txt"
STOP_ORDER = ("client", "node-a", "node-b", "node-c", "jauntd", "edge-web", "edge-idp", "idp")


def allowed_errors():
    path = os.path.join(FIXTURES, ALLOWED_ERRORS_FILE)
    if not os.path.exists(path):
        return []
    with open(path) as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def error_lines(text, allowed):
    found = []
    for line in text.splitlines():
        level = None
        try:
            level = json.loads(line).get("level")
        except ValueError:
            if re.search(r"\bERROR\b", line):
                level = "ERROR"
        if level in ("ERROR", "error") and not any(pattern in line for pattern in allowed):
            found.append(line[:300])
    return found


def profile_secrets(stand):
    values = []
    for user in ("alice", "bob", "carol"):
        listed = stand.on_client(["sh", "-c", "ls /home/{0}/.jaunt/default/ 2>/dev/null".format(user)], user=user).out.split()
        for name in listed:
            if "token" in name:
                value = stand.on_client(["cat", "/home/{}/.jaunt/default/{}".format(user, name)], user=user).out.strip()
                if len(value) >= 16:
                    values.append(value)
    return values


def mode_problems(stand):
    problems = []
    data = stand.on_server(["sh", "-c",
        "stat -c '%a %U' /var/lib/jaunt; stat -c '%a' /var/lib/jaunt/jaunt.db; stat -c '%a' /var/lib/jaunt/recordings; "
        "find /var/lib/jaunt -mindepth 1 ! -path '/var/lib/jaunt/recordings*' \\( -type d -o -type f \\) -perm /077 -print; "
        "find /var/lib/jaunt/recordings -perm /007 -print"])
    lines = data.out.splitlines()
    if len(lines) < 3 or lines[0] != "700 jauntd":
        problems.append("the data directory is {}".format(lines[0] if lines else "unreadable"))
    if len(lines) < 3 or lines[1] != "600":
        problems.append("jaunt.db is {}".format(lines[1] if len(lines) > 1 else "unreadable"))
    if len(lines) < 3 or lines[2] != "750":
        problems.append("the recordings directory is {}".format(lines[2] if len(lines) > 2 else "unreadable"))
    for extra in lines[3:]:
        problems.append("{} is open beyond its documented mode".format(extra))
    for node in stand.nodes:
        state = stand.on_node(node, ["sh", "-c",
            "stat -c '%a %U' /var/lib/jaunt; find /var/lib/jaunt -type f \\( -name '*key*' -o -name 'state.json' \\) -perm /077 -print"])
        rows = state.out.splitlines()
        if not rows or rows[0] != "700 jaunt":
            problems.append("{}: the state directory is {}".format(node, rows[0] if rows else "unreadable"))
        for extra in rows[1:]:
            problems.append("{}: {} is open to group or others".format(node, extra))
    return problems


def finish(stand, report):
    secrets = list(stand.secrets) + (profile_secrets(stand) if stand.admin is not None else [])
    with report.step("hygiene: every agent runs as an unprivileged user") as step:
        for node in stand.nodes:
            shown = stand.on_node(node, ["ps", "-o", "user=,pid=,args=", "-C", "jaunt-agent"])
            users = [line.split()[0] for line in shown.out.splitlines() if line.strip()]
            step.expect(users and all(user != "root" for user in users), "{}: ps shows {!r}".format(node, shown.out))

    with report.step("hygiene: state directories have the documented modes") as step:
        problems = mode_problems(stand)
        step.expect(not problems, "; ".join(problems))

    with report.step("hygiene: the agents stop cleanly on SIGTERM with exit status 0") as step:
        for node in stand.nodes:
            status = stand.agent_stop(node)
            step.expect(status == "0", "the agent on {} exited with {}".format(node, status))

    logs = stand.collect_logs()

    with report.step("hygiene: every container stops with exit status 0") as step:
        for role in [role for role in STOP_ORDER if not role.startswith("node-") or role in stand.nodes]:
            stopped = engine.engine("stop", "-t", "30", container(role), timeout=90)
            code = engine.engine("inspect", "-f", "{{.State.ExitCode}}", container(role)).out.strip()
            step.expect(stopped.ok and code == "0", "{} exited with {} ({})".format(role, code, stopped.text()))

    logs.update(stand.collect_logs(include_files=False))

    with report.step("hygiene: no ERROR lines in the jauntd and agent logs") as step:
        allowed = allowed_errors()
        found = []
        for name in ["jauntd", "idp", "edge-web", "edge-idp"] + ["{}-agent".format(node) for node in stand.nodes]:
            for line in error_lines(logs.get(name, ""), allowed):
                found.append("{}: {}".format(name, line))
        step.expect(not found, "\n".join(found[:10]))

    with report.step("hygiene: no private keys, tokens or secrets in any container log") as step:
        hits = []
        for name, text in logs.items():
            for pattern in SECRET_PATTERNS:
                if pattern.search(text):
                    hits.append("{} matches {}".format(name, pattern.pattern[:40]))
            for value in secrets:
                if value and value in text:
                    hits.append("{} contains a known secret ({} characters)".format(name, len(value)))
        step.expect(not hits, "; ".join(hits))
