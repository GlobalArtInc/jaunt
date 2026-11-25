import hashlib
import os
import time

from stand.layout import BINARIES, OLD_AGENT_DIR

from .rotation_kit import Kit, keys_of


def digest_of(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def attach(stand):
    stand.kit = Kit(stand)
    return stand.kit


def run(stand, report):
    kit = attach(stand)
    started = time.monotonic()
    kit.marker = None

    with report.step("node-b can add and remove the firewall rules the stale-agent step needs") as step:
        problems = kit.probe_firewall("node-b")
        step.expect(not problems, "; ".join(problems))

    with report.step("the admin signs in to the web console through the fake IdP") as step:
        session = stand.admin_login()
        kit.marker = stand.marker()
        step.expect("audit.read" in session["permissions"], "no audit.read: {}".format(session["permissions"]))

    for node in ("node-a", "node-b", "node-c"):
        with report.step("{} enrols and is approved".format(node)) as step:
            code = stand.enrol_start(node)
            done = stand.jauntd("node", "approve", code, "--yes")
            step.expect(done.ok, done.text())
            stand.node_ids[node] = stand.enrol_wait(node)

    kit.first_nodes = dict(stand.node_ids)

    with report.step("the agents of node-a (current build) and node-c (old protocol) connect; node-b stays stopped") as step:
        stand.agent_start("node-a")
        stand.agent_start("node-c")
        version = stand.on_node("node-c", ["jaunt-agent", "--version"])
        step.note("node-c agent: {}".format(version.out.strip()))
        step.expect(stand.on_node("node-b", ["pgrep", "-c", "jaunt-agent"]).out.strip() in ("", "0"), "an agent runs on node-b")

    with report.step("node-c runs the old agent binary and node-a the current one") as step:
        old = digest_of(os.path.join(OLD_AGENT_DIR, "jaunt-agent"))
        current = digest_of(os.path.join(BINARIES, "jaunt-agent"))
        step.expect(old != current, "the cached old agent is the current agent")
        for node, expected in (("node-c", old), ("node-a", current)):
            shown = stand.on_node(node, ["sha256sum", "/usr/local/bin/jaunt-agent"])
            step.expect(shown.ok and shown.out.split()[0] == expected, "{} runs {}".format(node, shown.text()[:80]))

    with report.step("alice and bob sign in and reach node-a and node-c") as step:
        for user in ("alice", "bob"):
            kit.sign_in(user)
        for node in ("node-a", "node-c"):
            step.expect(kit.connects("alice", node), "alice cannot reach {}".format(node))
            step.expect(kit.connects("bob", node), "bob cannot reach {}".format(node))

    with report.step("S1: an interactive session on node-a counts once a second") as step:
        kit.open_session("alice", "node-a", "S1")
        kit.check_session(step, "its start")

    with report.step("the starting state: user keys [A], host keys [A], the API equals the CLI") as step:
        cli, api = kit.status_pair()
        for kind in ("user", "host"):
            states = [key["state"] for key in cli[kind]["keys"]]
            step.expect(states == ["active"], "{} keys {}".format(kind, cli[kind]["keys"]))
            kit.fingerprints[kind + "-a"] = keys_of(cli[kind])["active"]
            kit.record_trust_id(kind, cli[kind]["trust_id"])
        step.expect(cli["user"]["nodes"]["offline_names"] == ["node-b"], "offline: {}".format(cli["user"]["nodes"]))
        step.expect(cli["user"]["nodes"]["current"] == 2, "current: {}".format(cli["user"]["nodes"]))
        shown = stand.jauntd("ca", "status")
        step.expect(shown.ok and "user" in shown.out and "host" in shown.out, shown.text())

    kit.phase("setup", started)
