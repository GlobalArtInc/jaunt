import os
import subprocess
import time

from scenarios import enrol, logins
from scenarios.recording import record_shell
from stand import engine, recordings
from stand.layout import OUT, ROOT, container
from stand.report import Report
from stand.stand import Stand

WEB_PORT = 18443
IDP_PORT = 18444
WEB_TESTS = os.path.join(ROOT, "web-tests")
SCREENSHOTS = os.path.join(OUT, "screenshots")
PENDING = ("web-pending-380", "web-pending-1440")


def start_pending(stand, name):
    state = "/tmp/state-{}".format(name)
    prepared = stand.on_node("node-a", ["sh", "-c", "mkdir -p {0} && chown jaunt {0}".format(state)])
    if not prepared.ok:
        raise RuntimeError(prepared.text())
    log = "/tmp/enroll-{}.log".format(name)
    engine.exec_detached(container("node-a"), [
        "setpriv", "--reuid=jaunt", "--regid=jaunt", "--init-groups", "--", "sh", "-c",
        "exec /usr/local/bin/jaunt-agent enroll --server http://127.0.0.1:7001 --name {} --labels env=web "
        "--ca-pin {} --state-dir {} >{} 2>&1".format(name, stand.ca_pin, state, log),
    ])
    holder = {}

    def has_code():
        shown = stand.on_node("node-a", ["cat", log]).out
        for line in shown.splitlines():
            if line.startswith("code:"):
                holder["code"] = line.split()[1]
                return True
        return False

    stand.wait_until("the pending enrolment {}".format(name), has_code, 60)
    return holder["code"]


def run_node(step, script, stand, extra):
    step.expect(os.path.isdir(os.path.join(WEB_TESTS, "node_modules", "playwright")),
                "run `npm ci` in web-tests first (and `npx playwright install chromium`)")
    env = dict(os.environ)
    env.update({"E2E_WEB_PORT": str(WEB_PORT), "E2E_IDP_PORT": str(IDP_PORT), "E2E_SCREENSHOTS": SCREENSHOTS + os.sep})
    env.update(extra)
    started = time.monotonic()
    done = subprocess.run(["node", os.path.join(WEB_TESTS, "e2e", script)], env=env, cwd=WEB_TESTS,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=600)
    step.note("{} took {:.1f} s".format(script, time.monotonic() - started))
    for line in done.stdout.strip().splitlines()[-12:]:
        step.note(line)
    step.expect(done.returncode == 0, "{} exited {}".format(script, done.returncode))


def run(args):
    stand = Stand("debian:13", keep=args.keep)
    stand.publish_ports = {"edge-web": "127.0.0.1:{}:443".format(WEB_PORT), "edge-idp": "127.0.0.1:{}:443".format(IDP_PORT)}
    report = Report("web")
    session = None
    try:
        stand.build_images()
        with report.step("the stand starts with the TLS edges published on 127.0.0.1"):
            stand.up()
        if report.failed():
            return report
        enrol.run(stand, report)
        logins.run(stand, report)
        if report.failed():
            return report
        with report.step("a live session of alice and two pending enrolments are prepared") as step:
            session = stand.ssh_stream("alice", "node-a", "sleep 600")
            stand.wait_until("alice's session", lambda: stand.accepted_logins("node-a") >= 1, 30)
            codes = [start_pending(stand, name) for name in PENDING]
            step.note("pending enrolment codes are held back from this output")
        with report.step("a recorded session is played in the real console at 380 and 1440 px, screenshots in target/e2e/screenshots") as step:
            typed = recordings.unique_token("web-recorded")
            marker, ran, status, output = record_shell(stand, "alice", "node-a", ["echo {}".format(typed), "exit"], typed)
            step.expect(ran and status == 0, "the typed session failed: {}".format(output[-300:]))
            recorded = recordings.last_session(stand, marker, "alice", "node-a")
            step.expect(recordings.wait_recording(stand, recorded, ("complete",))["recording"] == "complete", "not recorded")
            run_node(step, "recording.mjs", stand, {"E2E_RECORDED_SESSION": recorded, "E2E_TYPED_TEXT": typed})
        with report.step("Chromium drives the real console at 380 and 1440 px, screenshots in target/e2e/screenshots") as step:
            run_node(step, "real.mjs", stand, {
                "E2E_PENDING": ",".join("{}:{}".format(code, name) for code, name in zip(codes, PENDING)),
                "E2E_REVOKE_USERS": ",".join([stand.certs["alice"]["principal"], stand.certs["bob"]["principal"]]),
            })
        with report.step("the approved enrolments reached the node list") as step:
            status, listed = stand.api("GET", "/v1/admin/nodes")
            names = [node["name"] for node in listed["nodes"]] if status == 200 else []
            step.expect(all(name in names for name in PENDING), "nodes: {}".format(names))
    finally:
        if session is not None:
            stand.on_client(["pkill", "-u", "alice", "-f", "sleep 600"], user="alice")
        stand.collect_logs()
        if not args.keep:
            with report.step("the stand is removed"):
                stand.down()
    return report
