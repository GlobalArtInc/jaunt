import base64
import hashlib
import json
import re
import time

from stand.layout import GATE_HOST, node_host
from stand.report import StepFailed

PROFILE = "/home/{}/.jaunt/default"
HOST_CERTIFICATE = re.compile(r"Server host certificate: \S+ (SHA256:\S+), serial \d+ ID .* CA \S+ (SHA256:\S+)")
SIGNING_CA = re.compile(r"Signing CA: \S+ (SHA256:\S+)")
SESSION_GAP_SECS = 20
SESSION_MIN_SECS = 60
SESSION_EXPIRY_SLACK_SECS = 6
AGENTS_PORT = "8444"
API_PROTOCOL = "jaunt-agent/1"
API_RULE = ["OUTPUT", "-p", "tcp", "--dport", AGENTS_PORT, "-m", "string", "--string", API_PROTOCOL, "--algo", "bm",
            "-j", "REJECT", "--reject-with", "tcp-reset"]
RESET_ALL_RULE = ["OUTPUT", "-p", "tcp", "--dport", AGENTS_PORT, "-j", "REJECT", "--reject-with", "tcp-reset"]


def fingerprint_text(hex_digest):
    return "SHA256:" + base64.b64encode(bytes.fromhex(hex_digest)).decode().rstrip("=")


def keys_of(slot):
    return {key["state"]: key["fingerprint"] for key in slot["keys"] if key["state"] not in ("retired", "stray")}


def retired_of(slot):
    return [key["fingerprint"] for key in slot["keys"] if key["state"] == "retired"]


def step_of(slot, name):
    for entry in slot["steps"]:
        if entry["step"] == name:
            return entry
    return None


class Kit:
    def __init__(self, stand):
        self.stand = stand
        self.waits = []
        self.phases = []
        self.sessions = []
        self.session_checks = 0
        self.session_serial = 0
        self.fingerprints = {}
        self.trust_ids = {"user": [], "host": []}
        self.frozen = {}
        self.first_nodes = {}
        self.blocked = set()

    def phase(self, name, started):
        self.phases.append((name, time.monotonic() - started))

    def wait(self, name, check, deadline, interval=1.0):
        started = time.monotonic()
        end = started + deadline
        last = None
        while True:
            last = check()
            if last:
                took = time.monotonic() - started
                self.waits.append((name, took, deadline))
                return took, last
            if time.monotonic() >= end:
                self.waits.append((name, time.monotonic() - started, deadline))
                raise StepFailed("timed out after {} s waiting for: {}".format(deadline, name))
            time.sleep(interval)

    def status(self):
        shown = self.stand.jauntd("ca", "status", "--json")
        if not shown.ok:
            raise StepFailed("jauntd ca status --json exited {}: {}".format(shown.status, shown.text()))
        return json.loads(shown.out)

    def api_status(self):
        code, parsed = self.stand.api("GET", "/v1/admin/ca")
        if code != 200 or parsed is None:
            raise StepFailed("GET /v1/admin/ca answered {} {}".format(code, parsed))
        return parsed

    def status_pair(self):
        for _ in range(4):
            cli = self.status()
            api = self.api_status()
            if api == cli:
                return cli, api
            time.sleep(1)
        raise StepFailed("GET /v1/admin/ca differs from jauntd ca status --json:\ncli {}\napi {}".format(cli, api))

    def change(self, kind, step, force=False):
        argv = ["ca", step, kind]
        if force:
            argv.append("--force")
        return self.stand.jauntd(*argv, timeout=90)

    def record_trust_id(self, kind, trust_id):
        if trust_id not in self.trust_ids[kind]:
            self.trust_ids[kind].append(trust_id)

    def profile_file(self, user, name):
        return "{}/{}".format(PROFILE.format(user), name)

    def certificate_text(self, user, path=None):
        shown = self.stand.on_client(["ssh-keygen", "-L", "-f", path or self.profile_file(user, "id_ed25519-cert.pub")], user=user)
        return shown.out

    def signer_of(self, user, path=None):
        found = SIGNING_CA.search(self.certificate_text(user, path))
        return found.group(1) if found else None

    def seconds_left(self, user):
        info = self.stand.certificate_info(user)
        if not info["valid"]:
            return 0
        until = self.stand.on_client(
            ["sh", "-c", "TZ=UTC date -d \"{}\" +%s".format(info["valid"][1])], user=user).out.strip()
        now = self.stand.on_client(["date", "-u", "+%s"]).out.strip()
        return int(until or 0) - int(now or 0)

    def sign_in(self, user):
        self.stand.logout(user)
        status, output, browser = self.stand.login(user)
        if status != 0:
            raise StepFailed("jaunt login of {} exited {}:\n{}\nbrowser: {}".format(user, status, output, browser.text()))

    def fresh(self, user, seconds=40):
        if self.seconds_left(user) < seconds:
            self.sign_in(user)

    def known_host_keys(self, user):
        text = self.stand.on_client(["cat", self.profile_file(user, "known_hosts")], user=user).out
        keys = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "@cert-authority":
                digest = hashlib.sha256(base64.b64decode(parts[3])).digest()
                text = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
                if text not in keys:
                    keys.append(text)
        return keys

    def freeze(self, user, name):
        profile = PROFILE.format(user)
        known = "/tmp/frozen-{}.known_hosts".format(name)
        built = "/tmp/frozen-{}.config".format(name)
        script = (
            "cp {profile}/known_hosts {known} && "
            "sed -e '/^Match host /d' -e 's#UserKnownHostsFile .*#UserKnownHostsFile {known}#' {profile}/ssh_config > {built}"
        ).format(profile=profile, known=known, built=built)
        done = self.stand.on_client(["sh", "-c", script], user=user)
        if not done.ok:
            raise StepFailed("cannot freeze the client {}: {}".format(name, done.text()))
        self.frozen[name] = {"user": user, "config": built, "known_hosts": known}

    def frozen_ssh(self, name, target, command="true", options=(), timeout=60):
        entry = self.frozen[name]
        host = GATE_HOST if target == "gate" else node_host(target)
        login = "jaunt" if target == "gate" else "deploy"
        argv = ["ssh", "-F", entry["config"], "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", *options,
                "{}@{}".format(login, host)]
        argv.append(command)
        return self.stand.on_client(argv, user=entry["user"], timeout=timeout)

    def gate_accepts(self, name):
        shown = self.frozen_ssh(name, "gate", "true", options=("-v",))
        return "Authenticated to {}".format(GATE_HOST) in shown.err, shown

    def presented_ca(self, name, target):
        shown = self.frozen_ssh(name, target, "true", options=("-v",))
        found = HOST_CERTIFICATE.findall(shown.err)
        if not found:
            return None, shown
        return found[0 if target == "gate" else -1][1], shown

    def connects(self, user, node):
        return self.stand.ssh(user, node, "echo reached-$(hostname)").out.strip() == "reached-{}".format(node)

    def clock(self):
        return int(self.stand.on_client(["date", "-u", "+%s"]).out.strip())

    def open_session(self, user, node, label):
        self.fresh(user, SESSION_MIN_SECS)
        expires = self.clock() + self.seconds_left(user)
        self.session_serial += 1
        path = "/tmp/session-{}.count".format(self.session_serial)
        script = "i=0; while true; do i=$((i+1)); echo \"$i $(date +%s)\" >> {f}; sleep 1; done".format(f=path)
        stream = self.stand.ssh_stream(user, node, script, extra=("-tt",))
        self.sessions.append({"user": user, "node": node, "label": label, "path": path, "stream": stream,
                              "expires": expires})
        self.stand.wait_until("the session {} prints its first count".format(label),
                              lambda: len(self.counter_rows(self.sessions[-1])) >= 2, 30, interval=1)

    def counter_rows(self, session):
        shown = self.stand.on_node(session["node"], ["cat", session["path"]])
        return [line.split() for line in shown.out.splitlines() if line.strip()]

    def newest_session_left(self, node):
        live = [item for item in self.sessions if item["node"] == node and item["stream"].running()]
        if not live:
            return 0
        return max(item["expires"] for item in live) - self.clock()

    def keep_session(self, node, label, min_left=SESSION_MIN_SECS, user="alice"):
        if self.newest_session_left(node) < min_left:
            self.open_session(user, node, label)

    def judge(self, session):
        rows = self.counter_rows(session)
        if len(rows) < 2:
            return False, "the counter file has {} rows".format(len(rows))
        counters = [int(row[0]) for row in rows]
        stamps = [int(row[1]) for row in rows]
        if counters != list(range(1, len(counters) + 1)):
            return False, "the counter is not continuous"
        gap = max(b - a for a, b in zip(stamps, stamps[1:]))
        if gap > SESSION_GAP_SECS:
            return False, "the counter paused for {} s".format(gap)
        if session["stream"].running():
            lag = self.clock() - stamps[-1]
            if lag > SESSION_GAP_SECS:
                return False, "the last count is {} s old".format(lag)
            return True, "alive, {} counts".format(counters[-1])
        output = session["stream"].output()
        if "your certificate has expired" not in output:
            return False, "the session ended for another reason: {}".format(output[-300:])
        if stamps[-1] < session["expires"] - SESSION_EXPIRY_SLACK_SECS:
            return False, "the session stopped {} s before its certificate expired".format(session["expires"] - stamps[-1])
        return True, "ended by the expiry of its certificate"

    def check_session(self, step, phase):
        alive = 0
        ended = 0
        for session in self.sessions:
            ok, text = self.judge(session)
            step.expect(ok, "after {}: the session {} of {} on {}: {}".format(phase, session["label"], session["user"], session["node"], text))
            if session["stream"].running():
                alive += 1
            else:
                ended += 1
        step.expect(alive >= 1, "after {}: no session is alive".format(phase))
        self.session_checks += 1
        step.note("sessions after {}: {} alive, {} ended by the expiry of their certificates".format(phase, alive, ended))

    def tunnel_connections(self, node):
        text = self.stand.on_node(node, ["cat", "/tmp/agent.log"]).out
        return text.count("the tunnel is connected")

    def count_in_agent_log(self, node, text):
        return self.stand.on_node(node, ["cat", "/tmp/agent.log"]).out.count(text)

    def trust_loads(self, node):
        return self.stand.on_node(node, ["cat", "/tmp/agent.log"]).out.count("loaded the user CA trust set")

    def established_to_control(self, node):
        shown = self.stand.on_node(node, ["ss", "-Htn", "state", "established", "dport", "=", ":" + AGENTS_PORT])
        return len([line for line in shown.out.splitlines() if line.strip()])

    def agent_pid(self, node):
        return self.stand.on_node(node, ["cat", "/tmp/agent.pid"]).out.strip()

    def probe_firewall(self, node):
        stand = self.stand
        problems = []
        rules = (
            ("the string match on the agent API protocol", "xt_string", API_RULE),
            ("the connection reset", "ipt_REJECT or nft_reject", RESET_ALL_RULE),
        )
        for what, module, rule in rules:
            added = stand.on_node(node, ["iptables", "-A", *rule])
            if added.ok:
                removed = stand.on_node(node, ["iptables", "-D", *rule])
                if not removed.ok:
                    problems.append("{} could be added but not removed on {}: {}".format(what, node, removed.text()))
                continue
            text = added.text()
            if "Operation not permitted" in text or "Permission denied" in text:
                problems.append("{} on {}: the container lacks the NET_ADMIN capability ({})".format(what, node, text))
            elif "No chain/target/match" in text or "Extension" in text or "does not exist" in text or "Couldn't load" in text:
                problems.append("{} on {}: the kernel module {} is missing ({})".format(what, node, module, text))
            else:
                problems.append("{} on {}: iptables failed ({})".format(what, node, text))
        return problems

    def block_api(self, node):
        stand = self.stand
        added = stand.on_node(node, ["iptables", "-A", *API_RULE])
        if not added.ok:
            raise StepFailed("cannot add the API rule on {}: {}".format(node, added.text()))
        self.blocked.add(node)
        before = self.tunnel_connections(node)
        reset = stand.on_node(node, ["iptables", "-I", RESET_ALL_RULE[0], "1", *RESET_ALL_RULE[1:]])
        if not reset.ok:
            raise StepFailed("cannot add the reset rule on {}: {}".format(node, reset.text()))
        try:
            self.wait("{}: its connections to the control plane are reset".format(node),
                      lambda: self.established_to_control(node) == 0, 90, interval=1)
        finally:
            stand.on_node(node, ["iptables", "-D", RESET_ALL_RULE[0], "1"])
        self.wait("{}: the tunnel reconnects".format(node), lambda: self.tunnel_connections(node) > before, 60, interval=1)

    def unblock_api(self, node):
        removed = self.stand.on_node(node, ["iptables", "-D", *API_RULE])
        self.blocked.discard(node)
        if not removed.ok:
            raise StepFailed("cannot remove the API rule on {}: {}".format(node, removed.text()))

    def release_blocks(self):
        for node in sorted(self.blocked):
            self.unblock_api(node)
