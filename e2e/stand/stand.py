import json
import os
import re
import shutil
import time

from . import engine
from .cleanup import remove_everything
from .engine import Streaming, exec_detached, exec_in
from .layout import (
    AGENTS_HOST, AGENTS_PORT, ALL_ROLES, BINARIES, CA_PEM, CLI_SERVER, CLIENT_FORWARD_PORT, CLIENT_USERS,
    CONTAINER_DIR, CONTROL_PORT, DATA_VOLUME, FIXTURES, GATE_HOST, GATE_PORT, IDP_CLIENT_ID,
    IDP_HOST, NETWORK, NODES, OUT, PROJECT, RUN_DIR, SUFFIX, WEB_HOST, WEB_ORIGIN, container, node_host,
)
from .report import StepFailed

CLIENT_SECRET = "e2e-test-only-oidc-client-secret"
LOGIN_DEADLINE = 120
JAUNTD_BIN = "/usr/local/bin/jauntd"
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"Bearer [A-Za-z0-9._~+/=-]{16,}"),
]


def qualify(image):
    return image if "/" in image else "docker.io/library/{}".format(image)


def slug(image):
    return re.sub(r"[^a-z0-9]+", "-", image.lower()).strip("-")


def write_file(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(text)
    os.chmod(path, mode)


def jauntd_config(cert_ttl_secs):
    return "\n".join([
        "data_dir: /var/lib/jaunt",
        "listen: 0.0.0.0:{}".format(CONTROL_PORT),
        "agents_listen: 0.0.0.0:{}".format(AGENTS_PORT),
        "public_url: {}".format(WEB_ORIGIN),
        "ssh_suffix: {}".format(SUFFIX),
        "agent_endpoint: {}:{}".format(AGENTS_HOST, AGENTS_PORT),
        "gate_endpoint: {}:{}".format(GATE_HOST, GATE_PORT),
        "cert_ttl_secs: {}".format(cert_ttl_secs),
        "policy_dir: /etc/jaunt/policy",
        "policy_poll_secs: 1",
        "ssh_gate:",
        "  listen: 0.0.0.0:{}".format(GATE_PORT),
        "  hostnames: [{}]".format(GATE_HOST),
        "oidc:",
        "  issuer_url: https://{}".format(IDP_HOST),
        "  client_id: {}".format(IDP_CLIENT_ID),
        "  client_secret_file: /etc/jaunt/oidc-client-secret",
        "  extra_root_certificates_file: {}".format(CA_PEM),
        "recordings:",
        "  dir: /var/lib/jaunt/recordings",
        "",
    ])


class Stand:
    def __init__(self, base_image, transfer_mib=256, keep=False):
        self.base_image = qualify(base_image)
        self.label = base_image
        self.transfer_mib = transfer_mib
        self.keep = keep
        self.node_image = "{}:{}".format(PROJECT, slug(base_image))
        self.tool_image = "{}:debian-13".format(PROJECT)
        self.run_dir = RUN_DIR
        self.log_dir = os.path.join(OUT, "logs", slug(base_image))
        self.ca_pin = None
        self.admin = None
        self.secrets = [CLIENT_SECRET]
        self.cert_ttl_secs = 28800
        self.publish_ports = {}
        self.codes = {}
        self.node_ids = {}
        self.certs = {}
        self.cli_revocation = ""
        self.digest = None
        self.revocation = None

    def build_images(self):
        wanted = [(self.tool_image, qualify("debian:13"))]
        if self.node_image != self.tool_image:
            wanted.append((self.node_image, self.base_image))
        for image, base in wanted:
            result = engine.engine(
                "build", "--build-arg", "BASE={}".format(base), "-t", image,
                "-f", os.path.join(CONTAINER_DIR, "Containerfile"), CONTAINER_DIR, timeout=900,
            )
            if not result.ok:
                raise RuntimeError("building {} failed:\n{}".format(image, result.err[-2000:]))

    def clear_run_dir(self):
        if not os.path.isdir(self.run_dir):
            return
        shutil.rmtree(self.run_dir, ignore_errors=True)
        if not os.path.isdir(self.run_dir):
            return
        cleared = engine.engine(
            "run", "--rm", "--security-opt", "label=disable", "-v", "{}:/run-dir".format(self.run_dir),
            self.tool_image, "sh", "-c", "chmod -R u+rwX /run-dir; find /run-dir -mindepth 1 -delete",
        )
        if not cleared.ok:
            raise RuntimeError("cannot clear {}: {}".format(self.run_dir, cleared.text()))
        shutil.rmtree(self.run_dir)

    def mounts(self, *pairs):
        argv = []
        for source, target in pairs:
            argv += ["-v", "{}:{}".format(source, target)]
        return argv

    def create(self, role, image, aliases, mounts, command, user=None, env=None, publish=None):
        argv = ["run", "-d", "--security-opt", "label=disable", "--name", container(role), "--network", NETWORK,
                "--hostname", role]
        for alias in aliases:
            argv += ["--network-alias", alias]
        if user:
            argv += ["--user", user]
        if publish:
            argv += ["-p", publish]
        for key, value in (env or {}).items():
            argv += ["-e", "{}={}".format(key, value)]
        argv += self.mounts(*mounts) + [image] + command
        result = engine.engine(*argv)
        if not result.ok:
            raise RuntimeError("starting {} failed:\n{}".format(role, result.err[-2000:]))

    def binary(self, name):
        path = os.path.join(BINARIES, name)
        if not os.path.exists(path):
            raise RuntimeError("{} is missing: build the Linux binaries first".format(path))
        return path

    def up(self):
        remove_everything()
        self.clear_run_dir()
        os.makedirs(self.run_dir, exist_ok=True)
        certs = os.path.join(self.run_dir, "certs")
        os.makedirs(certs)
        etc = os.path.join(self.run_dir, "jauntd-etc")
        idp = os.path.join(self.run_dir, "idp")
        container_dir = CONTAINER_DIR
        for check in ("jauntd", "jaunt", "jaunt-agent", "jaunt-fake-idp"):
            self.binary(check)

        made = engine.engine(
            "run", "--rm", "--security-opt", "label=disable", *self.mounts((certs, "/certs"), (container_dir, "/e2e:ro")),
            self.tool_image, "sh", "/e2e/mkcerts.sh", "idp", "jaunt",
        )
        if not made.ok:
            raise RuntimeError("creating the test certificates failed:\n" + made.err[-2000:])

        write_file(os.path.join(etc, "jauntd.yaml"), jauntd_config(self.cert_ttl_secs))
        write_file(os.path.join(etc, "oidc-client-secret"), CLIENT_SECRET + "\n")
        shutil.copytree(os.path.join(FIXTURES, "policy"), os.path.join(etc, "policy"))
        write_file(os.path.join(idp, "client-secret"), CLIENT_SECRET + "\n")
        shutil.copy(os.path.join(FIXTURES, "idp-users.json"), os.path.join(idp, "users.json"))
        for owned in (etc, idp):
            for path, _, names in os.walk(owned):
                for name in names:
                    os.chmod(os.path.join(path, name), 0o644)
                os.chmod(path, 0o755)

        for step in (
            ["network", "create", NETWORK],
            ["volume", "create", DATA_VOLUME],
        ):
            engine.engine(*step)
        prepared = engine.engine(
            "run", "--rm", "--security-opt", "label=disable", "-v", "{}:/data".format(DATA_VOLUME), self.tool_image,
            "sh", "-c", "chown 65532:65532 /data && chmod 0700 /data",
        )
        if not prepared.ok:
            raise RuntimeError("preparing the data volume failed:\n" + prepared.err[-1000:])
        initialised = engine.engine(
            "run", "--rm", "--security-opt", "label=disable", "--user", "65532:65532",
            *self.mounts(
                (DATA_VOLUME, "/var/lib/jaunt"), (etc, "/etc/jaunt:ro"),
                (self.binary("jauntd"), "{}:ro".format(JAUNTD_BIN)),
            ),
            self.tool_image, JAUNTD_BIN, "ca", "init", "--generate-identity", "--config", "/etc/jaunt/jauntd.yaml",
        )
        if not initialised.ok:
            raise RuntimeError("jauntd ca init failed:\n" + initialised.err[-2000:])
        match = re.search(r"^internal-ca (sha256:[0-9a-f]{64})$", initialised.out, re.M)
        if not match:
            raise RuntimeError("jauntd ca init printed no internal CA pin")
        self.ca_pin = match.group(1)
        self.etc = etc

        e2e = (container_dir, "/e2e:ro")
        certs_ro = (certs, "/certs:ro")
        self.create("idp", self.tool_image, ["idp"], [
            (self.binary("jaunt-fake-idp"), "/usr/local/bin/jaunt-fake-idp:ro"), (idp, "/etc/idp:ro"),
        ], [
            "/usr/local/bin/jaunt-fake-idp", "--listen", "0.0.0.0:8080", "--issuer", "https://{}".format(IDP_HOST),
            "--client-id", IDP_CLIENT_ID, "--client-secret-file", "/etc/idp/client-secret",
            "--redirect-uri", "{}/v1/login/callback".format(WEB_ORIGIN), "--users", "/etc/idp/users.json",
        ])
        self.create("edge-web", self.tool_image, [WEB_HOST], [certs_ro, e2e], ["/e2e/edge.sh", "jaunt", "jauntd:8443"],
                    publish=self.publish_ports.get("edge-web"))
        self.create("edge-idp", self.tool_image, [IDP_HOST], [certs_ro, e2e], ["/e2e/edge.sh", "idp", "idp:8080"],
                    publish=self.publish_ports.get("edge-idp"))
        self.create("jauntd", self.tool_image, ["jauntd", AGENTS_HOST, GATE_HOST], [
            (self.binary("jauntd"), "{}:ro".format(JAUNTD_BIN)), (DATA_VOLUME, "/var/lib/jaunt"),
            (etc, "/etc/jaunt:ro"), certs_ro,
        ], [JAUNTD_BIN, "run", "--config", "/etc/jaunt/jauntd.yaml"], user="65532:65532", env={"RUST_LOG": "info"})
        self.create("client", self.tool_image, ["client"], [
            (self.binary("jaunt"), "/usr/local/bin/jaunt:ro"), certs_ro, e2e,
            (os.path.join(CONTAINER_DIR, "xdg-open"), "/usr/local/bin/xdg-open:ro"),
        ], ["/e2e/idle.sh"])
        for node, spec in NODES.items():
            self.create(node, self.node_image, [node], [
                (self.binary("jaunt-agent"), "/usr/local/bin/jaunt-agent:ro"), e2e,
            ], ["/e2e/node.sh"])
        self.prepare_client()
        self.wait_until("jauntd answers health checks", self.control_healthy, 60)
        for node in NODES:
            self.wait_until("{} is ready".format(node), lambda node=node: self.node_ready(node), 90)

    def prepare_client(self):
        exec_detached(container("client"), [
            "socat", "TCP-LISTEN:{},bind=127.0.0.1,fork,reuseaddr".format(CLIENT_FORWARD_PORT),
            "TCP:jauntd:{}".format(CONTROL_PORT),
        ])
        for user in CLIENT_USERS:
            exec_detached(container("client"), ["ssh-agent", "-D", "-a", self.agent_socket(user)], user=user)
        for user in CLIENT_USERS:
            self.wait_until("the ssh-agent of {}".format(user), lambda user=user: self.agent_up(user), 20)

    def agent_socket(self, user):
        return "/tmp/ssh-agent-{}.sock".format(user)

    def agent_up(self, user):
        return exec_in(container("client"), ["test", "-S", self.agent_socket(user)]).ok

    def control_healthy(self):
        return exec_in(container("client"), ["curl", "-sf", "http://127.0.0.1:{}/healthz".format(CLIENT_FORWARD_PORT)]).ok

    def node_ready(self, node):
        return exec_in(container(node), ["test", "-f", "/run/e2e/ready"]).ok

    def wait_until(self, what, check, timeout, interval=0.5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(interval)
        raise StepFailed("timed out after {} s waiting for: {}".format(timeout, what))

    def user_env(self, user):
        return {"HOME": "/home/{}".format(user), "SSH_AUTH_SOCK": self.agent_socket(user)}

    def on_client(self, argv, user=None, tty=False, timeout=120, extra_env=None):
        env = self.user_env(user) if user else {}
        env.update(extra_env or {})
        return exec_in(container("client"), argv, user=user, env=env, tty=tty, timeout=timeout)

    def on_node(self, node, argv, user=None, timeout=120):
        return exec_in(container(node), argv, user=user, timeout=timeout)

    def on_server(self, argv, timeout=60):
        return exec_in(container("jauntd"), argv, timeout=timeout)

    def jauntd(self, *args, timeout=60):
        return self.on_server([JAUNTD_BIN, "--config", "/etc/jaunt/jauntd.yaml", *args], timeout=timeout)

    def login(self, user, hint=None):
        stream = Streaming(engine.exec_argv(
            container("client"),
            ["jaunt", "login", "--server", CLI_SERVER, "--no-browser", "--accept-ssh-config", "--timeout", str(LOGIN_DEADLINE)],
            user=user, env=self.user_env(user),
        ))
        url = stream.wait_for_line("https://", 30)
        if url is None:
            stream.finish(5)
            raise StepFailed("jaunt login printed no sign-in address:\n" + stream.output())
        browser = self.browse(user, "{}&login_hint={}".format(url, hint or user))
        status = stream.finish(LOGIN_DEADLINE)
        return status, stream.output(), browser

    def browse(self, user, url):
        jar = "/home/{}/.idp-cookies".format(user)
        return self.on_client([
            "curl", "-sS", "-L", "--max-redirs", "10", "--max-time", "30", "--cacert", CA_PEM,
            "-b", jar, "-c", jar, "-o", "/dev/null", "-w", "%{http_code} %{url_effective}", url,
        ], user=user, timeout=60)

    def logout(self, user):
        return self.on_client(["jaunt", "logout"], user=user)

    def certificate_info(self, user):
        shown = self.on_client(["ssh-keygen", "-L", "-f", "/home/{}/.jaunt/default/id_ed25519-cert.pub".format(user)], user=user)
        principal = re.search(r"Principals:\s*\n\s+(\S+)", shown.out)
        serial = re.search(r"Serial:\s*(\d+)", shown.out)
        key_id = re.search(r'Key ID:\s*"([^"]+)"', shown.out)
        valid = re.search(r"Valid:\s*from (\S+) to (\S+)", shown.out)
        return {
            "principal": principal.group(1) if principal else None,
            "serial": int(serial.group(1)) if serial else None,
            "key_id": key_id.group(1) if key_id else None,
            "valid": valid.groups() if valid else None,
            "raw": shown.text(),
        }

    def ssh_argv(self, node, command=None, login="deploy", options=(), extra=()):
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", *options, *extra,
                "{}@{}".format(login, node_host(node))]
        if command is not None:
            argv.append(command)
        return argv

    def ssh(self, user, node, command=None, timeout=60, tty=False, options=(), extra=()):
        return self.on_client(self.ssh_argv(node, command, options=options, extra=extra), user=user, tty=tty, timeout=timeout)

    def ssh_stream(self, user, node, command=None, options=(), extra=()):
        return Streaming(engine.exec_argv(
            container("client"), self.ssh_argv(node, command, options=options, extra=extra),
            user=user, env=self.user_env(user),
        ))

    def accepted_logins(self, node):
        counted = self.on_node(node, ["sh", "-c", "grep -c 'Accepted publickey for deploy ' /var/log/sshd.log || true"])
        return int(counted.out.strip() or 0)

    def failed_logins(self, node):
        counted = self.on_node(node, ["sh", "-c", "grep -cE 'Failed |Invalid user|authentication failure' /var/log/sshd.log || true"])
        return int(counted.out.strip() or 0)

    def curl_json(self, jar, method, path, body=None, token=None, origin=True):
        argv = ["curl", "-sS", "--max-time", "30", "--cacert", CA_PEM, "-b", jar, "-X", method,
                "-w", "\n%{http_code}", "{}{}".format(WEB_ORIGIN, path)]
        if origin:
            argv[1:1] = ["-H", "Origin: {}".format(WEB_ORIGIN)]
        if token:
            argv[1:1] = ["-H", "x-jaunt-csrf: {}".format(token)]
        if body is not None:
            argv[1:1] = ["-H", "content-type: application/json", "-d", json.dumps(body)]
        shown = self.on_client(argv, timeout=60)
        text, _, code = shown.out.rpartition("\n")
        try:
            parsed = json.loads(text) if text.strip() else None
        except ValueError:
            parsed = None
        return int(code or 0), parsed, text

    def admin_login(self, hint="admin"):
        jar = "/tmp/admin-cookies"
        self.on_client(["rm", "-f", jar])
        first = self.on_client([
            "curl", "-sS", "-D", "-", "-o", "/dev/null", "--max-time", "30", "--cacert", CA_PEM, "-c", jar,
            "{}/v1/web/login".format(WEB_ORIGIN),
        ])
        match = re.search(r"^location:\s*(\S+)", first.out, re.I | re.M)
        if not match:
            raise StepFailed("the web login did not redirect to the identity provider:\n" + first.text())
        second = self.on_client([
            "curl", "-sS", "-L", "--max-redirs", "10", "--max-time", "30", "--cacert", CA_PEM, "-b", jar, "-c", jar,
            "-o", "/dev/null", "-w", "%{http_code}", "{}&login_hint={}".format(match.group(1), hint),
        ])
        if second.out.strip() != "200":
            raise StepFailed("the web login did not end on a page: " + second.text())
        status, session, text = self.curl_json(jar, "GET", "/v1/web/session")
        if status != 200 or not session:
            raise StepFailed("no web session after sign-in: {} {}".format(status, text[:200]))
        self.admin = {"jar": jar, "csrf": session["csrf_token"], "user_id": session["user_id"],
                      "permissions": session["permissions"]}
        self.secrets.append(session["csrf_token"])
        return session

    def api(self, method, path, body=None):
        if not self.admin:
            raise StepFailed("no admin web session")
        status, parsed, text = self.curl_json(
            self.admin["jar"], method, path, body=body,
            token=self.admin["csrf"] if method != "GET" else None,
        )
        return status, parsed

    def audit_events(self, **filters):
        events = []
        cursor = None
        for _ in range(50):
            query = dict(filters, limit="200")
            if cursor:
                query["cursor"] = cursor
            path = "/v1/admin/audit?" + "&".join("{}={}".format(k, v) for k, v in sorted(query.items()))
            status, page = self.api("GET", path)
            if status != 200 or page is None:
                raise StepFailed("the audit query failed: {} {}".format(status, page))
            events.extend(page["events"])
            cursor = page.get("next_cursor")
            if not cursor:
                break
        return sorted(events, key=lambda event: (event["time"], event.get("id", "")))

    def marker(self):
        from .audit import last_marker
        return last_marker(self.audit_events())

    def restart_jauntd(self, cert_ttl_secs):
        self.cert_ttl_secs = cert_ttl_secs
        write_file(os.path.join(self.etc, "jauntd.yaml"), jauntd_config(cert_ttl_secs))
        restarted = engine.engine("restart", "-t", "30", container("jauntd"), timeout=90)
        if not restarted.ok:
            raise StepFailed("restarting jauntd failed: " + restarted.text())
        self.wait_until("jauntd answers health checks", self.control_healthy, 60)

    def agent_reconnected(self, node):
        return self.ssh("alice", node, "true", timeout=30).ok

    def tail_of(self, role, lines=40):
        return engine.engine("logs", "--tail", str(lines), container(role)).text()

    def collect_logs(self, include_files=True):
        os.makedirs(self.log_dir, exist_ok=True)
        gathered = {}
        for role in ALL_ROLES:
            logged = engine.engine("logs", container(role))
            text = logged.out + logged.err
            write_file(os.path.join(self.log_dir, "{}.log".format(role)), text)
            gathered[role] = text
        for node in NODES if include_files else ():
            for name, path in (("sshd", "/var/log/sshd.log"), ("agent", "/tmp/agent.log"), ("enroll", "/tmp/enroll.log"),
                               ("install", "/run/e2e/install.log")):
                fetched = self.on_node(node, ["cat", path])
                write_file(os.path.join(self.log_dir, "{}-{}.log".format(node, name)), fetched.out)
                gathered["{}-{}".format(node, name)] = fetched.out
        return gathered

    def enrol_start(self, node):
        spec = NODES[node]
        started = exec_detached(container(node), ["/e2e/agentctl.sh", "enroll", node, spec["labels"], self.ca_pin])
        if not started.ok:
            raise StepFailed("cannot start the enrolment on {}: {}".format(node, started.text()))
        holder = {}

        def has_code():
            shown = self.on_node(node, ["cat", "/tmp/enroll.log"]).out
            found = re.search(r"^code:\s+(\S+)$", shown, re.M)
            if found:
                holder["code"] = found.group(1)
            return bool(found)

        self.wait_until("{} prints an enrolment code".format(node), has_code, 60)
        return holder["code"]

    def enrol_wait(self, node):
        holder = {}

        def enrolled():
            shown = self.on_node(node, ["cat", "/tmp/enroll.log"]).out
            found = re.search(r"enrolled as node (\S+) \(", shown)
            if found:
                holder["id"] = found.group(1)
            return bool(found)

        self.wait_until("{} finishes enrolling".format(node), enrolled, 60)
        return holder["id"]

    def agent_start(self, node):
        started = self.on_node(node, ["/e2e/agentctl.sh", "start"])
        if not started.ok:
            raise StepFailed("cannot start the agent on {}: {}".format(node, started.text()))

        def connected():
            return "the tunnel is connected" in self.on_node(node, ["cat", "/tmp/agent.log"]).out

        self.wait_until("the agent on {} connects its tunnel".format(node), connected, 60)

    def agent_stop(self, node):
        stopped = self.on_node(node, ["/e2e/agentctl.sh", "stop"], timeout=60)
        return stopped.out.strip()

    def down(self):
        if self.keep:
            return
        remove_everything()
