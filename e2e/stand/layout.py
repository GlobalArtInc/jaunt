import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
E2E = os.path.join(ROOT, "e2e")
OUT = os.path.join(ROOT, "target", "e2e")
BINARIES = os.path.join(ROOT, "target", "installer-linux", "release")
CONTAINER_DIR = os.path.join(E2E, "container")
FIXTURES = os.path.join(E2E, "fixtures")

PROJECT = os.environ.get("E2E_PROJECT", "jaunt-e2e")
if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", PROJECT):
    raise SystemExit("E2E_PROJECT must be lowercase letters, digits, '_', '.' or '-', got {!r}".format(PROJECT))

SUFFIX = "e2e.test"
NETWORK = PROJECT
PREFIX = PROJECT + "-"
DATA_VOLUME = PROJECT + "-data"
RUN_DIR = os.path.join(OUT, "run", PROJECT)
ALL_ROLES = ("client", "node-a", "node-b", "jauntd", "edge-web", "edge-idp", "idp")

WEB_HOST = "jaunt.{}".format(SUFFIX)
IDP_HOST = "idp.{}".format(SUFFIX)
AGENTS_HOST = "agents.{}".format(SUFFIX)
GATE_HOST = "gate.{}".format(SUFFIX)
WEB_ORIGIN = "https://{}".format(WEB_HOST)
GATE_PORT = 2222
AGENTS_PORT = 8444
CONTROL_PORT = 8443
CLIENT_FORWARD_PORT = 7002
CLI_SERVER = "http://127.0.0.1:{}".format(CLIENT_FORWARD_PORT)
CA_PEM = "/certs/e2e-test-only-ca.pem"

CLIENT_USERS = ("alice", "bob", "carol")
IDP_CLIENT_ID = "jaunt-e2e"

NODES = {
    "node-a": {"labels": "env=test"},
    "node-b": {"labels": "env=prod"},
}


def container(role):
    return PREFIX + role


def node_host(node):
    return "{}.{}".format(node, SUFFIX)
