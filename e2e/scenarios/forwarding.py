from stand.engine import exec_detached
from stand.layout import container

MARKER = "e2e-forward-marker"
SERVICE_PORT = 8088
NOT_PERMITTED = "jaunt: port forwarding is not allowed by your roles"
LOOPBACK_ONLY = "jaunt: forwarding is limited to localhost on the node"


def fetch(stand, user, port):
    shown = stand.on_client(["curl", "-sS", "--max-time", "5", "http://127.0.0.1:{}/marker".format(port)], user=user)
    return shown.out.strip() if shown.ok else None


def stop_forward(stand, user, stream):
    stand.on_client(["pkill", "-u", user, "-f", "ssh .*-N"], user=user)
    stream.finish(15)


def run(stand, report):
    with report.step("a loopback service is started on node-a") as step:
        prepared = stand.on_node("node-a", ["sh", "-c",
            "mkdir -p /home/deploy/www && echo {} >/home/deploy/www/marker && chown -R deploy /home/deploy/www".format(MARKER)])
        step.expect(prepared.ok, prepared.text())
        exec_detached(container("node-a"), ["python3", "-m", "http.server", "--bind", "127.0.0.1",
                                            "--directory", "/home/deploy/www", str(SERVICE_PORT)], user="deploy")
        stand.wait_until("the loopback service on node-a", lambda: stand.on_node(
            "node-a", ["sh", "-c", "ss -ltn | grep -q 127.0.0.1:{}".format(SERVICE_PORT)]).ok, 30)

    with report.step("-L: alice reaches the loopback service of node-a through the gate") as step:
        stream = stand.ssh_stream("alice", "node-a", options=("-o", "ExitOnForwardFailure=yes"),
                                  extra=("-N", "-L", "18088:localhost:{}".format(SERVICE_PORT)))
        try:
            stand.wait_until("the forward to answer", lambda: fetch(stand, "alice", 18088) == MARKER, 30)
        finally:
            stop_forward(stand, "alice", stream)

    with report.step("-L to another address is refused with the loopback-only text") as step:
        stream = stand.ssh_stream("alice", "node-a", extra=("-N", "-L", "18090:10.0.0.1:80"))
        try:
            stand.wait_until("the local end of the forward", lambda: stand.on_client(
                ["sh", "-c", "ss -ltn | grep -q 127.0.0.1:18090"]).ok, 30)
            fetch(stand, "alice", 18090)
            step.expect(stream.wait_for_text(LOOPBACK_ONLY, 20), stream.output())
        finally:
            stop_forward(stand, "alice", stream)

    with report.step("-L: bob has no port forwarding and is refused with the role text") as step:
        stream = stand.ssh_stream("bob", "node-a", extra=("-N", "-L", "18089:localhost:{}".format(SERVICE_PORT)))
        try:
            stand.wait_until("the local end of the forward", lambda: stand.on_client(
                ["sh", "-c", "ss -ltn | grep -q 127.0.0.1:18089"]).ok, 30)
            step.expect(fetch(stand, "bob", 18089) is None, "bob got the service through the forward")
            step.expect(stream.wait_for_text(NOT_PERMITTED, 20), stream.output())
        finally:
            stop_forward(stand, "bob", stream)

    with report.step("the loopback service on node-a is stopped") as step:
        stand.on_node("node-a", ["pkill", "-u", "deploy", "-f", "http.server"])
