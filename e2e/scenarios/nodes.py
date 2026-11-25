from stand import audit
from scenarios.revocation import LIVE_LIMIT_SECS, cut_session, start_session
from stand.texts import GENERIC_REFUSAL, refusal_texts


def run(stand, report):
    marker = stand.marker()
    node_id = stand.node_ids["node-b"]
    with report.step("removing node-b through the admin API ends its sessions within {} s".format(LIVE_LIMIT_SECS)) as step:
        stream = start_session(stand, "alice", "node-b")
        done = {}

        def cut():
            done["answer"] = stand.api("DELETE", "/v1/admin/nodes/{}".format(node_id), {"confirm_name": "node-b"})

        cut_session(stand, step, stream, cut)
        status, body = done["answer"]
        step.expect(status in (200, 204), "delete answered {} {}".format(status, body))

    with report.step("the agent of node-b is disconnected") as step:
        def gone():
            events = audit.after(stand.audit_events(), marker)
            return any(event["type"] == "agent.disconnected" and event.get("node") == node_id for event in events)

        stand.wait_until("agent.disconnected for node-b", gone, 20)

    with report.step("a new connection to node-b is refused with the generic text") as step:
        shown = stand.ssh("alice", "node-b", "true")
        step.expect(shown.status != 0 and refusal_texts(shown.err) == [GENERIC_REFUSAL], "stderr: {}".format(shown.err))

    with report.step("node-a is unaffected by the removal of node-b") as step:
        shown = stand.ssh("alice", "node-a", "id -un")
        step.expect(shown.ok and shown.out.strip() == "deploy", shown.text())

    with report.step("audit: node.removed and agent.disconnected for node-b") as step:
        events = audit.after(stand.audit_events(), marker)
        mine = [event for event in events if event.get("node") == node_id]
        step.expect(audit.appears_in_order(mine, ["node.removed", "agent.disconnected"]) or
                    audit.appears_in_order(mine, ["agent.disconnected", "node.removed"]), audit.kinds(mine))
        removed = audit.of_type(mine, "node.removed")
        step.expect(removed and removed[0]["actor"] == "web:" + stand.admin["user_id"], "node.removed: {}".format(removed))
        stand.on_node("node-b", ["pkill", "-u", "deploy", "-f", "sleep 600"])
