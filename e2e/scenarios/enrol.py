from stand import audit


def run(stand, report):
    with report.step("the admin signs in to the web console through the fake IdP") as step:
        session = stand.admin_login()
        step.expect("nodes.approve" in session["permissions"], "no nodes.approve: {}".format(session["permissions"]))
        step.expect("audit.read" in session["permissions"], "no audit.read: {}".format(session["permissions"]))

    with report.step("node-a asks to enrol and prints a code") as step:
        stand.codes["node-a"] = stand.enrol_start("node-a")
        step.expect(len(stand.codes["node-a"]) >= 8, "odd code {}".format(stand.codes["node-a"]))

    with report.step("jauntd node approve admits node-a") as step:
        done = stand.jauntd("node", "approve", stand.codes["node-a"], "--yes")
        step.expect(done.ok, done.text())
        stand.node_ids["node-a"] = stand.enrol_wait("node-a")

    with report.step("the agent on node-a connects its tunnel") as step:
        stand.agent_start("node-a")
        agent = stand.on_node("node-a", ["ps", "-o", "user=", "-C", "jaunt-agent"])
        step.expect(agent.out.split() == ["jaunt"], "the agent runs as: {}".format(agent.out.split()))

    with report.step("node-b enrols through the web admin API with a real web session") as step:
        code = stand.enrol_start("node-b")
        status, found = stand.api("POST", "/v1/admin/enrolments/lookup", {"code": code})
        step.expect(status == 200 and found, "lookup answered {} {}".format(status, found))
        enrolment = found["enrolment"]
        step.expect(enrolment["name"] == "node-b", "lookup shows {}".format(enrolment["name"]))
        step.expect(enrolment["labels"] == {"env": "prod"}, "labels {}".format(enrolment["labels"]))
        status, approved = stand.api(
            "POST", "/v1/admin/enrolments/{}/approve".format(enrolment["id"]), {"intent": found["intent"]},
        )
        step.expect(status in (200, 201) and approved, "approve answered {} {}".format(status, approved))
        stand.node_ids["node-b"] = approved["node"]["id"]
        enrolled = stand.enrol_wait("node-b")
        step.expect(enrolled == stand.node_ids["node-b"], "the agent got node {} not {}".format(enrolled, stand.node_ids["node-b"]))

    with report.step("the agent on node-b connects its tunnel"):
        stand.agent_start("node-b")

    with report.step("the admin API lists both nodes with their labels") as step:
        status, listed = stand.api("GET", "/v1/admin/nodes")
        step.expect(status == 200 and listed, "list answered {}".format(status))
        step.note(str(listed)[:300])

    with report.step("audit: node.enroll.requested, approved, delivered, agent.connected for each node") as step:
        events = stand.audit_events()
        for node in ("node-a", "node-b"):
            node_id = stand.node_ids[node]
            mine = [event for event in events if event.get("node") == node_id or event["fields"].get("name") == node]
            step.expect(
                audit.appears_in_order(mine, ["node.enroll.approved", "node.enroll.delivered", "agent.connected"]),
                "{}: {}".format(node, audit.kinds(mine)),
            )
        requested = audit.of_type(events, "node.enroll.requested")
        step.expect(len(requested) >= 2, "requested events: {}".format(audit.kinds(events)))
