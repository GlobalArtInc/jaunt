from stand import audit
from stand.texts import GENERIC_REFUSAL, refusal_texts


def refused_without_login(stand, step, user, node):
    before = (stand.accepted_logins(node), stand.failed_logins(node))
    shown = stand.ssh(user, node, "true")
    step.expect(shown.status != 0, "ssh succeeded")
    step.expect(refusal_texts(shown.err) == [GENERIC_REFUSAL], "stderr: {}".format(shown.err.strip()))
    after = (stand.accepted_logins(node), stand.failed_logins(node))
    step.expect(before == after, "sshd on {} logged {} -> {}".format(node, before, after))


def run(stand, report):
    marker = stand.marker()
    with report.step("bob, a member of limited, reaches node-a") as step:
        shown = stand.ssh("bob", "node-a", "id -un")
        step.expect(shown.ok and shown.out.strip() == "deploy", shown.text())

    with report.step("positive control: the sshd log of each node does record accepted logins in this run") as step:
        for node in ("node-a", "node-b"):
            step.expect(stand.accepted_logins(node) >= 1, "{}: no Accepted line, so a quiet log would prove nothing".format(node))
        step.expect(stand.on_node("node-a", ["grep", "-c", "Accepted publickey for deploy .* ID jaunt:", "/var/log/sshd.log"]).out.strip() != "0",
                    "the accepted logins of node-a carry no Jaunt key id")

    with report.step("bob is refused on node-b with the generic text and no sshd login") as step:
        refused_without_login(stand, step, "bob", "node-b")

    for node in ("node-a", "node-b"):
        with report.step("carol, who has no role, is refused on {} and sshd sees nothing".format(node)) as step:
            refused_without_login(stand, step, "carol", node)

    with report.step("every refusal gives the same text, so the user learns nothing about why") as step:
        bob = refusal_texts(stand.ssh("bob", "node-b", "true").err)
        carol = refusal_texts(stand.ssh("carol", "node-b", "true").err)
        unknown = refusal_texts(stand.ssh("carol", "no-such-node", "true").err)
        step.expect(bob == carol == unknown == [GENERIC_REFUSAL], "bob: {} carol: {} unknown node: {}".format(bob, carol, unknown))

    with report.step("audit: authz.deny for bob (node-b) and for carol on both nodes") as step:
        events = audit.after(stand.audit_events(), marker)
        denies = audit.of_type(events, "authz.deny")
        bob = audit.by_actor(denies, stand.certs["bob"]["principal"])
        carol = audit.by_actor(denies, stand.certs["carol"]["principal"])
        step.expect(bob, "no authz.deny for bob: {}".format(audit.kinds(events)))
        step.expect(len(carol) >= 2, "authz.deny for carol: {}".format(len(carol)))
        step.note(str(carol[0]["fields"]))
