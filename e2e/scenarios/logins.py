import re

from stand import audit

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def run(stand, report):
    marker = stand.marker()
    for user in ("alice", "bob", "carol"):
        with report.step("{} signs in with jaunt login, the browser step goes through the fake IdP".format(user)) as step:
            status, output, browser = stand.login(user)
            step.expect(status == 0, "jaunt login exited {}:\n{}\nbrowser: {}".format(status, output, browser.text()))
            step.expect("Signed in as {}@e2e.test".format(user) in output, output)
            info = stand.certificate_info(user)
            stand.certs[user] = info
            step.expect(info["principal"] and UUID.match(info["principal"]), "principal is {}".format(info["principal"]))
            step.expect(info["key_id"] and info["key_id"].startswith("jaunt:{}@e2e.test:".format(user)), "key id {}".format(info["key_id"]))
            loaded = stand.on_client(["ssh-add", "-l"], user=user)
            step.expect("ED25519" in loaded.out, "ssh-add -l: {}".format(loaded.text()))
            config = stand.on_client(["cat", "/home/{}/.ssh/config".format(user)], user=user)
            step.expect("Include" in config.out, "~/.ssh/config: {}".format(config.text()))
            modes = stand.on_client(["sh", "-c", "stat -c '%a %n' /home/{0}/.jaunt/default/* /home/{0}/.jaunt/default".format(user)], user=user)
            step.note(modes.out.strip().replace("\n", "; "))

    with report.step("jaunt status shows the signed-in user and a valid certificate") as step:
        shown = stand.on_client(["jaunt", "status", "--online"], user="alice")
        step.expect(shown.ok and "alice@e2e.test" in shown.out, shown.text())

    with report.step("jaunt ls lists the nodes alice may see") as step:
        shown = stand.on_client(["jaunt", "ls"], user="alice")
        step.expect(shown.ok and "node-a" in shown.out and "node-b" in shown.out, shown.text())

    with report.step("audit: login.started, login.approved, cert.issued for every user") as step:
        events = audit.after(stand.audit_events(), marker)
        started = audit.of_type(events, "login.started")
        step.expect(len(started) >= 3, "login.started events: {}".format(audit.kinds(events)))
        for user in ("alice", "bob", "carol"):
            mine = audit.by_actor(events, stand.certs[user]["principal"])
            step.expect(audit.appears_in_order(mine, ["login.approved", "cert.issued"]), "{}: {}".format(user, audit.kinds(mine)))
            issued = audit.of_type(mine, "cert.issued")
            step.expect(issued and issued[-1]["fields"].get("serial") == stand.certs[user]["serial"],
                        "{}: serial in the audit {}".format(user, issued))
