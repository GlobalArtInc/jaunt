from stand import audit

SHORT_TTL_SECS = 90


def expiry_of(stand, user):
    info = stand.certificate_info(user)
    now = int(stand.on_client(["date", "-u", "+%s"]).out.strip())
    until = stand.on_client(["sh", "-c", "TZ=UTC date -d \"$(ssh-keygen -L -f /home/{}/.jaunt/default/id_ed25519-cert.pub | sed -n 's/.*to \\(.*\\)$/\\1/p')\" +%s".format(user)], user=user)
    return info, now, int(until.out.strip() or 0)


def run(stand, report):
    marker = stand.marker()
    with report.step("jauntd restarts with a {} s certificate lifetime and node-a reconnects".format(SHORT_TTL_SECS)) as step:
        stand.restart_jauntd(SHORT_TTL_SECS)
        stand.wait_until("node-a to be reachable again", lambda: stand.agent_reconnected("node-a"), 90)

    with report.step("alice signs in again and gets a short certificate") as step:
        stand.logout("alice")
        status, output, browser = stand.login("alice")
        step.expect(status == 0, "jaunt login: {}\nbrowser: {}".format(output, browser.text()))
        first, now, until = expiry_of(stand, "alice")
        stand.certs["alice"] = first
        step.expect(0 < until - now <= SHORT_TTL_SECS, "the certificate lives {} s".format(until - now))
        shown = stand.ssh("alice", "node-a", "id -un")
        step.expect(shown.ok, shown.text())

    with report.step("after the certificate expired, ssh without a terminal says how to sign in") as step:
        stand.wait_until(
            "the certificate to expire",
            lambda: int(stand.on_client(["date", "-u", "+%s"]).out.strip()) >= until + 3,
            SHORT_TTL_SECS + 30,
            interval=2,
        )
        shown = stand.ssh("alice", "node-a", "true")
        step.expect(shown.status != 0, "ssh succeeded with an expired certificate")
        step.expect("jaunt login" in shown.err, "stderr: {}".format(shown.err))
        step.note("ssh said: {}".format(" | ".join(line for line in shown.err.splitlines() if line.strip())[:300]))

    with report.step("with a terminal, ssh signs in through the still valid IdP session and connects") as step:
        shown = stand.ssh("alice", "node-a", "echo renewed-$(id -un)", tty=True, timeout=120)
        step.expect(shown.ok and "renewed-deploy" in shown.out, shown.text())
        second = stand.certificate_info("alice")
        step.expect(second["serial"] and second["serial"] != first["serial"],
                    "the serial stayed {} -> {}".format(first["serial"], second["serial"]))

    with report.step("audit: a second login.approved and cert.issued followed the expiry") as step:
        events = audit.after(stand.audit_events(), marker)
        mine = audit.by_actor(events, stand.certs["alice"]["principal"])
        issued = audit.of_type(mine, "cert.issued")
        step.expect(len(issued) >= 2, audit.kinds(mine))
