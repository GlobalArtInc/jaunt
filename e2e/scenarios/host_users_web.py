import json
import os

from scenarios import host_users_kit as kit
from scenarios.host_users import control_created, control_refused, helper_ref_lines
from stand.layout import OUT

NODE = "node-a"
PLAIN_NODE = "node-b"
USER = "erin"
ADMIN = "admin"
CREATED = {"380": "hu-web1", "1440": "hu-web2"}
RESERVED = "postgres"
GROUP = "hu-wgrp"
OFF = "hu-wuncreated"
DELAY_SECS = 3
RESULT_FILE = os.path.join(OUT, "web-accounts.json")
LOGINS = {"created": CREATED, "reserved": RESERVED, "group": GROUP, "off": OFF}


def environment():
    return {
        "E2E_ACCOUNT_USER": USER,
        "E2E_ACCOUNT_ADMIN": ADMIN,
        "E2E_ACCOUNTS_OUT": RESULT_FILE,
        "E2E_ACCOUNT_LOGINS": json.dumps(LOGINS),
    }


def prepare(stand, step):
    kit.prepare_host(stand, NODE)
    done = kit.install_creating(stand, NODE)
    step.expect(done.ok, "install --create-accounts on {}: {}".format(NODE, done.text()))
    kit.write_section(stand, NODE, deny=())
    kit.start_helper(stand, NODE)
    kit.sh(stand, NODE, "groupadd {}".format(GROUP))
    kit.restart_agent(stand, NODE)
    waited = kit.wait_creates_accounts(stand, NODE, True)
    if waited > 15:
        step.note("the creates_accounts flag appeared {:.0f} s after the restart".format(waited))
    step.expect(not kit.creates_accounts(stand, PLAIN_NODE), "{} announces account creation".format(PLAIN_NODE))
    kit.delay_useradd(stand, NODE, DELAY_SECS)
    if os.path.exists(RESULT_FILE):
        os.remove(RESULT_FILE)


def finish(stand):
    kit.restore_useradd(stand, NODE)


def denials(stand):
    return stand.audit_events(type="terminal.denied")


def verify(stand, step):
    step.expect(os.path.exists(RESULT_FILE), "the browser run wrote no results")
    with open(RESULT_FILE) as handle:
        results = json.load(handle)["results"]
    created = [row for row in results if row["kind"] == "created"]
    step.expect(sorted(row["login"] for row in created) == sorted(CREATED.values()), "created: {}".format(created))
    for row in created:
        login = row["login"]
        stand.wait_until("host_user.created of {} in the control audit".format(login), lambda login=login: control_created(stand, login), 20, interval=1)
        event = control_created(stand, login)[0]
        step.expect(event["session_id"] == row["session"], "the audit session {} is not the page session {}".format(event["session_id"], row["session"]))
        ref = event["fields"]["ref"]
        lines = kit.helper_lines(stand, NODE, login)
        step.expect(len(lines) == 1 and "ref={} ".format(ref) in lines[0] and "outcome=created uid={} ".format(row["uid"]) in lines[0], lines)
        agent = kit.agent_events_of(stand, NODE, "agent.host_user.created", login)
        step.expect(len(agent) == 1 and agent[0]["ref"] == ref and agent[0]["session_id"] == row["session"], agent)
        step.expect(kit.account_facts(stand, NODE, login) is not None, "{} is missing on {}".format(login, NODE))
    refused = [row for row in results if row["kind"] == "account_refused"]
    step.expect(len(refused) == 4, "refusals: {}".format(refused))
    for row in refused:
        ref = row["ref"]
        reason = "reserved_name" if row["login"] == RESERVED else "group_collision"
        agent = [fields for fields in kit.agent_events_of(stand, NODE, "agent.host_user.refused", row["login"]) if fields["ref"] == ref]
        step.expect(len(agent) == 1 and agent[0]["reason"] == reason, "{}: agent audit {}".format(row["login"], agent))
        lines = helper_ref_lines(stand, NODE, ref)
        if reason == "group_collision":
            step.expect(len(lines) == 1 and "outcome=refused reason=group_collision" in lines[0], "{}: helper journal {}".format(ref, lines))
        else:
            step.expect(not lines, "{}: the helper saw a node-rule refusal: {}".format(ref, lines))
        stand.wait_until("host_user.refused of {} in the control audit".format(ref), lambda ref=ref: control_refused(stand, ref), 20, interval=1)
        step.expect(control_refused(stand, ref)[0]["fields"].get("reason") == reason, control_refused(stand, ref))
    missing = [row for row in results if row["kind"] == "no_account"]
    step.expect(len(missing) == 2, "no_account runs: {}".format(missing))
    for row in missing:
        ref = row["ref"]
        step.expect(kit.REF.fullmatch(ref or ""), "no_account reference {}".format(ref))
        agent = [fields for fields in kit.agent_events_of(stand, PLAIN_NODE, "agent.host_user.missing", OFF) if fields["ref"] == ref]
        step.expect(len(agent) == 1 and agent[0].get("cause") == "disabled", "{}: agent audit {}".format(ref, agent))
        stand.wait_until("terminal.denied no_account with the reference {}".format(ref),
                         lambda ref=ref: [event for event in denials(stand) if event["fields"].get("ref") == ref], 20, interval=1)
        shown = [event for event in denials(stand) if event["fields"].get("ref") == ref]
        step.expect(len(shown) == 1 and shown[0]["fields"].get("reason") == "no_account" and shown[0]["fields"].get("login") == OFF, shown)
    step.expect(not kit.helper_lines(stand, NODE, OFF) and kit.account_facts(stand, PLAIN_NODE, OFF) is None,
                "the login without creation left traces")
