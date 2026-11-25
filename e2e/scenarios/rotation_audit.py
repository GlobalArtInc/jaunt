import json

from stand import audit
from stand.stand import SECRET_PATTERNS


def index_of(events, start, event_type, **fields):
    for position in range(start, len(events)):
        event = events[position]
        if event["type"] == event_type and all(event["fields"].get(name) == value for name, value in fields.items()):
            return position
    return None


def run(stand, report):
    kit = stand.kit
    fp = kit.fingerprints

    with report.step("audit: ca.key.added, ca.reloaded, ca.key.promoted, ca.reloaded, ca.key.retired, ca.reloaded in order for each rotation") as step:
        events = audit.after(stand.audit_events(type="ca."), kit.marker)
        step.note("ca events: {}".format(", ".join("{}[{}]".format(e["type"], e["fields"].get("kind")) for e in events)))
        for kind, old, new in (("user", fp["user-a"], fp["user-b"]), ("host", fp["host-a"], fp["host-b"]), ("user", fp["user-b"], fp["user-c"])):
            position = index_of(events, 0, "ca.key.added", kind=kind, fp=new)
            step.expect(position is not None, "no ca.key.added for the {} key {}".format(kind, new))
            position = index_of(events, position, "ca.reloaded", kind=kind)
            step.expect(position is not None, "no ca.reloaded after add-next of {}".format(new))
            position = index_of(events, position, "ca.key.promoted", kind=kind, fp=new)
            step.expect(position is not None, "no ca.key.promoted for {}".format(new))
            position = index_of(events, position, "ca.reloaded", kind=kind, active_fp=new)
            step.expect(position is not None, "no ca.reloaded naming {} as active".format(new))
            position = index_of(events, position, "ca.key.retired", kind=kind, fp=old)
            step.expect(position is not None, "no ca.key.retired for {}".format(old))
            position = index_of(events, position, "ca.reloaded", kind=kind, active_fp=new)
            step.expect(position is not None, "no ca.reloaded after retiring {}".format(old))

    with report.step("audit: --force is recorded as forced = true and only for the two forced steps") as step:
        events = audit.after(stand.audit_events(type="ca.key."), kit.marker)
        forced = sorted((event["type"], event["fields"].get("kind"), event["fields"].get("fp"))
                        for event in events if event["fields"].get("forced") is True)
        expected = sorted([("ca.key.promoted", "user", fp["user-c"]), ("ca.key.retired", "user", fp["user-b"])])
        step.expect(forced == expected, "forced events: {}".format(forced))
        unforced = [event for event in events if event["type"] != "ca.key.added" and event["fields"].get("forced") is False]
        step.expect(len(unforced) == 4, "unforced promote and retire events: {}".format(len(unforced)))
        refused = [event for event in events if event["fields"].get("blocked") is True]
        step.expect(len(refused) == 2, "events that went past a blocked check: {}".format(len(refused)))

    with report.step("audit: agent.trust.served carries every user trust id the status showed") as step:
        events = audit.after(stand.audit_events(type="agent.trust.served"), kit.marker)
        served = {event["fields"].get("trust_id") for event in events}
        step.expect(None not in served, "an event has no trust_id: {}".format(events[:1]))
        missing = [trust_id for trust_id in kit.trust_ids["user"] if trust_id not in served]
        step.expect(len(kit.trust_ids["user"]) >= 5 and not missing,
                    "trust ids never served: {} of {}".format(missing, kit.trust_ids["user"]))
        step.note("{} served events, {} distinct trust ids".format(len(events), len(served)))
        both = kit.trust_ids["user"][1]
        old_agent = [event for event in events if event.get("node") == kit.first_nodes["node-c"]
                     and event["fields"].get("trust_id") == both]
        step.expect(old_agent, "the old-protocol node-c was never served the set with both keys {}".format(both))
        step.note("node-c (first-version trust route) was served the set with both user keys {} time(s)".format(len(old_agent)))

    with report.step("keys: retired private keys are gone from the data directory, the public halves are kept") as step:
        shown = stand.on_server(["sh", "-c", "cd /var/lib/jaunt/ca && for kind in user host; do echo $kind; ls $kind $kind/retired 2>&1; done"])
        step.note(shown.out.strip().replace("\n", "; "))
        cli = kit.status()
        for kind, retired in (("user", [fp["user-a"], fp["user-b"]]), ("host", [fp["host-a"]])):
            for key in retired:
                step.expect(key + ".age" not in shown.out, "{}: the private key of {} is still on disk".format(kind, key))
                step.expect(key + ".pub" in shown.out, "{}: the public key of {} is gone".format(kind, key))
            states = [entry["state"] for entry in cli[kind]["keys"]]
            step.expect(states.count("retired") == len(retired), "{} states {}".format(kind, states))

    with report.step("secrets: the audit trail and the status output hold no key material") as step:
        identity = stand.on_server(["cat", "/var/lib/jaunt/ca/age-identity.txt"]).out
        values = [line.strip() for line in identity.splitlines() if line.startswith("AGE-SECRET-KEY-")]
        step.expect(values, "the age identity was not found")
        stand.secrets.extend(values)
        text = json.dumps(stand.audit_events()) + json.dumps(kit.status()) + json.dumps(kit.api_status())
        for pattern in SECRET_PATTERNS:
            step.expect(not pattern.search(text), "the audit output matches {}".format(pattern.pattern[:40]))
        for value in values:
            step.expect(value not in text, "the age secret appears in the audit output")

    report_timings(kit, report)


def report_timings(kit, report):
    with report.step("timings: phases and the named waits") as step:
        for name, seconds in kit.phases:
            step.note("phase {}: {:.0f} s".format(name, seconds))
        for name, seconds, deadline in kit.waits:
            step.note("wait {:.1f} s of {} s: {}".format(seconds, deadline, name))
        step.note("the sessions were checked {} times: none ended before its certificate expired".format(kit.session_checks))
