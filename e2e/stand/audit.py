def kinds(events):
    return [event["type"] for event in events]


def appears_in_order(events, expected):
    remaining = iter(kinds(events))
    return all(any(kind == wanted for kind in remaining) for wanted in expected)


def by_actor(events, actor):
    return [event for event in events if event.get("actor") == actor]


def of_session(events, session_id):
    return [event for event in events if event.get("session_id") == session_id]


def of_type(events, prefix):
    return [event for event in events if event["type"].startswith(prefix)]


def after(events, marker):
    return [event for event in events if (event["time"], event.get("id", "")) > marker]


def last_marker(events):
    if not events:
        return ("", "")
    last = events[-1]
    return (last["time"], last.get("id", ""))
