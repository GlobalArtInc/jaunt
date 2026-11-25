import json


class CastError(Exception):
    pass


KINDS = ("o", "i", "r", "m")


def parse(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CastError("the cast is not UTF-8: {}".format(error))
    if not text.endswith("\n"):
        raise CastError("the cast does not end with a newline")
    lines = text.split("\n")[:-1]
    if not lines:
        raise CastError("the cast is empty")
    try:
        header = json.loads(lines[0])
    except ValueError as error:
        raise CastError("the header is not JSON: {}".format(error))
    if sorted(header) != ["env", "height", "timestamp", "version", "width"]:
        raise CastError("unexpected header keys: {}".format(sorted(header)))
    if header["version"] != 2:
        raise CastError("version {}".format(header["version"]))
    for key in ("width", "height", "timestamp"):
        if not isinstance(header[key], int) or isinstance(header[key], bool):
            raise CastError("{} is not an integer".format(key))
    if sorted(header["env"]) != ["SHELL", "TERM"] or not all(isinstance(v, str) for v in header["env"].values()):
        raise CastError("unexpected env: {}".format(header["env"]))
    events = []
    previous = 0.0
    for number, line in enumerate(lines[1:], start=2):
        try:
            event = json.loads(line)
        except ValueError as error:
            raise CastError("line {} is not JSON: {}".format(number, error))
        if not isinstance(event, list) or len(event) != 3:
            raise CastError("line {} is not a triple".format(number))
        when, kind, data = event
        if isinstance(when, bool) or not isinstance(when, (int, float)) or when < previous:
            raise CastError("line {}: time {!r} is not monotonic after {}".format(number, when, previous))
        if kind not in KINDS or not isinstance(data, str):
            raise CastError("line {}: bad event {!r}".format(number, event))
        previous = when
        events.append((when, kind, data))
    return header, events


def joined(events, kind):
    return "".join(data for _, event_kind, data in events if event_kind == kind)


def markers(events):
    return [data for _, kind, data in events if kind == "m"]
