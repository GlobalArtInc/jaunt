GENERIC_REFUSAL = "jaunt: access denied or node unavailable"
OPEN_FAILED = "open failed: connect failed: "


def refusal_texts(stderr):
    found = []
    for line in stderr.splitlines():
        if OPEN_FAILED in line:
            found.append(line.split(OPEN_FAILED, 1)[1].strip())
    return found


def is_generic_refusal(stderr):
    return refusal_texts(stderr) == [GENERIC_REFUSAL]
