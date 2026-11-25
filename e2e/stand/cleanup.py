from . import engine
from .layout import ALL_ROLES, DATA_VOLUME, NETWORK, container


def names(*args):
    listed = engine.engine(*args)
    if not listed.ok:
        raise RuntimeError("`{} {}` failed: {}".format(engine.ENGINE, " ".join(args), listed.text()))
    return set(listed.out.split())


def remove_everything():
    problems = []
    existing = names("ps", "-a", "--format", "{{.Names}}")
    for role in ALL_ROLES:
        name = container(role)
        if name not in existing:
            continue
        engine.engine("kill", name)
        removed = engine.engine("rm", "-f", name)
        if not removed.ok:
            problems.append("removing container {}: {}".format(name, removed.text()))
    if NETWORK in names("network", "ls", "--format", "{{.Name}}"):
        removed = engine.engine("network", "rm", NETWORK)
        if not removed.ok:
            problems.append("removing network {}: {}".format(NETWORK, removed.text()))
    if DATA_VOLUME in names("volume", "ls", "--format", "{{.Name}}"):
        removed = engine.engine("volume", "rm", DATA_VOLUME)
        if not removed.ok:
            problems.append("removing volume {}: {}".format(DATA_VOLUME, removed.text()))
    if problems:
        raise RuntimeError("the stand could not be removed:\n" + "\n".join(problems))
