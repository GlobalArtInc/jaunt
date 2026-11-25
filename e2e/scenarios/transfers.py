import time

REMOTE_HOME = "/home/deploy"
LOCAL = "/tmp/e2e-big"


def digest_local(stand, path):
    return stand.on_client(["sha256sum", path], user="alice").out.split()[0]


def digest_remote(stand, path):
    shown = stand.on_node("node-a", ["sha256sum", path])
    return shown.out.split()[0] if shown.ok else None


def used_protocol(log, mode):
    sftp = "Sending subsystem: sftp" in log
    legacy = "Sending command: scp" in log
    return sftp and not legacy if mode == "sftp" else legacy and not sftp


def run(stand, report):
    mib = stand.transfer_mib
    target = "deploy@node-a.e2e.test"
    with report.step("a {} MiB random file is prepared on the client".format(mib)) as step:
        made = stand.on_client(["sh", "-c", "head -c {} /dev/urandom >{}".format(mib * 1048576, LOCAL)], user="alice", timeout=300)
        step.expect(made.ok, made.text())
        stand.digest = digest_local(stand, LOCAL)

    for mode, flags in (("sftp", []), ("legacy", ["-O"])):
        remote = "{}/big-{}".format(REMOTE_HOME, mode)
        back = "/tmp/e2e-back-{}".format(mode)
        with report.step("scp {} upload of {} MiB matches by sha256".format(mode, mib)) as step:
            started = time.monotonic()
            sent = stand.on_client(["scp", "-v", "-o", "BatchMode=yes", *flags, LOCAL, "{}:big-{}".format(target, mode)], user="alice", timeout=900)
            step.expect(sent.ok, sent.text()[-600:])
            step.expect(used_protocol(sent.err, mode), "scp did not use the {} protocol".format(mode))
            step.note("{:.1f} s".format(time.monotonic() - started))
            step.expect(digest_remote(stand, remote) == stand.digest, "the digests differ")
        with report.step("scp {} download of {} MiB matches by sha256".format(mode, mib)) as step:
            started = time.monotonic()
            got = stand.on_client(["scp", "-v", "-o", "BatchMode=yes", *flags, "{}:big-{}".format(target, mode), back], user="alice", timeout=900)
            step.expect(got.ok, got.text()[-600:])
            step.expect(used_protocol(got.err, mode), "scp did not use the {} protocol".format(mode))
            step.note("{:.1f} s".format(time.monotonic() - started))
            step.expect(digest_local(stand, back) == stand.digest, "the digests differ")
        stand.on_client(["rm", "-f", back], user="alice")
        stand.on_node("node-a", ["rm", "-f", remote])

    with report.step("rsync upload of {} MiB matches by sha256".format(mib)) as step:
        started = time.monotonic()
        sent = stand.on_client(["rsync", "-a", "-e", "ssh -o BatchMode=yes", LOCAL, "{}:rsync-big".format(target)], user="alice", timeout=900)
        step.expect(sent.ok, sent.text())
        step.note("{:.1f} s".format(time.monotonic() - started))
        step.expect(digest_remote(stand, "{}/rsync-big".format(REMOTE_HOME)) == stand.digest, "the digests differ")

    with report.step("rsync download of {} MiB matches by sha256".format(mib)) as step:
        started = time.monotonic()
        got = stand.on_client(["rsync", "-a", "-e", "ssh -o BatchMode=yes", "{}:rsync-big".format(target), "/tmp/e2e-rsync-back"], user="alice", timeout=900)
        step.expect(got.ok, got.text())
        step.note("{:.1f} s".format(time.monotonic() - started))
        step.expect(digest_local(stand, "/tmp/e2e-rsync-back") == stand.digest, "the digests differ")

    stand.on_client(["rm", "-f", LOCAL, "/tmp/e2e-rsync-back"], user="alice")
    stand.on_node("node-a", ["rm", "-f", "{}/rsync-big".format(REMOTE_HOME)])
