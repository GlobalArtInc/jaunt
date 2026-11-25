import os
import subprocess
import threading
import time

ENGINE = os.environ.get("CONTAINER_ENGINE", "podman")


class Result:
    def __init__(self, status, out, err, seconds):
        self.status = status
        self.out = out
        self.err = err
        self.seconds = seconds

    @property
    def ok(self):
        return self.status == 0

    def text(self):
        return (self.out + self.err).strip()


def run(argv, timeout=120, input_text=None):
    started = time.monotonic()
    try:
        done = subprocess.run(
            argv,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            input=input_text,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as expired:
        return Result(124, expired.stdout or "", (expired.stderr or "") + "\ntimed out", time.monotonic() - started)
    return Result(done.returncode, done.stdout, done.stderr, time.monotonic() - started)


def engine(*args, timeout=120, input_text=None):
    return run([ENGINE, *args], timeout=timeout, input_text=input_text)


def exec_argv(container, argv, user=None, env=None, tty=False, detach=False):
    command = [ENGINE, "exec"]
    if detach:
        command.append("-d")
    if tty:
        command.append("-t")
    if user:
        command += ["-u", user]
    for key, value in (env or {}).items():
        command += ["-e", "{}={}".format(key, value)]
    return command + [container] + list(argv)


def exec_in(container, argv, user=None, env=None, tty=False, timeout=120, input_text=None):
    return run(exec_argv(container, argv, user, env, tty), timeout=timeout, input_text=input_text)


def exec_detached(container, argv, user=None, env=None):
    return run(exec_argv(container, argv, user, env, detach=True), timeout=30)


class Streaming:
    def __init__(self, argv):
        self.process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
        )
        self.lines = []
        self.lock = threading.Lock()
        self.reader = threading.Thread(target=self.pump, daemon=True)
        self.reader.start()

    def pump(self):
        for line in self.process.stdout:
            with self.lock:
                self.lines.append(line.rstrip("\n"))

    def snapshot(self):
        with self.lock:
            return list(self.lines)

    def wait_for_line(self, prefix, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in self.snapshot():
                if line.startswith(prefix):
                    return line
            if self.process.poll() is not None:
                break
            time.sleep(0.1)
        for line in self.snapshot():
            if line.startswith(prefix):
                return line
        return None

    def wait_for_text(self, text, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(text in line for line in self.snapshot()):
                return True
            if self.process.poll() is not None:
                break
            time.sleep(0.1)
        return any(text in line for line in self.snapshot())

    def finish(self, timeout):
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            self.reader.join(5)
            return 124
        self.reader.join(5)
        return self.process.returncode

    def running(self):
        return self.process.poll() is None

    def output(self):
        return "\n".join(self.snapshot())
