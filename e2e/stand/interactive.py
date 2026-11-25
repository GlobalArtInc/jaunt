import fcntl
import os
import pty
import select
import struct
import subprocess
import termios
import time
import tty

from . import engine
from .layout import container


class Interactive:
    def __init__(self, argv, user, env):
        master, slave = pty.openpty()
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        tty.setraw(slave)
        command = engine.exec_argv(container("client"), argv, user=user, env=env, tty=True, interactive=True)
        self.process = subprocess.Popen(
            command, stdin=slave, stdout=slave, stderr=slave, close_fds=True, start_new_session=True,
        )
        os.close(slave)
        self.master = master
        self.received = bytearray()

    def pump(self, timeout):
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return False
        try:
            data = os.read(self.master, 65536)
        except OSError:
            data = b""
        if not data:
            time.sleep(min(timeout, 0.1))
            return False
        self.received.extend(data)
        return True

    def send(self, text):
        os.write(self.master, text.encode())

    def expect(self, text, timeout=30):
        needle = text.encode()
        deadline = time.monotonic() + timeout
        start = len(self.received)
        while time.monotonic() < deadline:
            if needle in self.received[max(0, start - len(needle)):]:
                return True
            if self.process.poll() is not None and not self.pump(0.2):
                break
            self.pump(0.2)
        return needle in self.received[max(0, start - len(needle)):]

    def wait(self, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self.process.poll() is None:
            self.pump(0.2)
        while self.pump(0.1):
            pass
        return self.process.poll()

    def text(self):
        return self.received.decode("utf-8", "replace")

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        try:
            os.close(self.master)
        except OSError:
            pass
