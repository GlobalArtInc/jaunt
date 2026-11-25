import time
import traceback
from contextlib import contextmanager


class StepFailed(Exception):
    pass


class Step:
    def __init__(self, name):
        self.name = name
        self.notes = []

    def expect(self, condition, message):
        if not condition:
            raise StepFailed(message)

    def note(self, text):
        self.notes.append(text)


class Report:
    def __init__(self, label):
        self.label = label
        self.rows = []

    @contextmanager
    def step(self, name):
        step = Step(name)
        started = time.monotonic()
        failure = None
        try:
            yield step
        except StepFailed as failed:
            failure = str(failed)
        except Exception:
            failure = traceback.format_exc(limit=6)
        seconds = time.monotonic() - started
        self.rows.append((name, failure is None, seconds, failure))
        mark = "PASS" if failure is None else "FAIL"
        print("{} [{}] {} ({:.1f} s)".format(mark, self.label, name, seconds), flush=True)
        for note in step.notes:
            print("     {}".format(note), flush=True)
        if failure is not None:
            for line in failure.strip().splitlines():
                print("     {}".format(line), flush=True)

    def passed(self):
        return sum(1 for row in self.rows if row[1])

    def failed(self):
        return sum(1 for row in self.rows if not row[1])

    def table(self):
        width = max([len(row[0]) for row in self.rows] + [10])
        lines = ["", "RESULTS [{}]".format(self.label), "-" * (width + 20)]
        for name, ok, seconds, _ in self.rows:
            lines.append("{:<{w}}  {}  {:7.1f} s".format(name, "PASS" if ok else "FAIL", seconds, w=width))
        lines.append("-" * (width + 20))
        lines.append("{} passed, {} failed, {:.1f} s total".format(
            self.passed(), self.failed(), sum(row[2] for row in self.rows)))
        return "\n".join(lines)
