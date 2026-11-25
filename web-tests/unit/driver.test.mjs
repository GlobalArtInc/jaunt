import assert from "node:assert/strict";
import { test } from "node:test";

import { parseCastBytes } from "../../crates/jaunt-web/assets/assets/js/recording/cast.js";
import { IDLE_CAP_SECONDS, buildTimeline, createDriver, renderInput } from "../../crates/jaunt-web/assets/assets/js/recording/driver.js";

const encoder = new TextEncoder();
const HEADER = '{"version":2,"width":90,"height":20}';

function castOf(...events) {
  return parseCastBytes(encoder.encode([HEADER, ...events.map((event) => JSON.stringify(event))].join("\n") + "\n"));
}

function fakeClock() {
  const clock = {
    time: 0,
    timers: [],
    now: () => clock.time,
    setTimeout(callback, ms) {
      const timer = { callback, at: clock.time + ms, id: clock.timers.length + 1 };
      clock.timers.push(timer);
      return timer.id;
    },
    clearTimeout(id) {
      clock.timers = clock.timers.filter((timer) => timer.id !== id);
    },
    advance(ms) {
      const end = clock.time + ms;
      for (;;) {
        const due = clock.timers.filter((timer) => timer.at <= end).sort((a, b) => a.at - b.at)[0];
        if (!due) {
          break;
        }
        clock.timers = clock.timers.filter((timer) => timer !== due);
        clock.time = Math.max(clock.time, due.at);
        due.callback();
      }
      clock.time = end;
    },
  };
  return clock;
}

function fakeSink() {
  const ops = [];
  return {
    ops,
    write: (text) => ops.push(["write", text]),
    resize: (cols, rows) => ops.push(["resize", cols, rows]),
    reset: (cols, rows) => ops.push(["reset", cols, rows]),
    dispose: () => ops.push(["dispose"]),
    text: () => ops.filter((op) => op[0] === "write").map((op) => op[1]).join(""),
  };
}

function setup(events, options = {}) {
  const clock = fakeClock();
  const sink = fakeSink();
  const driver = createDriver({ cast: castOf(...events), sink, clock, compressIdle: false, ...options });
  return { clock, sink, driver };
}

const SCRIPT = [[0.5, "o", "A"], [1, "o", "B"], [3, "o", "C"]];

test("events appear at their recorded times and the terminal is sized from the header", () => {
  const { clock, sink, driver } = setup(SCRIPT);
  assert.deepEqual(sink.ops[0], ["reset", 90, 20]);
  driver.play();
  clock.advance(400);
  assert.equal(sink.text(), "");
  clock.advance(100);
  assert.equal(sink.text(), "A");
  clock.advance(500);
  assert.equal(sink.text(), "AB");
  clock.advance(1900);
  assert.equal(sink.text(), "AB");
  clock.advance(200);
  assert.equal(sink.text(), "ABC");
  assert.equal(driver.snapshot().status, "ended");
  assert.equal(clock.timers.length, 0);
});

test("long pauses are shortened to the idle cap and the total shrinks with them", () => {
  const events = [[1, "o", "A"], [61, "o", "B"], [62, "o", "C"]];
  const cast = castOf(...events);
  assert.equal(buildTimeline(cast, { showInput: false, compressIdle: false }).total, 62);
  assert.equal(buildTimeline(cast, { showInput: false, compressIdle: true }).total, 1 + IDLE_CAP_SECONDS + 1);
  const { clock, sink, driver } = setup(events, { compressIdle: true });
  driver.play();
  clock.advance(1000);
  assert.equal(sink.text(), "A");
  clock.advance(IDLE_CAP_SECONDS * 1000);
  assert.equal(sink.text(), "AB");
  assert.equal(driver.snapshot().duration, 4);
});

test("the speed scales the clock from half speed to eight times and can change while playing", () => {
  for (const [speed, wait] of [[0.5, 1000], [2, 250], [8, 62.5]]) {
    const { clock, sink, driver } = setup([[0.5, "o", "A"]], { speed });
    driver.play();
    clock.advance(wait - 1);
    assert.equal(sink.text(), "", String(speed));
    clock.advance(2);
    assert.equal(sink.text(), "A", String(speed));
  }
  const { clock, sink, driver } = setup(SCRIPT);
  driver.play();
  clock.advance(1000);
  assert.equal(driver.snapshot().position, 1);
  driver.setSpeed(4);
  clock.advance(500);
  assert.equal(sink.text(), "ABC");
  driver.setSpeed(3);
  assert.equal(driver.snapshot().speed, 4);
});

test("pause freezes the position and play continues from it", () => {
  const { clock, sink, driver } = setup(SCRIPT);
  driver.play();
  clock.advance(700);
  driver.pause();
  assert.equal(driver.snapshot().status, "paused");
  assert.equal(driver.snapshot().position, 0.7);
  clock.advance(10_000);
  assert.equal(sink.text(), "A");
  driver.play();
  clock.advance(300);
  assert.equal(sink.text(), "AB");
});

test("seeking forward applies only what is missing, seeking back resets and replays", () => {
  const { sink, driver } = setup(SCRIPT);
  driver.seek(1.5);
  assert.deepEqual(sink.ops.slice(1), [["write", "AB"]]);
  driver.seek(3);
  assert.deepEqual(sink.ops.slice(2), [["write", "C"]]);
  assert.equal(driver.snapshot().status, "ended");
  driver.seek(0.6);
  assert.deepEqual(sink.ops.slice(3), [["reset", 90, 20], ["write", "A"]]);
  assert.equal(driver.snapshot().status, "paused");
  driver.seek(-50);
  assert.equal(driver.snapshot().position, 0);
  driver.seek(Infinity);
  assert.equal(driver.snapshot().position, 3);
  driver.seek(Number.NaN);
  assert.equal(driver.snapshot().position, 0);
});

test("skip moves relative to the position and restart plays from the beginning", () => {
  const { clock, sink, driver } = setup(SCRIPT);
  driver.skip(2);
  assert.equal(sink.text(), "AB");
  driver.skip(-1.5);
  assert.equal(driver.snapshot().position, 0.5);
  driver.seek(3);
  driver.restart();
  assert.equal(driver.snapshot().status, "playing");
  clock.advance(500);
  assert.deepEqual(sink.ops.slice(-2), [["reset", 90, 20], ["write", "A"]]);
});

test("playing a finished recording starts it again and seeking while playing keeps the clock", () => {
  const { clock, sink, driver } = setup(SCRIPT);
  driver.play();
  clock.advance(5000);
  assert.equal(driver.snapshot().status, "ended");
  driver.play();
  clock.advance(600);
  assert.equal(sink.text(), "ABCA");
  driver.seek(2.9);
  clock.advance(200);
  assert.equal(sink.text().endsWith("C"), true);
});

test("typed input is hidden until asked for, then shown as visible text without any escape from the recording", () => {
  const events = [[0.1, "o", "$ "], [0.2, "i", "ls\r\u001b[31m\u009d0;x\u007f"], [0.3, "o", "out"]];
  const { sink, driver } = setup(events);
  driver.seek(1);
  assert.equal(sink.text(), "$ out");
  driver.setShowInput(true);
  assert.equal(driver.snapshot().position, 0.3);
  assert.equal(sink.text().endsWith("$ \u001b[7mls^M^[[31m�0;x^?\u001b[27mout"), true);
  assert.equal(renderInput(""), "");
  driver.setShowInput(false);
  assert.equal(sink.ops.at(-1)[0], "write");
  assert.equal(sink.ops.at(-1)[1], "$ out");
});

test("a resize flushes the output before it and a huge replay is written in bounded pieces", () => {
  const { sink, driver } = setup([[0.1, "o", "a"], [0.2, "r", "100x30"], [0.3, "o", "b"]]);
  driver.seek(1);
  assert.deepEqual(sink.ops.slice(1), [["write", "a"], ["resize", 100, 30], ["write", "b"]]);

  const big = Array.from({ length: 700 }, (_, index) => [index / 1000, "o", "x".repeat(1000)]);
  const bulk = setup(big);
  bulk.driver.seek(10);
  const writes = bulk.sink.ops.filter((op) => op[0] === "write");
  assert.ok(writes.length >= 2);
  assert.ok(writes.every((op) => op[1].length < 300_000));
  assert.equal(bulk.sink.text().length, 700_000);
});

test("disposing stops the timer and ignores later calls", () => {
  const { clock, sink, driver } = setup(SCRIPT);
  driver.play();
  driver.dispose();
  assert.equal(clock.timers.length, 0);
  const before = sink.ops.length;
  driver.play();
  driver.seek(2);
  clock.advance(5000);
  assert.equal(sink.ops.length, before);
});

test("an empty cast ends at once and listeners hear about every change", () => {
  const { driver } = setup([]);
  const heard = [];
  driver.onChange((snapshot) => heard.push(snapshot.status));
  driver.play();
  assert.deepEqual(heard, ["ended"]);
  assert.equal(driver.snapshot().duration, 0);
});
