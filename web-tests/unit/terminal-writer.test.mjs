import assert from "node:assert/strict";
import { test } from "node:test";

import { fakeClock } from "./terminal-support.mjs";

const ADAPTER = "../../crates/jaunt-web/assets/assets/js/recording/terminal.js";
const ESC = "\u001b";
const bytes = (text) => new TextEncoder().encode(text);

async function rig() {
  const { createGuardedWriter } = await import(ADAPTER);
  const clock = fakeClock();
  const terminal = { cols: 80, rows: 24, written: [], write(text) { this.written.push(text); } };
  const writer = createGuardedWriter(terminal, clock);
  return { clock, terminal, writer };
}

test("a fragment held for longer than 30 ms is written as it is, in order", async () => {
  const { clock, terminal, writer } = await rig();
  writer.write(bytes(`ab${ESC}[50`));
  assert.deepEqual(terminal.written, ["ab"]);
  assert.equal(clock.state.timers.length, 1);
  clock.advance(29);
  assert.deepEqual(terminal.written, ["ab"]);
  clock.advance(1);
  assert.deepEqual(terminal.written, ["ab", `${ESC}[50`]);
  assert.equal(clock.state.timers.length, 0);
  clock.advance(1000);
  assert.deepEqual(terminal.written, ["ab", `${ESC}[50`]);
});

test("the next write cancels the timer and puts the held bytes before the new text", async () => {
  const { clock, terminal, writer } = await rig();
  writer.write(bytes(`ab${ESC}[50`));
  clock.advance(20);
  writer.write(bytes("00Scd"));
  assert.deepEqual(terminal.written, ["ab", `${ESC}[24Scd`]);
  assert.equal(clock.state.timers.length, 0);
  clock.advance(1000);
  assert.equal(terminal.written.length, 2);
});

test("a write that ends in another fragment replaces the timer instead of stacking one", async () => {
  const { clock, terminal, writer } = await rig();
  writer.write(bytes(`${ESC}[5`));
  writer.write(bytes(`0${ESC}[6`));
  assert.equal(clock.state.timers.length, 1);
  clock.advance(30);
  assert.equal(terminal.written.join(""), `${ESC}[50${ESC}[6`);
});

test("dispose cancels the timer, forgets the held bytes and later writes do nothing", async () => {
  const { clock, terminal, writer } = await rig();
  writer.write(bytes(`ab${ESC}[50`));
  writer.dispose();
  assert.equal(clock.state.timers.length, 0);
  clock.advance(1000);
  assert.deepEqual(terminal.written, ["ab"]);
  writer.write(bytes("more"));
  assert.deepEqual(terminal.written, ["ab"]);
});

test("a character split between two writes is decoded once and a long write is cut into small pieces", async () => {
  const { terminal, writer } = await rig();
  const euro = bytes("€");
  writer.write(euro.subarray(0, 1));
  writer.write(euro.subarray(1));
  assert.equal(terminal.written.join(""), "€");
  terminal.written.length = 0;
  writer.write(bytes("z".repeat(5000)));
  assert.equal(terminal.written.every((piece) => piece.length <= 2048), true);
  assert.equal(terminal.written.join(""), "z".repeat(5000));
});
