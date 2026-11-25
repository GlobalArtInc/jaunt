import assert from "node:assert/strict";
import { test } from "node:test";

const BASE = "../../crates/jaunt-web/assets/assets/js/terminal/";
const ESC = "\u001b";
const SIZE = { cols: 100, rows: 30 };

test("counts of the line and scroll sequences are clamped to the rows or the columns and nothing else is touched", async () => {
  const { clampCounts } = await import(BASE + "guard.js");
  const run = (text) => clampCounts(text, SIZE).text;
  for (const final of ["S", "T", "L", "M"]) {
    assert.equal(run(`x${ESC}[5000${final}`), `x${ESC}[30${final}`, final);
    assert.equal(run(`${ESC}[30${final}`), `${ESC}[30${final}`, final);
    assert.equal(run(`${ESC}[31${final}`), `${ESC}[30${final}`, final);
  }
  assert.equal(run(`${ESC}[5000b`), `${ESC}[3000b`);
  assert.equal(run(`${ESC}[100b`), `${ESC}[100b`);
  for (const final of ["Z", "@", "P", "X"]) {
    assert.equal(run(`${ESC}[5000${final}`), `${ESC}[100${final}`, final);
    assert.equal(run(`${ESC}[100${final}`), `${ESC}[100${final}`, final);
  }
  assert.equal(run(`${ESC}[5000;5000H`), `${ESC}[5000;5000H`);
  assert.equal(run(`${ESC}[5000A`), `${ESC}[5000A`);
  assert.equal(run(`${ESC}[?5000S`), `${ESC}[?5000S`);
  assert.equal(run(`${ESC}[5000 S`), `${ESC}[5000 S`);
  assert.equal(run(`${ESC}[S${ESC}[;5000S`), `${ESC}[S${ESC}[;5000S`);
  assert.equal(run(`${ESC}[0005000S`), `${ESC}[30S`);
  assert.equal(run(`${ESC}[99999999999999999999S`), `${ESC}[30S`);
  assert.equal(run(`${ESC}[5000:1S`), `${ESC}[30:1S`);
  assert.equal(run(`${ESC}[5000;7S`), `${ESC}[30;7S`);
  assert.equal(run("plain text 5000S [5000S"), "plain text 5000S [5000S");
});

test("the eight-bit introducer is clamped too, and a sequence inside another one is found", async () => {
  const { clampCounts } = await import(BASE + "guard.js");
  assert.equal(clampCounts("\u009b5000S", SIZE).text, "\u009b30S");
  assert.equal(clampCounts(`${ESC}[5${ESC}[5000L`, SIZE).text, `${ESC}[5${ESC}[30L`);
  assert.equal(clampCounts(`${ESC}]0;title${ESC}[5000T`, SIZE).text, `${ESC}]0;title${ESC}[30T`);
});

test("a sequence split across chunks is held back and clamped once it is complete", async () => {
  const { createOutputGuard } = await import(BASE + "guard.js");
  const guard = createOutputGuard(() => SIZE);
  assert.deepEqual(guard.pieces(`ab${ESC}[50`), ["ab"]);
  assert.equal(guard.hasPending(), true);
  assert.deepEqual(guard.pieces("00"), []);
  assert.deepEqual(guard.pieces("Scd"), [`${ESC}[30Scd`]);
  assert.equal(guard.hasPending(), false);
  assert.deepEqual(guard.pieces(ESC), []);
  assert.deepEqual(guard.pieces("[5000M"), [`${ESC}[30M`]);
  guard.pieces(`${ESC}[12`);
  assert.equal(guard.flush(), `${ESC}[12`);
  assert.equal(guard.hasPending(), false);
  guard.pieces(`${ESC}[1`);
  guard.reset();
  assert.equal(guard.hasPending(), false);
});

test("a sequence that never ends is passed on after 64 characters instead of being held forever", async () => {
  const { createOutputGuard, MAX_PENDING } = await import(BASE + "guard.js");
  const guard = createOutputGuard(() => SIZE);
  const long = `${ESC}[` + "1;".repeat(MAX_PENDING);
  assert.equal(guard.pieces(long).join(""), long);
  assert.equal(guard.hasPending(), false);
});

test("writes are split into pieces of at most 2048 units without cutting a surrogate pair", async () => {
  const { splitPieces, MAX_PIECE } = await import(BASE + "guard.js");
  assert.deepEqual(splitPieces(""), []);
  assert.deepEqual(splitPieces("abc"), ["abc"]);
  const pieces = splitPieces("a".repeat(5000));
  assert.deepEqual(pieces.map((piece) => piece.length), [MAX_PIECE, MAX_PIECE, 5000 - 2 * MAX_PIECE]);
  const pair = "a".repeat(MAX_PIECE - 1) + "\u{1F600}" + "b";
  const cut = splitPieces(pair);
  assert.equal(cut.join(""), pair);
  assert.equal(cut[0].length, MAX_PIECE - 1);
});

test("the size of the terminal decides the clamp and a missing size falls back to the protocol maximum", async () => {
  const { clampCounts } = await import(BASE + "guard.js");
  assert.equal(clampCounts(`${ESC}[9000S`, { cols: 80, rows: 24 }).text, `${ESC}[24S`);
  assert.equal(clampCounts(`${ESC}[9000S`, {}).text, `${ESC}[200S`);
  assert.equal(clampCounts(`${ESC}[9000Z`, undefined).text, `${ESC}[500Z`);
  assert.equal(clampCounts(`${ESC}[99999b`, undefined).text, `${ESC}[16384b`);
  assert.equal(clampCounts(`${ESC}[99999b`, { cols: 133, rows: 37 }).text, `${ESC}[4921b`);
  assert.equal(clampCounts(`${ESC}[99b`, { cols: 133, rows: 37 }).text, `${ESC}[99b`);
});

test("pasted text loses every escape and every eight-bit control, whatever the fragments are", async () => {
  const { sanitizePaste } = await import(BASE + "keys.js");
  assert.equal(sanitizePaste("ls\nwhoami\ttab"), "ls\nwhoami\ttab");
  assert.equal(sanitizePaste(`${ESC}[2${ESC}[201~01~rm -rf /tmp/x\r`), "[2[201~01~rm -rf /tmp/x\r");
  assert.equal(sanitizePaste("a\u009b201~b"), "a201~b");
  assert.equal(sanitizePaste(`a${ESC}b`), "ab");
  assert.equal(sanitizePaste("\u0080\u0090\u009d\u009f"), "");
  const fragments = [ESC, "[", "2", "0", "1", "~", "\u009b"];
  let seed = 12345;
  const next = () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed;
  };
  for (let round = 0; round < 200; round += 1) {
    let text = "";
    for (let index = 0, length = 1 + (next() % 40); index < length; index += 1) {
      text += fragments[next() % fragments.length];
    }
    const cleaned = sanitizePaste(text);
    assert.equal(cleaned.includes(ESC + "[200~"), false);
    assert.equal(cleaned.includes(ESC + "[201~"), false);
    assert.equal(cleaned.includes("\u009b"), false);
    assert.equal(cleaned.includes(ESC), false);
  }
});

test("sticky modifiers apply to one typed character only", async () => {
  const { createModifiers } = await import(BASE + "keys.js");
  const modifiers = createModifiers();
  modifiers.toggle("ctrl");
  assert.equal(modifiers.applyToText("\u001b[I"), "\u001b[I");
  assert.equal(modifiers.applyToText("ab"), "ab");
  assert.equal(modifiers.state().ctrl, true);
  assert.equal(modifiers.applyToText("c"), "\u0003");
  assert.equal(modifiers.state().ctrl, false);
  modifiers.toggle("alt");
  assert.equal(modifiers.applyToText("x"), "\u001bx");
  assert.equal(modifiers.applyToText("x"), "x");
});

function parserTerminal(size) {
  const registered = [];
  return {
    cols: size.cols,
    rows: size.rows,
    registered,
    parser: { registerCsiHandler: (identifier, handler) => registered.push({ identifier, handler }) },
  };
}

test("the parser handlers swallow a first parameter above the limit at the moment of the call and let the rest through", async () => {
  const { installCountLimits } = await import(BASE + "guard.js");
  const terminal = parserTerminal({ cols: 100, rows: 30 });
  installCountLimits(terminal);
  const decide = (final, params) => terminal.registered.find((entry) => entry.identifier.final === final).handler(params);
  assert.deepEqual(terminal.registered.map((entry) => entry.identifier.final).sort(), ["@", "L", "M", "P", "S", "T", "X", "Z", "b"]);
  assert.equal(terminal.registered.every((entry) => Object.keys(entry.identifier).join() === "final"), true);
  for (const final of ["S", "T", "L", "M"]) {
    assert.equal(decide(final, [30]), false, final);
    assert.equal(decide(final, [29]), false, final);
    assert.equal(decide(final, [31]), true, final);
    assert.equal(decide(final, [4999]), true, final);
    assert.equal(decide(final, [[4999, 1]]), true, final);
    assert.equal(decide(final, [1, 4999]), false, final);
    assert.equal(decide(final, []), false, final);
    assert.equal(decide(final, [0]), false, final);
  }
  for (const final of ["Z", "@", "P", "X"]) {
    assert.equal(decide(final, [100]), false, final);
    assert.equal(decide(final, [101]), true, final);
  }
  assert.equal(decide("b", [3000]), false);
  assert.equal(decide("b", [3001]), true);
  terminal.rows = 50;
  assert.equal(decide("L", [31]), false);
  assert.equal(decide("L", [51]), true);
  assert.equal(decide("b", [5000]), false);
  terminal.cols = 120;
  assert.equal(decide("P", [101]), false);
  assert.equal(decide("P", [121]), true);
  assert.equal(decide("b", [6001]), true);
  terminal.rows = 500;
  assert.equal(decide("b", [16384]), false);
  assert.equal(decide("b", [16385]), true);
});

test("a terminal without a size is held to the protocol maximum", async () => {
  const { installCountLimits } = await import(BASE + "guard.js");
  const terminal = parserTerminal({});
  installCountLimits(terminal);
  const decide = (final, count) => terminal.registered.find((entry) => entry.identifier.final === final).handler([count]);
  assert.equal(decide("L", 200), false);
  assert.equal(decide("L", 201), true);
  assert.equal(decide("P", 501), true);
});
