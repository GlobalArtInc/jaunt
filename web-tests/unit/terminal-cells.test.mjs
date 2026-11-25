import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { installDom } from "./support.mjs";
import { fakePrintPath, loadXterm } from "./terminal-support.mjs";

const JS = "../../crates/jaunt-web/assets/assets/js/";
const CELLS = JS + "terminal/cells.js";
const ADAPTER = JS + "recording/terminal.js";
const ESC = "\u001b";
const VS = (count) => String.fromCodePoint(...Array.from({ length: count }, (_, index) => 0xe0100 + index));
const marks = (count, from = 0x300) => String.fromCodePoint(...Array.from({ length: count }, (_, index) => from + index));
const LEGIT = [
  "สว\u0e31สด\u0e35คร\u0e31บ ก\u0e49ำ ท\u0e35\u0e48น\u0e35\u0e48",
  "ب\u0650س\u0652م\u0650 ٱلل\u064e\u0651ه\u0650 ٱلر\u064e\u0651ح\u0652م\u064eـ\u0670ن\u0650",
  "ש\u05b8\u05c1לו\u05b9ם",
  "क\u094dषत\u094dर\u093fय ह\u093fन\u094dद\u0940 नमस\u094dत\u0947 क\u093c",
  "தம\u0bbfழ\u0bcd",
  "Tiếng Việt ệ ả\u0302 ớ",
  "\u{1f468}\u200d\u{1f469}\u200d\u{1f467}\u200d\u{1f466}",
  "\u{1f9d1}\u{1f3fd}\u200d\u{1f91d}\u200d\u{1f9d1}\u{1f3fb}",
  "❤\ufe0f\u200d\u{1f525} ☺\ufe0f ✔\ufe0f 1\ufe0f\u20e3",
  "\u{1f1e9}\u{1f1ea}\u{1f1ef}\u{1f1f5}",
  "\u{1f3f4}\u{e0067}\u{e0062}\u{e0065}\u{e006e}\u{e0067}\u{e007f}",
  "葛\u{e0100} 辻\u{e0101}",
  "한글 각",
  `${ESC}[1;31mred${ESC}[0m é ${ESC}]0;title ${"\u0301".repeat(20)}\u0007done\r\n\tnext`,
];

const hooked = loadXterm();
const raw = loadXterm();

function create(xterm, options = {}) {
  return new xterm.libraries.Terminal({ cols: 80, rows: 6, logLevel: "off", ...options });
}

async function limited(budget, options) {
  const { installCellLimit } = await import(CELLS);
  const terminal = create(hooked, options);
  installCellLimit(terminal, typeof budget === "function" ? budget : () => budget);
  return terminal;
}

function write(terminal, text) {
  return new Promise((resolve) => terminal.write(text, resolve));
}

async function writeAll(terminal, parts) {
  for (const part of parts) {
    if (typeof part === "function") {
      part(terminal);
    } else {
      await write(terminal, part);
    }
  }
}

function widest(terminal) {
  const buffer = terminal.buffer.active;
  let units = 0;
  let points = 0;
  for (let y = 0; y < buffer.length; y += 1) {
    const line = buffer.getLine(y);
    for (let x = 0; x < terminal.cols; x += 1) {
      const chars = line.getCell(x).getChars();
      units = Math.max(units, chars.length);
      points = Math.max(points, Array.from(chars).length);
    }
  }
  return { units, points };
}

function snapshot(terminal) {
  const buffer = terminal.buffer.active;
  const rows = [];
  for (let y = 0; y < buffer.length; y += 1) {
    const line = buffer.getLine(y);
    const cells = [];
    for (let x = 0; x < terminal.cols; x += 1) {
      const cell = line.getCell(x);
      cells.push([cell.getChars(), cell.getWidth(), cell.getFgColorMode(), cell.getFgColor(), cell.getBgColorMode(), cell.getBgColor(), cell.isBold(), cell.isItalic(), cell.isUnderline(), cell.isInverse()].join(","));
    }
    rows.push(line.isWrapped + ":" + cells.join("|"));
  }
  return { rows, cursor: [buffer.cursorX, buffer.cursorY, buffer.baseY] };
}

test("the vendored terminal prints through its handler and grows a cell in one place, and the limit takes hold there", async () => {
  const terminal = create(hooked);
  const handler = terminal._core._inputHandler;
  const store = Object.getPrototypeOf(terminal._core.buffers.normal.lines.get(0));
  assert.equal(typeof handler.print, "function");
  assert.equal(Object.hasOwn(handler, "print"), false);
  assert.equal(typeof handler._parser._printHandler, "function");
  for (const name of ["addCodepointToCell", "getString", "getWidth", "loadCell", "setCell"]) {
    assert.equal(typeof store[name], "function", name);
  }
  const { installCellLimit } = await import(CELLS);
  installCellLimit(terminal, () => 8);
  installCellLimit(terminal, () => 8);
  assert.equal(Object.hasOwn(handler, "print"), true);
  await write(terminal, "e" + marks(63));
  assert.deepEqual(widest(terminal), { units: 7, points: 7 });
});

test("a terminal whose print path or cell store cannot be found is refused, so nothing runs unprotected", async () => {
  const { installCellLimit, isUnsafeTerminalError } = await import(CELLS);
  const shaped = (change) => {
    const core = fakePrintPath();
    change(core);
    return { _core: core };
  };
  const broken = {
    "no core": {},
    "no input handler": { _core: {} },
    "print already replaced": shaped((core) => {
      core._inputHandler.print = () => undefined;
    }),
    "no print handler on the parser": shaped((core) => {
      core._inputHandler._parser = {};
    }),
    "a parser that prints elsewhere": shaped((core) => {
      core._inputHandler._parser._printHandler = () => undefined;
    }),
    "no buffers": shaped((core) => {
      delete core.buffers;
    }),
    "lines without the cell methods": shaped((core) => {
      core.buffers.normal.lines.get = () => ({});
    }),
    "lines that cannot write a cell back": shaped((core) => {
      const line = core.buffers.normal.lines.get(0);
      Object.getPrototypeOf(line).setCell = undefined;
    }),
  };
  for (const [name, terminal] of Object.entries(broken)) {
    assert.throws(() => installCellLimit(terminal, () => 8), (error) => isUnsafeTerminalError(error) && /cannot start safely/.test(error.message), name);
  }
  const probed = fakePrintPath();
  probed._inputHandler._parser._printHandler = () => undefined;
  assert.throws(() => installCellLimit({ _core: probed }));
  assert.equal(probed._inputHandler.print, Object.getPrototypeOf(probed._inputHandler).print);
  const working = { _core: fakePrintPath() };
  installCellLimit(working, () => 8);
  assert.equal(Object.hasOwn(working._core._inputHandler, "print"), true);
});

test("the player and the live terminal refuse to start, dispose the terminal and never open it when the print path is missing", async () => {
  const dom = installDom();
  const { createInteractiveTerminal, createTerminalSink } = await import(ADAPTER);
  const { isUnsafeTerminalError } = await import(CELLS);
  const log = { created: 0, opened: 0, disposed: 0 };
  class Terminal {
    constructor() {
      log.created += 1;
    }

    open() {
      log.opened += 1;
    }

    loadAddon() {}

    dispose() {
      log.disposed += 1;
    }
  }
  const libraries = { Terminal, CanvasAddon: class {} };
  const container = document.createElement("div");
  assert.throws(() => createTerminalSink({ container, cols: 80, rows: 24, libraries }), isUnsafeTerminalError);
  assert.throws(() => createInteractiveTerminal({ container, cols: 80, rows: 24, libraries, onInput() {}, onReply() {} }), isUnsafeTerminalError);
  assert.deepEqual(log, { created: 2, opened: 0, disposed: 2 });
  dom.window.close();
});

test("the player sink and the live terminal built from the vendored library both hold a cell to six marks", async () => {
  const { createInteractiveTerminal, createTerminalSink, createGuardedWriter } = await import(ADAPTER);
  const { document } = hooked;
  const sink = createTerminalSink({ container: document.body.appendChild(document.createElement("div")), cols: 80, rows: 6, libraries: hooked.libraries, doc: document });
  for (const part of ["e" + marks(21), marks(21, 0x315), marks(21, 0x32a)]) {
    sink.write(part);
  }
  await sink.idle();
  assert.equal(widest(sink.terminal).points, 7);
  const live = createInteractiveTerminal({ container: document.body.appendChild(document.createElement("div")), cols: 80, rows: 6, libraries: hooked.libraries, doc: document, onInput() {}, onReply() {} });
  const writer = createGuardedWriter(live, { setTimeout: () => 0, clearTimeout() {} });
  const bytes = new TextEncoder().encode("e" + marks(63));
  for (let offset = 0; offset < bytes.length; offset += 5) {
    writer.write(bytes.subarray(offset, offset + 5));
  }
  await write(live, "");
  assert.equal(widest(live).points, 7);
  for (const terminal of [sink.terminal, live]) {
    assert.equal(Object.hasOwn(terminal._core._inputHandler, "print"), true);
    assert.equal(Object.hasOwn(terminal._core._renderService, "_renderRows"), true);
  }
  sink.dispose();
  writer.dispose();
  live.dispose();
});

test("the live terminal keeps a budget for its largest font, the player for its fixed font, both at the current device pixel ratio", async () => {
  const { createInteractiveTerminal, createTerminalSink } = await import(ADAPTER);
  const { document } = hooked;
  const cellWide = (terminal, width) => {
    terminal.element.querySelector(".xterm-screen").getBoundingClientRect = () => ({ width: width * terminal.cols, height: 17 * terminal.rows });
  };
  const sink = createTerminalSink({ container: document.body.appendChild(document.createElement("div")), cols: 80, rows: 6, libraries: hooked.libraries, doc: document });
  const live = createInteractiveTerminal({ container: document.body.appendChild(document.createElement("div")), cols: 80, rows: 6, libraries: hooked.libraries, doc: document, onInput() {}, onReply() {} });
  cellWide(sink.terminal, 8.43);
  cellWide(live, 8.43);
  assert.equal(live.options.fontSize, 14);
  assert.equal(sink.terminal.options.fontSize, 14);
  try {
    for (const [ratio, player, terminal] of [[3, 6, 4], [1, 6, 6], [4, 6, 3], [2, 6, 6]]) {
      Object.defineProperty(globalThis, "devicePixelRatio", { configurable: true, value: ratio });
      sink.write(ESC + "c" + "W" + VS(6));
      await sink.idle();
      await write(live, ESC + "c" + "W" + VS(6));
      assert.equal(sink.terminal.buffer.active.getLine(0).getCell(0).getChars(), "W" + VS(player), "sink at " + ratio);
      assert.equal(live.buffer.active.getLine(0).getCell(0).getChars(), "W" + VS(terminal), "live at " + ratio);
    }
  } finally {
    Reflect.deleteProperty(globalThis, "devicePixelRatio");
    sink.dispose();
    live.dispose();
  }
});

test("output written at the smallest font of the live terminal still fits the device cell of its largest font", async () => {
  const { createInteractiveTerminal } = await import(ADAPTER);
  const { FONT_SIZES, LARGEST_FONT_SIZE } = await import(JS + "terminal/fonts.js");
  const { document } = hooked;
  const characterWidth = { 14: 8.43, 24: 14.45 };
  const live = createInteractiveTerminal({ container: document.body.appendChild(document.createElement("div")), cols: 80, rows: 6, libraries: hooked.libraries, doc: document, fontSize: FONT_SIZES[0], onInput() {}, onReply() {} });
  live.element.querySelector(".xterm-screen").getBoundingClientRect = () => ({ width: characterWidth[live.options.fontSize] * live.cols, height: 17 * live.rows });
  assert.equal(LARGEST_FONT_SIZE, 24);
  try {
    for (const ratio of [3, 4]) {
      Object.defineProperty(globalThis, "devicePixelRatio", { configurable: true, value: ratio });
      const allowed = Math.floor(506 / Math.floor(characterWidth[24] * ratio));
      for (const form of ["W" + VS(6), "\u{20000}" + VS(6), "e" + marks(6)]) {
        live.options.fontSize = FONT_SIZES[0];
        await write(live, ESC + "c" + form);
        const stored = live.buffer.active.getLine(0).getCell(0).getChars().length;
        live.options.fontSize = LARGEST_FONT_SIZE;
        assert.equal(stored <= allowed, true, `${ratio}: ${stored} units stored, ${allowed} fit at ${LARGEST_FONT_SIZE} px`);
      }
    }
  } finally {
    Reflect.deleteProperty(globalThis, "devicePixelRatio");
    live.dispose();
  }
});

test("marks that xterm keeps joining to one cell stop at the cap whatever separates them", async () => {
  const families = {
    "one run": ["e" + marks(63)],
    "three writes": ["e" + marks(21), marks(21, 0x315), marks(21, 0x32a)],
    "escape and a swallowed letter": ["e" + marks(6) + (ESC + "é" + marks(6)).repeat(10)],
    "a lone string terminator": ["e" + marks(6) + ("\u009c" + marks(6)).repeat(10)],
    "a malformed csi": ["e" + marks(6) + (ESC + "[!1m" + marks(6)).repeat(10)],
    "an application string cut by a letter": [ESC + "_é" + "e" + marks(63)],
    "a privacy message cut by a letter": [ESC + "^é" + "e" + marks(63)],
    "a start of string cut by a letter": [ESC + "Xé" + "e" + marks(63)],
    "a device control string cut by a letter": [ESC + "Pé" + "e" + marks(63)],
    "an eight-bit application string": ["\u009fé" + "e" + marks(63)],
    "ideographic tone marks": ["e" + "\u302e".repeat(300)],
    "a wide character dropped at the margin": [ESC + "[?7l" + ESC + "[1;79H" + "e" + marks(6), ESC + "[1;80H" + "日" + marks(20)],
    "repeat of the last character": ["e" + marks(30) + ESC + "[5b"],
    "a resize between base and marks": ["abcdefghij", (terminal) => terminal.resize(5, 6), marks(40)],
  };
  for (const [name, parts] of Object.entries(families)) {
    const reference = create(raw);
    await writeAll(reference, parts);
    const terminal = await limited(8);
    await writeAll(terminal, parts);
    assert.equal(widest(reference).points > 7, true, name + " must overfill a cell in the raw terminal");
    const { units, points } = widest(terminal);
    assert.equal(points <= 7 && units <= 8, true, `${name}: ${points} code points, ${units} units`);
  }
});

test("a refused mark still changes the cell width exactly as xterm would, so later output lands in the same place as in the raw terminal", async () => {
  const parts = [ESC + "[?7l" + ESC + "[1;79H" + "e" + marks(6), ESC + "[1;80H" + "日" + marks(20), ESC + "[1;80H" + "日" + marks(3, 0x340), "x" + marks(2, 0x350)];
  const reference = create(raw);
  const terminal = await limited(8);
  for (const part of parts) {
    await write(reference, part);
    await write(terminal, part);
    const ours = terminal.buffer.active.getLine(0).getCell(78);
    const theirs = reference.buffer.active.getLine(0).getCell(78);
    assert.equal(ours.getWidth(), theirs.getWidth(), JSON.stringify(part));
    assert.equal(theirs.getChars().startsWith(ours.getChars()), true, JSON.stringify(part));
    assert.deepEqual(snapshot(terminal).cursor, snapshot(reference).cursor);
  }
});

test("a cell holds at most as many UTF-16 units as the budget, a supplementary mark counting two", async () => {
  const cases = [
    [8, "W" + VS(6), "W" + VS(3)],
    [4, "W" + VS(6), "W" + VS(1)],
    [14, "W" + VS(6), "W" + VS(6)],
    [4, "W\u0301\u0302\u0303\u0304", "W\u0301\u0302\u0303"],
    [2, "W\u0301\u0302", "W\u0301"],
    [1, "W\u0301", "W"],
    [0, "W\u0301", "W"],
    [4, "\u{1f600}\u0301\u0302\u0303", "\u{1f600}\u0301\u0302"],
    [8, "W" + VS(3) + "\u0301" + VS(1), "W" + VS(3) + "\u0301"],
    [9, "W" + VS(3) + "\u0301\u0302" + VS(1), "W" + VS(3) + "\u0301\u0302"],
    [8, "W" + VS(4) + "\u0301", "W" + VS(3) + "\u0301"],
    [Number.NaN, "W\u0301", "W"],
  ];
  for (const [budget, text, kept] of cases) {
    const terminal = await limited(budget);
    await write(terminal, text);
    assert.equal(terminal.buffer.active.getLine(0).getCell(0).getChars(), kept, `${budget} ${JSON.stringify(text)}`);
  }
});

test("a terminal of the same library that never got the limit still holds a cell to the default budget", async () => {
  const { installCellLimit } = await import(CELLS + "?isolated");
  const realm = loadXterm();
  const neighbour = create(realm);
  installCellLimit(neighbour, () => 54);
  await write(neighbour, "W" + VS(6));
  assert.equal(neighbour.buffer.active.getLine(0).getCell(0).getChars(), "W" + VS(6));
  const bystander = create(realm);
  await write(bystander, "W" + VS(6) + "\r\ne" + marks(63));
  assert.equal(bystander.buffer.active.getLine(0).getCell(0).getChars(), "W" + VS(3));
  assert.deepEqual(widest(bystander), { units: 7, points: 7 });
});

test("the budget is asked for once per print call and only when a character joins a cell, so a change applies to the next write", async () => {
  let asked = 0;
  let budget = 8;
  const terminal = await limited(() => {
    asked += 1;
    return budget;
  });
  await write(terminal, "plain text only, no marks\r\n");
  assert.equal(asked, 0);
  await write(terminal, "e\u0301 a\u0302 o\u0303\r\n");
  assert.equal(asked, 1);
  await write(terminal, "W" + VS(6) + "\r\n");
  budget = 5;
  await write(terminal, "W" + VS(6));
  assert.equal(asked, 3);
  assert.equal(terminal.buffer.active.getLine(2).getCell(0).getChars(), "W" + VS(3));
  assert.equal(terminal.buffer.active.getLine(3).getCell(0).getChars(), "W" + VS(2));
});

test("legitimate text in many scripts renders exactly as in the raw terminal", async () => {
  for (const sample of LEGIT) {
    const reference = create(raw);
    await write(reference, sample);
    const terminal = await limited(49);
    await write(terminal, sample);
    assert.deepEqual(snapshot(terminal), snapshot(reference), JSON.stringify(sample));
  }
});

test("the limit refuses exactly the code points that xterm joins to a cell, over every code point from U+00A0", async () => {
  const rows = 2048;
  const reference = create(raw);
  const terminal = await limited(64, { cols: 4, rows });
  const unicode = reference._core._inputHandler._unicodeService;
  const full = "a" + "\u0301".repeat(6);
  const points = [];
  for (let code = 0xa0; code <= 0x10ffff; code += 1) {
    if (code < 0xd800 || code > 0xdfff) {
      points.push(code);
    }
  }
  const wrong = [];
  let joined = 0;
  for (let start = 0; start < points.length; start += rows) {
    const batch = points.slice(start, start + rows);
    await write(terminal, ESC + "c" + batch.map((code, row) => `${ESC}[${row + 1};1H${full}${String.fromCodePoint(code)}`).join("") + "\r");
    const buffer = terminal.buffer.active;
    batch.forEach((code, row) => {
      const line = buffer.getLine(buffer.baseY + row);
      const refused = line.getCell(0).getChars() === full && line.getCell(1).getChars() === "";
      const zero = unicode.wcwidth(code) === 0;
      joined += zero ? 1 : 0;
      if (refused !== zero) {
        wrong.push(code.toString(16));
      }
    });
  }
  assert.deepEqual(wrong.slice(0, 20), []);
  assert.equal(joined, 1187);
});

test("the guard modules carry no width table or mark predicate of their own", () => {
  for (const file of ["terminal/cells.js", "terminal/guard.js", "recording/terminal.js"]) {
    const source = readFileSync(new URL(JS + file, import.meta.url), "utf8");
    for (const needle of ["\\p{", "\\u0300", "0x300", "0x0300", "wcwidth", "\\u200b", "0x200b"]) {
      assert.equal(source.toLowerCase().includes(needle.toLowerCase()), false, `${file} contains ${needle}`);
    }
  }
});

test("DEL never changes what the terminal shows, so the guard drops every one of them", async () => {
  const { createOutputGuard } = await import(JS + "terminal/guard.js");
  const samples = ["a\u007fb", `${ESC}\u007f[\u007f3\u007f1m\u007fx`, `${ESC}]0;t\u007fi\u0007y`, `${ESC}Pq\u007f${ESC}\\z`, `${ESC}_a\u007f${ESC}\\w`, `${ESC}[?\u007f7l\u007fv`, "e\u007f\u0301\u007f\u0302"];
  for (const sample of samples) {
    const withDel = create(raw);
    const without = create(raw);
    await write(withDel, sample);
    await write(without, sample.replaceAll("\u007f", ""));
    assert.deepEqual(snapshot(withDel), snapshot(without), JSON.stringify(sample));
  }
  const guard = createOutputGuard(() => ({ cols: 80, rows: 24 }));
  assert.deepEqual(guard.pieces(`${ESC}[\u007f5000\u007fL${ESC}\u007f[4999S\u009b\u007f4999T`), [`${ESC}[24L${ESC}[24S\u009b24T`]);
  const started = performance.now();
  assert.deepEqual(guard.pieces("\u007f".repeat(65536)), []);
  assert.equal(performance.now() - started < 100, true);
});

test("the number of code units a cell may hold follows the device cell width scaled to the largest font and the atlas page, read again on every call", async () => {
  const { cellUnitsLimit, DEFAULT_CELL_UNITS } = await import(CELLS);
  const dom = installDom();
  const terminalWith = (state) => {
    const element = document.createElement("div");
    const screen = document.createElement("div");
    screen.className = "xterm-screen";
    screen.getBoundingClientRect = () => ({ width: state.width * 80, height: 340 });
    element.appendChild(screen);
    return { cols: 80, rows: 20, element, options: state };
  };
  const scope = { devicePixelRatio: 1 };
  const state = { width: 8.4, fontSize: 14 };
  const current = cellUnitsLimit(terminalWith(state), { scope });
  const largest = cellUnitsLimit(terminalWith(state), { scope, largestFont: 24 });
  const rows = [];
  for (const ratio of [1, 2, 3, 4]) {
    scope.devicePixelRatio = ratio;
    rows.push([ratio, current(), largest()]);
  }
  assert.deepEqual(rows, [[1, 49, 30], [2, 27, 16], [3, 18, 10], [4, 14, 8]]);
  state.width = 14.4;
  state.fontSize = 24;
  assert.equal(largest(), 8);
  assert.equal(cellUnitsLimit(terminalWith(state), { scope, largestFont: 14 })(), 8);
  scope.devicePixelRatio = 1;
  assert.equal(cellUnitsLimit(terminalWith(state), { scope, largestFont: 14 })(), 30);
  scope.devicePixelRatio = 4;
  state.width = 400;
  assert.equal(current(), 0);
  scope.devicePixelRatio = Number.NaN;
  state.width = 8.4;
  state.fontSize = 14;
  assert.equal(current(), 49);
  assert.equal(largest(), 30);
  assert.equal(cellUnitsLimit({ cols: 80, rows: 20 }, { scope })(), DEFAULT_CELL_UNITS);
  assert.equal(cellUnitsLimit(terminalWith({ width: 8.4 }), { scope, largestFont: 24 })(), DEFAULT_CELL_UNITS);
  assert.equal(DEFAULT_CELL_UNITS, 8);
  dom.window.close();
});

test("a painted row is cut to the budget of the cell width it is painted at, scrollback only when it is scrolled into view", async () => {
  const { installCellLimit, installPaintLimit } = await import(CELLS);
  const { document } = hooked;
  const terminal = create(hooked, { rows: 4, scrollback: 50 });
  installCellLimit(terminal, () => 54);
  terminal.open(document.body.appendChild(document.createElement("div")));
  let budget = 54;
  let painted = 0;
  installPaintLimit(terminal, () => {
    painted += 1;
    return budget;
  });
  await write(terminal, "W" + VS(6) + "\r\n" + "\r\n".repeat(10) + "W" + VS(6) + "\r\ne" + marks(6));
  const render = terminal._core._renderService;
  const cell = (y) => terminal.buffer.active.getLine(y).getCell(0).getChars();
  const last = terminal.buffer.active.length - 1;
  budget = 7;
  render._renderRows(0, terminal.rows - 1);
  assert.equal(painted > 0, true);
  assert.equal(cell(last - 1), "W" + VS(3));
  assert.equal(cell(last), "e" + marks(6));
  assert.equal(cell(0), "W" + VS(6));
  terminal.scrollToTop();
  render._renderRows(0, terminal.rows - 1);
  assert.equal(cell(0), "W" + VS(3));
  budget = 3;
  terminal.scrollToBottom();
  render._renderRows(terminal.rows - 1, terminal.rows - 1);
  assert.equal(cell(last), "e" + marks(2));
  assert.equal(cell(last - 1), "W" + VS(3));
  terminal.dispose();
});

test("the paint budget follows the renderer's device cell width, read again on every call", async () => {
  const { paintUnitsLimit, DEFAULT_CELL_UNITS } = await import(CELLS);
  const cell = { width: 57 };
  const terminal = { _core: { _renderService: { dimensions: { device: { cell } } } } };
  const limit = paintUnitsLimit(terminal);
  const table = [[57, 8], [43, 11], [14, 32], [8, 54], [115, 4], [260, 1], [600, 0], [0, Number.POSITIVE_INFINITY], [Number.NaN, DEFAULT_CELL_UNITS], [-3, DEFAULT_CELL_UNITS], [undefined, DEFAULT_CELL_UNITS]];
  for (const [width, units] of table) {
    cell.width = width;
    assert.equal(limit(), units, String(width));
  }
  for (const core of [{}, { _renderService: {} }, { _renderService: { dimensions: { device: {} } } }]) {
    assert.equal(paintUnitsLimit({ _core: core })(), DEFAULT_CELL_UNITS);
  }
});

test("every terminal shares one limit on the cell store, however many are built and thrown away", async () => {
  const { createInteractiveTerminal, createTerminalSink } = await import(ADAPTER);
  const realm = loadXterm();
  const { document } = realm;
  const first = createInteractiveTerminal({ container: document.body.appendChild(document.createElement("div")), cols: 20, rows: 4, libraries: realm.libraries, doc: document, onInput() {}, onReply() {} });
  const store = Object.getPrototypeOf(first._core.buffers.normal.lines.get(0));
  const limited = store.addCodepointToCell;
  first.dispose();
  for (let round = 0; round < 25; round += 1) {
    const live = createInteractiveTerminal({ container: document.body.appendChild(document.createElement("div")), cols: 20, rows: 4, libraries: realm.libraries, doc: document, onInput() {}, onReply() {} });
    const sink = createTerminalSink({ container: document.body.appendChild(document.createElement("div")), cols: 20, rows: 4, libraries: realm.libraries, doc: document });
    live.dispose();
    sink.dispose();
  }
  assert.equal(store.addCodepointToCell, limited);
  const line = first._core.buffers.normal.lines.get(0);
  const reads = { count: 0 };
  const getString = store.getString;
  store.getString = function counted(index) {
    reads.count += 1;
    return getString.call(this, index);
  };
  try {
    line.setCellFromCodepoint(0, 0x65, 1, first._core._inputHandler._curAttrData);
    line.addCodepointToCell(0, 0x301, 1);
  } finally {
    store.getString = getString;
  }
  assert.equal(reads.count, 1);
  assert.equal(line.getString(0), "e\u0301");
});

test("the limited paint still hands every row to the renderer", async () => {
  const { installPaintLimit } = await import(CELLS);
  const { document } = hooked;
  const terminal = create(hooked, { rows: 4 });
  terminal.open(document.body.appendChild(document.createElement("div")));
  installPaintLimit(terminal, () => 8);
  const painted = [];
  const listener = terminal._core._renderService.onRender((range) => painted.push([range.start, range.end]));
  terminal._core._renderService._renderDebouncer._renderCallback(1, 2);
  terminal._core._renderService._renderRows(0, 3);
  listener.dispose();
  terminal.dispose();
  assert.deepEqual(painted, [[1, 2], [0, 3]]);
});

test("a terminal whose paint path cannot be found is refused", async () => {
  const { installPaintLimit, isUnsafeTerminalError } = await import(CELLS);
  const shaped = (change) => {
    const core = fakePrintPath();
    change(core);
    return { _core: core };
  };
  const broken = {
    "no render service": shaped((core) => {
      delete core._renderService;
    }),
    "paint already replaced": shaped((core) => {
      core._renderService._renderRows = () => undefined;
    }),
    "a scheduler that paints elsewhere": shaped((core) => {
      core._renderService._renderDebouncer._renderCallback = () => undefined;
    }),
    "no device cell size": shaped((core) => {
      core._renderService.dimensions = {};
    }),
    "no screen buffer": shaped((core) => {
      delete core.buffer;
    }),
  };
  for (const [name, terminal] of Object.entries(broken)) {
    assert.throws(() => installPaintLimit(terminal, () => 8), isUnsafeTerminalError, name);
  }
  const working = { _core: fakePrintPath() };
  installPaintLimit(working, () => 8);
  installPaintLimit(working, () => 8);
  assert.equal(Object.hasOwn(working._core._renderService, "_renderRows"), true);
});
