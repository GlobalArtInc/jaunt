import { chromium } from "playwright";

import { startStub } from "./stub.mjs";

const TOTAL_CASES = Number(process.env.MARKS_CASES || 5200);
const SEED = Number(process.env.MARKS_SEED || 20261125);
const FIXED_LIMIT_MS = 500;
const SLOW_MS = Number(process.env.MARKS_SLOW_MS || 2000);
const HANG_MS = Number(process.env.MARKS_HANG_MS || 5000);
const SETUP_MS = 30000;
const CLOSE_MS = 5000;
const MAX_HANGS_PER_LANE = 3;
const RUN_LIMIT_MS = 6 * 60 * 1000;
const COLS = 80;
const ROWS = 24;
const ESC = "\u001b";
const LANES = [
  { name: "live dpr1 14px", surface: "live", deviceScaleFactor: 1, fontSize: 14 },
  { name: "live dpr4 24px", surface: "live", deviceScaleFactor: 4, fontSize: 24 },
  { name: "player dpr1 14px", surface: "player", deviceScaleFactor: 1, fontSize: 14 },
  { name: "player dpr4 24px", surface: "player", deviceScaleFactor: 4, fontSize: 24 },
];

const GROWTH = [
  { name: "live dpr3", surface: "live", deviceScaleFactor: 3 },
  { name: "live dpr4", surface: "live", deviceScaleFactor: 4 },
  { name: "player dpr3", surface: "player", deviceScaleFactor: 3 },
  { name: "player dpr4", surface: "player", deviceScaleFactor: 4 },
];
const SMALL_FONT = 14;
const marks = (count, from = 0x300) => String.fromCodePoint(...Array.from({ length: count }, (_, index) => from + index));
const six = (offset) => marks(6, 0x300 + offset * 6);
const repeated = (separator) => "e" + six(0) + Array.from({ length: 10 }, (_, index) => separator + six(index + 1)).join("");
const supplementary = String.fromCodePoint(0xe0100, 0xe0101, 0xe0102, 0xe0103, 0xe0104, 0xe0105);
const GROWTH_FORMS = [
  { name: "W and six supplementary variation selectors", text: "W" + supplementary },
  { name: "a wide base and six supplementary variation selectors", text: "\u{20000}" + supplementary },
  { name: "e and six marks", text: "e" + marks(6) },
  { name: "e and 63 marks", text: "e" + marks(63) },
];
const FIXED = [
  { name: "APC cut by a letter, then e and 63 marks", parts: [{ text: ESC + "_é" + "e" + marks(63) }] },
  { name: "SOS cut by a letter, then e and 63 marks", parts: [{ text: ESC + "Xé" + "e" + marks(63) }] },
  { name: "PM cut by a letter, then e and 63 marks", parts: [{ text: ESC + "^é" + "e" + marks(63) }] },
  { name: "DCS cut by a letter, then e and 63 marks", parts: [{ text: ESC + "Pé" + "e" + marks(63) }] },
  { name: "8-bit APC cut by a letter, then e and 63 marks", parts: [{ text: "\u009fé" + "e" + marks(63) }] },
  { name: "e, 6 marks and ten times (ESC e-acute, 6 marks)", parts: [{ text: repeated(ESC + "é") }] },
  { name: "e, 6 marks and ten times (U+009C, 6 marks)", parts: [{ text: repeated("\u009c") }] },
  { name: "e, 6 marks and ten times (ESC [ ! 1 m, 6 marks)", parts: [{ text: repeated(ESC + "[!1m") }] },
  { name: "e and 63 marks in three frames", parts: [{ text: "e" + marks(21) }, { text: marks(21, 0x315) }, { text: marks(21, 0x32a) }] },
  { name: "e and 300 ideographic tone marks", parts: [{ text: "e" + "\u302e".repeat(300) }] },
  { name: "W and six supplementary variation selectors", parts: [{ text: "W" + String.fromCodePoint(0xe0100, 0xe0101, 0xe0102, 0xe0103, 0xe0104, 0xe0105) }] },
  { name: "wide character dropped at the right margin", parts: [{ text: ESC + "[?7l" + ESC + "[1;79H" + "e" + marks(6) }, { text: ESC + "[1;80H" + "日" + marks(40) }] },
  { name: "resize between the base and its marks", parts: [{ text: "abcdefghij" }, { resize: [5, 24] }, { text: marks(40) }] },
];

function buildCase(seed, index) {
  let state = (Math.imul(seed ^ 0x9e3779b9, 0x85ebca6b) ^ Math.imul(index + 1, 0xc2b2ae35)) >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
  const int = (low, high) => low + Math.floor(next() * (high - low + 1));
  const pick = (list) => list[Math.floor(next() * list.length)];
  const esc = "\u001b";
  const markRanges = [
    [0x300, 0x36f], [0x483, 0x489], [0x591, 0x5bd], [0x610, 0x61a], [0x64b, 0x65f], [0x6de, 0x6de], [0xe31, 0xe31], [0xe34, 0xe3a], [0xe47, 0xe4e],
    [0x1734, 0x1734], [0x1ab0, 0x1aff], [0x1dc0, 0x1dff], [0x200b, 0x200f], [0x2060, 0x2064], [0x20d0, 0x20f0], [0x302a, 0x302f], [0x3099, 0x309a],
    [0xfe00, 0xfe0f], [0xfe20, 0xfe2f], [0xe0001, 0xe0001], [0xe0020, 0xe007f], [0xe0100, 0xe01ef], [0x1160, 0x11ff],
  ];
  const mark = () => {
    const [low, high] = pick(markRanges);
    return String.fromCodePoint(int(low, high));
  };
  const bases = ["e", "W", "a", "日", "ก", "ا", "क", "\u{1f600}", "é", "ᄀ", "\u00a0", " ", "~", "\u{20000}"];
  const runLength = () => {
    const roll = next();
    return roll < 0.45 ? int(1, 8) : roll < 0.85 ? int(9, 80) : int(81, 300);
  };
  const tokens = [
    [30, () => {
      let text = next() < 0.6 ? pick(bases) : "";
      const count = runLength();
      for (let step = 0; step < count; step += 1) text += mark();
      return text;
    }],
    [8, () => esc + pick(["[", "]", "P", "X", "^", "_", "N", "O", "\\", "c", "7", "(", "#", "%"])],
    [6, () => String.fromCharCode(next() < 0.5 ? pick([0x90, 0x98, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f]) : int(0x80, 0x9f))],
    [6, () => pick(["\u0007", esc + "\\", "\u009c", "\u0018", "\u001a", esc])],
    [4, () => String.fromCharCode(int(0, 0x1f))],
    [3, () => "\u007f".repeat(int(1, 3))],
    [4, () => pick(["\ud83d", "\ude00", "😀", "\udbff", "\udc00\ud800", "\u{1f1e9}\u{1f1ea}", "\ud800" + mark()])],
    [10, () => {
      const roll = next();
      if (roll < 0.4) return "abcdefghijklmnopqrstuvwxyz0123456789 ;[]".slice(int(0, 30), int(31, 40));
      if (roll < 0.7) return String.fromCharCode(int(0xa0, 0xff), int(0xa0, 0xff));
      return pick(["日本語", "\u{1f600}\u{1f468}\u200d\u{1f469}", "한국", "สว\u0e31สด\u0e35", "❤\ufe0f"]);
    }],
    [6, () => esc + String.fromCharCode(int(0xa0, 0xff))],
    [6, () => pick([esc + "[!1m", esc + "[1<m", esc + "[1;2$x", esc + "[1:2:3m", esc + "[1 1m", esc + "[?1<m", "\u009b1<m", esc + "[" + String.fromCharCode(int(0xa0, 0xff)), esc + "[1" + String.fromCharCode(int(0xa0, 0xff)), esc + "P1" + String.fromCharCode(int(0xa0, 0xff)), esc + "[1;" + esc + "[2m"])],
    [8, () => {
      const prefix = pick(["", "", "", "?", ">", "<", "="]);
      const params = Array.from({ length: int(0, 3) }, () => String(int(0, 120))).join(";");
      const intermediate = next() < 0.1 ? pick([" ", "$", "!", "'", '"']) : "";
      return (next() < 0.85 ? esc + "[" : "\u009b") + prefix + params + intermediate + pick("ABCDEFGHJKLMPSTXZ@`abcdfghlmnrsu".split(""));
    }],
    [4, () => esc + "[" + pick(["?7l", "?7h", "4h", "4l", "?1049h", "?1049l", "?6h", "?6l", "?25l", "3;20r", "r", "?2004h", "79G", "1;80H"])],
    [3, () => esc + pick(["7", "8", "D", "E", "M", "c", "#8", "(0", "(B", ")0", "=", ">", "H"])],
  ];
  const weight = tokens.reduce((sum, [share]) => sum + share, 0);
  const token = () => {
    let roll = next() * weight;
    for (const [share, make] of tokens) {
      roll -= share;
      if (roll < 0) return make();
    }
    return tokens[0][1]();
  };
  const parts = [];
  let text = "";
  const count = int(1, 24);
  for (let step = 0; step < count; step += 1) {
    if (text !== "" && next() < 0.03) {
      parts.push({ text });
      parts.push({ resize: [int(2, 120), int(1, 40)] });
      text = "";
    }
    text += token();
  }
  parts.push({ text });
  return parts.map((part) => (part.text === undefined ? part : { text: part.text, cuts: Array.from({ length: int(0, 4) }, () => next()).sort((a, b) => a - b) }));
}

async function setupLab({ surface, fontSize, cols, rows }) {
  const adapter = await import("/assets/js/recording/terminal.js");
  const { createOutputGuard } = await import("/assets/js/terminal/guard.js");
  const { cellUnitsLimit, MAX_MARKS } = await import("/assets/js/terminal/cells.js");
  const { installReplyPolicy } = await import("/assets/js/terminal/replies.js");
  const libraries = await adapter.loadTerminalLibraries();
  const frame = document.createElement("iframe");
  frame.hidden = true;
  document.body.appendChild(frame);
  await new Promise((resolve, reject) => {
    const script = frame.contentDocument.createElement("script");
    script.src = "/assets/vendor/xterm/xterm.js";
    script.addEventListener("load", resolve);
    script.addEventListener("error", () => reject(new Error("the reference terminal did not load")));
    frame.contentDocument.head.appendChild(script);
  });
  const host = document.createElement("div");
  document.body.prepend(host);
  let sink = null;
  let terminal;
  if (surface === "live") {
    terminal = adapter.createInteractiveTerminal({ container: host, cols, rows, libraries, fontSize, onInput() {}, onReply() {} });
  } else {
    sink = adapter.createTerminalSink({ container: host, cols, rows, libraries });
    terminal = sink.terminal;
    terminal.options.fontSize = fontSize;
  }
  terminal.options.logLevel = "off";
  const reference = new frame.contentWindow.Terminal({ cols, rows, scrollback: surface === "live" ? 5000 : 0, convertEol: false, allowProposedApi: false, windowOptions: {}, logLevel: "off" });
  adapter.neutralise(reference);
  installReplyPolicy(reference, { send() {}, now: () => 0 });
  const { LARGEST_FONT_SIZE, PLAYER_FONT_SIZE } = await import("/assets/js/terminal/fonts.js");
  const largestFont = sink === null ? LARGEST_FONT_SIZE : PLAYER_FONT_SIZE;
  const unitsLimit = cellUnitsLimit(terminal, { largestFont });
  const encoder = new TextEncoder();
  const settle = (target) => new Promise((resolve) => target.write("", resolve));
  const frames = () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  const fakeTimers = () => ({
    pending: new Map(),
    next: 1,
    setTimeout(callback) {
      const id = this.next;
      this.next += 1;
      this.pending.set(id, callback);
      return id;
    },
    clearTimeout(id) {
      this.pending.delete(id);
    },
    run() {
      const due = [...this.pending.values()];
      this.pending.clear();
      for (const callback of due) callback();
    },
  });
  const slices = (length, cuts) => {
    const points = [0, ...cuts.map((cut) => Math.floor(cut * length)), length];
    const out = [];
    for (let index = 1; index < points.length; index += 1) out.push([points[index - 1], points[index]]);
    return out;
  };
  const greedy = (chars, budget) => {
    let kept = "";
    let points = 0;
    for (const point of chars) {
      if (points === 0 || (kept.length + point.length <= budget && points <= MAX_MARKS)) {
        kept += point;
        points += 1;
      }
    }
    return kept;
  };
  const attributes = (cell) => [cell.getWidth(), cell.getFgColorMode(), cell.getFgColor(), cell.getBgColorMode(), cell.getBgColor(), cell.isBold(), cell.isItalic(), cell.isDim(), cell.isUnderline(), cell.isBlink(), cell.isInverse(), cell.isInvisible(), cell.isStrikethrough(), cell.isOverline()].join(",");
  const codes = (text) => Array.from(text, (point) => point.codePointAt(0).toString(16)).join(" ");

  function inspect(budget) {
    const result = { maxUnits: 0, maxPoints: 0, capped: false, diff: null };
    if (terminal.buffer.active.type !== reference.buffer.active.type) {
      result.diff = "active buffer " + terminal.buffer.active.type + " against " + reference.buffer.active.type;
    }
    const mine = terminal.buffer.active;
    const theirs = reference.buffer.active;
    if (result.diff === null && (mine.cursorX !== theirs.cursorX || mine.cursorY !== theirs.cursorY || mine.baseY !== theirs.baseY)) {
      result.diff = `cursor ${mine.cursorX},${mine.cursorY},${mine.baseY} against ${theirs.cursorX},${theirs.cursorY},${theirs.baseY}`;
    }
    for (const kind of ["normal", "alternate"]) {
      const ours = terminal.buffer[kind];
      const raw = reference.buffer[kind];
      if (result.diff === null && ours.length !== raw.length) {
        result.diff = `${kind} buffer has ${ours.length} lines against ${raw.length}`;
      }
      for (let y = 0; y < ours.length; y += 1) {
        const line = ours.getLine(y);
        const other = raw.getLine(y);
        if (result.diff === null && other && line.isWrapped !== other.isWrapped) {
          result.diff = `${kind} line ${y} wrapped ${line.isWrapped} against ${other.isWrapped}`;
        }
        for (let x = 0; x < terminal.cols; x += 1) {
          const cell = line.getCell(x);
          const chars = cell.getChars();
          result.maxUnits = Math.max(result.maxUnits, chars.length);
          result.maxPoints = Math.max(result.maxPoints, Array.from(chars).length);
          if (!other) continue;
          const rawCell = other.getCell(x);
          const rawChars = rawCell.getChars();
          const expected = greedy(rawChars, budget);
          if (expected !== rawChars) result.capped = true;
          if (result.diff === null && (chars !== expected || attributes(cell) !== attributes(rawCell))) {
            result.diff = `${kind} line ${y} column ${x}: [${codes(chars)}] ${attributes(cell)} against raw [${codes(rawChars)}] ${attributes(rawCell)}`;
          }
        }
      }
    }
    return result;
  }

  async function drain() {
    if (sink !== null) await sink.idle();
    else await settle(terminal);
    await settle(reference);
  }

  async function runCase(spec) {
    const parts = spec.fixed || window.__buildCase(spec.seed, spec.index);
    if (sink !== null) {
      sink.reset(cols, rows);
      await sink.idle();
    } else if (terminal.cols !== cols || terminal.rows !== rows) {
      terminal.resize(cols, rows);
    }
    if (reference.cols !== cols || reference.rows !== rows) reference.resize(cols, rows);
    terminal._core.writeSync("\u001bc");
    reference._core.writeSync("\u001bc");
    await drain();
    const liveTimers = fakeTimers();
    const referenceTimers = fakeTimers();
    const writer = sink === null ? adapter.createGuardedWriter(terminal, liveTimers) : null;
    const referenceWriter = sink === null ? adapter.createGuardedWriter(reference, referenceTimers) : null;
    const referenceGuard = createOutputGuard(() => ({ cols: reference.cols, rows: reference.rows }));
    const started = performance.now();
    for (const part of parts) {
      if (part.resize) {
        await drain();
        if (sink !== null) {
          sink.resize(part.resize[0], part.resize[1]);
          await sink.idle();
        } else {
          terminal.resize(part.resize[0], part.resize[1]);
        }
        reference.resize(part.resize[0], part.resize[1]);
        continue;
      }
      const cuts = part.cuts || [];
      if (sink === null) {
        const bytes = encoder.encode(part.text);
        for (const [from, to] of slices(bytes.length, cuts)) {
          writer.write(bytes.subarray(from, to));
          referenceWriter.write(bytes.subarray(from, to));
        }
      } else {
        for (const [from, to] of slices(part.text.length, cuts)) {
          const piece = part.text.slice(from, to);
          sink.write(piece);
          for (const guarded of referenceGuard.pieces(piece)) reference.write(guarded);
        }
      }
    }
    liveTimers.run();
    referenceTimers.run();
    await drain();
    await frames();
    const elapsed = performance.now() - started;
    if (writer !== null) {
      writer.dispose();
      referenceWriter.dispose();
    }
    const dimensions = terminal._core._renderService.dimensions;
    const deviceCell = dimensions && dimensions.device && dimensions.device.cell ? dimensions.device.cell.width : 0;
    const budget = unitsLimit();
    const result = inspect(budget);
    return { elapsed, deviceCell, allowed: deviceCell > 0 ? Math.floor(506 / deviceCell) : 0, budget, ...result };
  }

  function limits() {
    const deviceCell = terminal._core._renderService.dimensions.device.cell.width;
    const widest = inspect(Number.POSITIVE_INFINITY);
    return { deviceCell, allowed: deviceCell > 0 ? Math.floor(506 / deviceCell) : 0, budget: unitsLimit(), fontSize: terminal.options.fontSize, ratio: devicePixelRatio, maxUnits: widest.maxUnits, maxPoints: widest.maxPoints };
  }

  async function writeForm(text) {
    terminal.options.fontSize = fontSize;
    if (sink !== null) {
      sink.reset(cols, rows);
      await sink.idle();
    }
    terminal._core.writeSync("\u001bc");
    reference._core.writeSync("\u001bc");
    const form = text + "\u001b[" + rows + ";1H" + text;
    if (sink === null) {
      const writer = adapter.createGuardedWriter(terminal, fakeTimers());
      writer.write(encoder.encode(form));
      writer.dispose();
    } else {
      sink.write(form);
    }
    await drain();
    await frames();
    return limits();
  }

  async function growFont() {
    terminal.options.fontSize = largestFont;
    await frames();
    await frames();
    return limits();
  }

  async function settled() {
    await frames();
    await frames();
    return limits();
  }

  window.__lab = { runCase, writeForm, growFont, settled };
  return { deviceCell: terminal._core._renderService.dimensions.device.cell.width, budget: unitsLimit(), largestFont };
}

function withDeadline(promise, ms) {
  let timer;
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ timeout: true }), ms);
  });
  return Promise.race([promise.then((value) => ({ value }), (error) => ({ error: String((error && error.message) || error).slice(0, 300) })), deadline]).finally(() => clearTimeout(timer));
}

function describe(spec) {
  const parts = spec.fixed || buildCase(spec.seed, spec.index);
  return JSON.stringify(parts.map((part) => (part.resize ? { resize: part.resize } : Array.from(part.text, (point) => point.codePointAt(0).toString(16)).join(" ")))).slice(0, 1200);
}

function label(spec) {
  return spec.fixed ? `fixed case "${spec.name}"` : `seed ${spec.seed} index ${spec.index}`;
}

async function runLane(browser, stub, lane, laneIndex, perLane, kill) {
  const stats = { lane: lane.name, cases: 0, capped: 0, hangs: [], violations: [], diffs: [], slow: [], errors: [], fixed: [], slowest: { ms: 0, spec: null }, setup: null };
  let context = null;
  let page = null;
  let cdp = null;

  async function open() {
    context = await browser.newContext({ deviceScaleFactor: lane.deviceScaleFactor, viewport: { width: 1200, height: 800 } });
    page = await context.newPage();
    cdp = await context.newCDPSession(page);
    await page.goto(stub.origin + "/");
    await page.evaluate("window.__buildCase = " + buildCase.toString());
    const setup = await withDeadline(page.evaluate(setupLab, { surface: lane.surface, fontSize: lane.fontSize, cols: COLS, rows: ROWS }), SETUP_MS);
    if (!setup.value) throw new Error(`${lane.name}: the lab did not start: ${setup.error || "timeout"}`);
    stats.setup = setup.value;
  }

  async function recover() {
    await withDeadline(cdp.send("Runtime.terminateExecution"), 2000);
    const closed = await withDeadline(context.close(), CLOSE_MS);
    if (closed.timeout) kill(`${lane.name}: a hung page could not be closed`);
    await open();
  }

  await open();
  const specs = [...FIXED.map((entry) => ({ fixed: entry.parts, name: entry.name })), ...Array.from({ length: perLane }, (_, offset) => ({ seed: SEED, index: laneIndex * 1000000 + offset }))];
  for (const spec of specs) {
    const running = page.evaluate((value) => window.__lab.runCase(value), spec);
    running.catch(() => undefined);
    const outcome = await withDeadline(running, HANG_MS);
    stats.cases += 1;
    if (outcome.timeout) {
      stats.hangs.push(`${label(spec)} did not finish rendering within ${HANG_MS} ms: ${describe(spec)}`);
      if (stats.hangs.length >= MAX_HANGS_PER_LANE) {
        stats.errors.push(`stopped after ${stats.hangs.length} hangs`);
        await withDeadline(cdp.send("Runtime.terminateExecution"), 2000);
        break;
      }
      await recover();
      continue;
    }
    if (outcome.error) {
      stats.errors.push(`${label(spec)}: ${outcome.error}`);
      continue;
    }
    const result = outcome.value;
    if (result.capped) stats.capped += 1;
    if (result.elapsed > stats.slowest.ms) stats.slowest = { ms: result.elapsed, spec };
    if (spec.fixed) {
      stats.fixed.push(`${spec.name}: ${Math.round(result.elapsed)} ms, widest cell ${result.maxPoints} code points / ${result.maxUnits} units`);
      if (result.elapsed >= FIXED_LIMIT_MS) stats.slow.push(`${label(spec)} took ${Math.round(result.elapsed)} ms`);
    } else if (result.elapsed >= SLOW_MS) {
      stats.slow.push(`${label(spec)} took ${Math.round(result.elapsed)} ms: ${describe(spec)}`);
    }
    if (!(result.deviceCell > 0) || result.budget > result.allowed || result.maxUnits > result.allowed || result.maxPoints > 7) {
      stats.violations.push(`${label(spec)}: widest cell ${result.maxPoints} code points / ${result.maxUnits} units, allowed ${result.allowed} at device cell ${result.deviceCell} px, guard budget ${result.budget}: ${describe(spec)}`);
    }
    if (result.diff !== null) stats.diffs.push(`${label(spec)}${result.capped ? " (after a cut)" : ""}: ${result.diff}: ${describe(spec)}`);
  }
  await withDeadline(context.close(), CLOSE_MS);
  return stats;
}

async function runGrowth(browser, stub, config, kill) {
  const stats = { name: config.name, forms: [], hangs: [], violations: [], errors: [] };
  let context = null;
  let page = null;
  let cdp = null;
  const viewport = { width: 1200, height: 800 };

  async function open() {
    context = await browser.newContext({ deviceScaleFactor: config.deviceScaleFactor, viewport });
    page = await context.newPage();
    cdp = await context.newCDPSession(page);
    await page.goto(stub.origin + "/");
    await page.evaluate("window.__buildCase = " + buildCase.toString());
    const setup = await withDeadline(page.evaluate(setupLab, { surface: config.surface, fontSize: SMALL_FONT, cols: COLS, rows: ROWS }), SETUP_MS);
    if (!setup.value) throw new Error(`${config.name}: the lab did not start: ${setup.error || "timeout"}`);
  }

  async function step(name, run) {
    const running = run();
    running.catch(() => undefined);
    const outcome = await withDeadline(running, HANG_MS);
    if (outcome.timeout) {
      stats.hangs.push(name);
      await withDeadline(cdp.send("Runtime.terminateExecution"), 2000);
      const closed = await withDeadline(context.close(), CLOSE_MS);
      if (closed.timeout) kill(`${config.name}: a hung page could not be closed`);
      await open();
      return null;
    }
    if (outcome.error) {
      stats.errors.push(`${name}: ${outcome.error}`);
      return null;
    }
    return outcome.value;
  }

  const check = (name, result) => {
    if (result.maxUnits > result.allowed || result.maxPoints > 7) {
      stats.violations.push(`${name}: widest cell ${result.maxPoints} code points / ${result.maxUnits} units, allowed ${result.allowed} at device cell ${result.deviceCell} px`);
    }
  };

  const scale = (ratio, width) => cdp.send("Emulation.setDeviceMetricsOverride", { width, height: viewport.height, deviceScaleFactor: ratio, mobile: false });

  await open();
  for (const form of GROWTH_FORMS) {
    const label = `${config.name}, ${form.name}`;
    const written = await step(`${label}: written at ${SMALL_FONT} px`, () => page.evaluate((text) => window.__lab.writeForm(text), form.text));
    if (written === null) continue;
    const grown = await step(`${label}: font raised to the largest size`, () => page.evaluate(() => window.__lab.growFont()));
    if (grown === null) continue;
    check(`${label} after the font grew`, grown);
    await withDeadline(scale(config.deviceScaleFactor * 2, viewport.width + 1), 2000);
    const zoomed = await step(`${label}: device scale raised to ${config.deviceScaleFactor * 2}`, () => page.evaluate(() => window.__lab.settled()));
    if (zoomed === null) continue;
    if (!(zoomed.deviceCell > grown.deviceCell)) stats.errors.push(`${label}: the renderer kept a ${zoomed.deviceCell} px cell after the device scale grew`);
    check(`${label} after the device scale grew`, zoomed);
    stats.forms.push(`${form.name}: written ${written.maxUnits} units at ${written.fontSize} px (device cell ${written.deviceCell} px, budget ${written.budget}); font ${grown.fontSize} px: device cell ${grown.deviceCell} px, allowed ${grown.allowed}, widest ${grown.maxUnits}; device scale ${zoomed.ratio}: device cell ${zoomed.deviceCell} px, allowed ${zoomed.allowed}, widest ${zoomed.maxUnits}`);
    await withDeadline(scale(config.deviceScaleFactor, viewport.width), 2000);
    await step(`${label}: device scale restored`, () => page.evaluate(() => window.__lab.settled()));
  }
  await withDeadline(context.close(), CLOSE_MS);
  return stats;
}

async function main() {
  const started = Date.now();
  const stub = await startStub({ permissions: [] });
  const server = await chromium.launchServer();
  const child = server.process();
  const kill = (reason) => {
    console.error(reason);
    child.kill("SIGKILL");
    process.exit(1);
  };
  setTimeout(() => kill(`the oracle run exceeded ${RUN_LIMIT_MS / 1000} s and was stopped`), RUN_LIMIT_MS).unref();
  const browser = await chromium.connect(server.wsEndpoint());
  const perLane = Math.ceil(TOTAL_CASES / LANES.length);
  console.log(`marks oracle: seed ${SEED}, ${perLane} random cases and ${FIXED.length} fixed cases in each of ${LANES.length} lanes`);
  let lanes;
  let growth;
  try {
    lanes = await Promise.all(LANES.map((lane, index) => runLane(browser, stub, lane, index, perLane, kill)));
    growth = await Promise.all(GROWTH.map((config) => runGrowth(browser, stub, config, kill)));
  } catch (error) {
    kill(String((error && error.stack) || error));
  }
  await withDeadline(browser.close(), CLOSE_MS);
  await withDeadline(server.close(), CLOSE_MS);
  child.kill("SIGKILL");
  await stub.close();
  const failures = [];
  let cases = 0;
  let slowest = { ms: 0, where: "" };
  for (const stats of lanes) {
    cases += stats.cases;
    if (stats.slowest.ms > slowest.ms) slowest = { ms: stats.slowest.ms, where: `${stats.lane}, ${label(stats.slowest.spec)}` };
    console.log(`${stats.lane}: ${stats.cases} cases, device cell ${stats.setup.deviceCell} px, guard budget ${stats.setup.budget} units, ${stats.capped} cases cut by the limit, slowest ${Math.round(stats.slowest.ms)} ms, ${stats.hangs.length} hangs, ${stats.violations.length} cells over the limit, ${stats.diffs.length} differences from the raw terminal`);
    for (const line of stats.fixed) console.log("  " + line);
    for (const [kind, list] of [["hang", stats.hangs], ["over the limit", stats.violations], ["differs from raw", stats.diffs], ["slow", stats.slow], ["error", stats.errors]]) {
      for (const entry of list.slice(0, 5)) failures.push(`${stats.lane}: ${kind}: ${entry}`);
      if (list.length > 5) failures.push(`${stats.lane}: ${kind}: ${list.length - 5} more`);
    }
  }
  for (const stats of growth) {
    console.log(`growth ${stats.name}: ${stats.hangs.length} hangs, ${stats.violations.length} cells over the limit`);
    for (const line of stats.forms) console.log("  " + line);
    for (const [kind, list] of [["hang", stats.hangs], ["over the limit", stats.violations], ["error", stats.errors]]) {
      for (const entry of list) failures.push(`growth ${stats.name}: ${kind}: ${entry}`);
    }
  }
  console.log(`marks oracle: ${cases} cases in ${Math.round((Date.now() - started) / 1000)} s, slowest ${Math.round(slowest.ms)} ms (${slowest.where})`);
  if (failures.length > 0) {
    console.error(`${failures.length} failure(s); rerun with MARKS_SEED=${SEED}:`);
    for (const entry of failures) console.error(" - " + entry);
    process.exit(1);
  }
  console.log("marks oracle: no hang, every cell within the limit of its device cell width, every cell identical to the raw terminal after the same cut, no hang when the font or the device scale grows after the output");
  process.exit(0);
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
