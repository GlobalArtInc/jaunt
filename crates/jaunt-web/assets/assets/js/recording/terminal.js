import { cellUnitsLimit, installCellLimit, installPaintLimit } from "../terminal/cells.js";
import { FONT_SIZES, LARGEST_FONT_SIZE, PLAYER_FONT_SIZE } from "../terminal/fonts.js";
import { LIMITED_FINALS, createOutputGuard, installCountLimits } from "../terminal/guard.js";
import { installReplyPolicy } from "../terminal/replies.js";

const VENDOR_ROOT = "/assets/vendor/";
const STYLESHEET = VENDOR_ROOT + "xterm/xterm.css";
const SCRIPTS = [VENDOR_ROOT + "xterm/xterm.js", VENDOR_ROOT + "xterm-addon-canvas/addon-canvas.js"];
const SWALLOWED_OSC = Array.from({ length: 200 }, (_, index) => index);
const FONT = 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace';
const FALLBACK_BACKGROUND = "#0b0d10";
const FALLBACK_FOREGROUND = "#d8dee7";
const SELECTION = "#3b4a63";
const OVERSIZED_COUNT = 5000;
const CSI_FINALS = Array.from({ length: 0x7f - 0x40 }, (_, index) => String.fromCharCode(0x40 + index)).filter((final) => !LIMITED_FINALS.includes(final));
const FULL_RESET = "\u001bc";
const INTERACTIVE_SCROLLBACK = 5000;
const PENDING_FLUSH_MS = 30;

let loading = null;
let shared = null;

function appendAndWait(doc, node) {
  return new Promise((resolve, reject) => {
    node.addEventListener("load", () => resolve());
    node.addEventListener("error", () => reject(new Error("a player file did not load")));
    doc.head.appendChild(node);
  });
}

function script(doc, source) {
  const node = doc.createElement("script");
  node.src = source;
  node.async = false;
  return appendAndWait(doc, node);
}

function stylesheet(doc, source) {
  const node = doc.createElement("link");
  node.rel = "stylesheet";
  node.href = source;
  return appendAndWait(doc, node);
}

export function loadTerminalLibraries(doc = document, scope = globalThis) {
  if (scope.Terminal && scope.CanvasAddon) {
    return Promise.resolve({ Terminal: scope.Terminal, CanvasAddon: scope.CanvasAddon.CanvasAddon });
  }
  if (loading === null) {
    loading = (async () => {
      await stylesheet(doc, STYLESHEET);
      for (const source of SCRIPTS) {
        await script(doc, source);
      }
      if (!scope.Terminal || !scope.CanvasAddon) {
        throw new Error("the terminal library did not define its entry points");
      }
      return { Terminal: scope.Terminal, CanvasAddon: scope.CanvasAddon.CanvasAddon };
    })();
    loading.catch(() => {
      loading = null;
    });
  }
  return loading;
}

export function withInertStyleElements(fn, doc = document) {
  const original = doc.createElement;
  const hadOwn = Object.hasOwn(doc, "createElement");
  doc.createElement = function createElement(name, ...rest) {
    return String(name).toLowerCase() === "style" ? original.call(this, "template") : original.call(this, name, ...rest);
  };
  try {
    return fn();
  } finally {
    if (hadOwn) {
      doc.createElement = original;
    } else {
      delete doc.createElement;
    }
  }
}

function themeOf(container, doc) {
  const view = doc.defaultView;
  const style = view && typeof view.getComputedStyle === "function" ? view.getComputedStyle(container) : null;
  const read = (name, fallback) => (style && style.getPropertyValue(name).trim()) || fallback;
  const foreground = read("--term-text", FALLBACK_FOREGROUND);
  return { background: read("--term-bg", FALLBACK_BACKGROUND), foreground, cursor: foreground, selectionBackground: SELECTION };
}

function oversizedCount(params) {
  const first = Array.isArray(params[0]) ? params[0][0] : params[0];
  return typeof first === "number" && first > OVERSIZED_COUNT;
}

export function neutralise(terminal) {
  for (const id of SWALLOWED_OSC) {
    terminal.parser.registerOscHandler(id, () => true);
  }
  for (const final of CSI_FINALS) {
    terminal.parser.registerCsiHandler({ final }, oversizedCount);
  }
  installCountLimits(terminal);
}

function construct({ container, cols, rows, libraries, doc, largestFont }, overrides) {
  const { Terminal, CanvasAddon } = libraries;
  const terminal = withInertStyleElements(() => {
    const created = new Terminal({
      cols,
      rows,
      scrollback: 0,
      disableStdin: true,
      cursorBlink: false,
      convertEol: false,
      allowProposedApi: false,
      allowTransparency: false,
      screenReaderMode: false,
      linkHandler: null,
      fontFamily: FONT,
      fontSize: PLAYER_FONT_SIZE,
      theme: themeOf(container, doc),
      ...overrides,
    });
    try {
      installCellLimit(created, cellUnitsLimit(created, { largestFont }));
      created.open(container);
      created.loadAddon(new CanvasAddon());
      installPaintLimit(created);
    } catch (error) {
      created.dispose();
      throw error;
    }
    return created;
  }, doc);
  neutralise(terminal);
  return terminal;
}

function buildTerminal(options) {
  const terminal = construct({ ...options, largestFont: PLAYER_FONT_SIZE }, {});
  if (terminal.textarea) {
    terminal.textarea.tabIndex = -1;
    terminal.textarea.setAttribute("aria-hidden", "true");
    terminal.textarea.readOnly = true;
  }
  return terminal;
}

function acquire(options) {
  const { container, cols, rows, libraries, doc } = options;
  if (shared !== null && (shared.Terminal !== libraries.Terminal || shared.doc !== doc)) {
    shared = null;
  }
  if (shared !== null && !shared.inUse) {
    const { terminal } = shared;
    shared.inUse = true;
    container.appendChild(terminal.element);
    terminal.options.theme = themeOf(container, doc);
    terminal.resize(cols, rows);
    terminal.refresh(0, terminal.rows - 1);
    return { terminal, reused: shared };
  }
  const terminal = buildTerminal(options);
  if (shared === null || !shared.inUse) {
    shared = { terminal, Terminal: libraries.Terminal, doc, inUse: true };
    return { terminal, reused: shared };
  }
  return { terminal, reused: null };
}

export function createTerminalSink({ container, cols, rows, libraries, doc = document }) {
  const { terminal, reused } = acquire({ container, cols, rows, libraries, doc });
  const guard = createOutputGuard(() => ({ cols: terminal.cols, rows: terminal.rows }));
  let tasks = [];
  let waiters = [];
  let busy = false;
  let disposed = false;

  function settle() {
    if (!busy && tasks.length === 0) {
      const pending = waiters;
      waiters = [];
      for (const resolve of pending) {
        resolve();
      }
    }
  }

  function drain() {
    if (busy || disposed) {
      return;
    }
    const task = tasks.shift();
    if (task === undefined) {
      settle();
      return;
    }
    busy = true;
    const done = () => {
      busy = false;
      drain();
    };
    if (task.kind === "write") {
      terminal.write(task.text, done);
    } else if (task.kind === "resize") {
      terminal.resize(task.cols, task.rows);
      done();
    } else {
      terminal.write(FULL_RESET, () => {
        terminal.resize(task.cols, task.rows);
        done();
      });
    }
  }

  function enqueue(task) {
    tasks.push(task);
    drain();
  }

  return {
    write(text) {
      for (const piece of guard.pieces(text)) {
        enqueue({ kind: "write", text: piece });
      }
    },
    resize: (newCols, newRows) => enqueue({ kind: "resize", cols: newCols, rows: newRows }),
    reset(newCols, newRows) {
      guard.reset();
      tasks = [];
      enqueue({ kind: "reset", cols: newCols, rows: newRows });
    },
    idle: () =>
      new Promise((resolve) => {
        waiters.push(resolve);
        settle();
      }),
    dispose() {
      disposed = true;
      tasks = [];
      if (reused === null) {
        terminal.dispose();
        return;
      }
      terminal.write(FULL_RESET);
      if (terminal.element && terminal.element.parentNode) {
        terminal.element.parentNode.removeChild(terminal.element);
      }
      reused.inUse = false;
    },
    terminal,
  };
}

export function createInteractiveTerminal({ container, cols, rows, libraries, doc = document, fontSize = FONT_SIZES[0], now = () => Date.now(), onInput, onReply }) {
  const terminal = construct({ container, cols, rows, libraries, doc, largestFont: LARGEST_FONT_SIZE }, { scrollback: INTERACTIVE_SCROLLBACK, fontSize, windowOptions: {} });
  installReplyPolicy(terminal, { send: onReply, now });
  terminal.onData((text) => onInput(text));
  terminal.onBinary((text) => onInput(Uint8Array.from(text, (char) => char.charCodeAt(0) & 0xff)));
  return terminal;
}

export function createGuardedWriter(terminal, timers) {
  const guard = createOutputGuard(() => ({ cols: terminal.cols, rows: terminal.rows }));
  const decoder = new TextDecoder("utf-8");
  let timer = null;
  let disposed = false;

  function cancel() {
    if (timer !== null) {
      timers.clearTimeout(timer);
      timer = null;
    }
  }

  function flush() {
    timer = null;
    const rest = guard.flush();
    if (rest !== "" && !disposed) {
      terminal.write(rest);
    }
  }

  return {
    write(bytes) {
      if (disposed) {
        return;
      }
      cancel();
      for (const piece of guard.pieces(decoder.decode(bytes, { stream: true }))) {
        terminal.write(piece);
      }
      if (guard.hasPending()) {
        timer = timers.setTimeout(flush, PENDING_FLUSH_MS);
      }
    },
    dispose() {
      disposed = true;
      cancel();
    },
  };
}
