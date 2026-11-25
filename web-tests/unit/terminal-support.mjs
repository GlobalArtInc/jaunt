import { readFileSync } from "node:fs";

import { JSDOM, VirtualConsole } from "jsdom";

export const TICKET = "T".repeat(43);
export const PROTOCOL = "jaunt-terminal.v1";

export function fakeClock() {
  const state = { time: 0, timers: [], next: 1 };
  const add = (callback, ms, every) => {
    const id = state.next;
    state.next += 1;
    state.timers.push({ callback, at: state.time + ms, id, every });
    return id;
  };
  const remove = (id) => {
    state.timers = state.timers.filter((timer) => timer.id !== id);
  };
  return {
    state,
    now: () => state.time,
    setTimeout: (callback, ms) => add(callback, ms, null),
    clearTimeout: remove,
    setInterval: (callback, ms) => add(callback, ms, ms),
    clearInterval: remove,
    advance(ms) {
      const end = state.time + ms;
      for (;;) {
        const due = state.timers.filter((timer) => timer.at <= end).sort((a, b) => a.at - b.at)[0];
        if (!due) {
          break;
        }
        state.time = Math.max(state.time, due.at);
        if (due.every === null) {
          remove(due.id);
        } else {
          due.at += due.every;
        }
        due.callback();
      }
      state.time = end;
    },
  };
}

export class FakeSocket {
  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.readyState = 0;
    this.bufferedAmount = 0;
    this.protocol = "";
    this.sent = [];
    this.closed = null;
    this.listeners = new Map();
  }

  addEventListener(type, handler) {
    this.listeners.set(type, handler);
  }

  emit(type, event) {
    const handler = this.listeners.get(type);
    if (handler) {
      handler(event);
    }
  }

  send(data) {
    this.sent.push(data);
  }

  close(code, reason) {
    this.closed = [code, reason];
    this.readyState = 3;
  }

  accept(protocol = PROTOCOL) {
    this.protocol = protocol;
    this.readyState = 1;
    this.emit("open", {});
  }

  control(message) {
    this.emit("message", { data: typeof message === "string" ? message : JSON.stringify(message) });
  }

  output(bytes) {
    this.emit("message", { data: Uint8Array.from(bytes).buffer });
  }

  drop(code, reason = "") {
    this.readyState = 3;
    this.emit("close", { code, reason });
  }

  frames() {
    return this.sent.filter((item) => typeof item === "string").map((item) => JSON.parse(item));
  }

  input() {
    return this.sent.filter((item) => typeof item !== "string").map((item) => Array.from(item));
  }
}

export class FakeTerminal {
  constructor(options) {
    this.options = { disableStdin: true, fontSize: options.fontSize };
    this.init = options;
    this.cols = options.cols;
    this.rows = options.rows;
    this.written = [];
    this.pasted = [];
    this.resizes = [];
    this.resets = 0;
    this.focused = 0;
    this.blurred = 0;
    this.disposed = false;
    this.selection = "";
    this.modes = { applicationCursorKeysMode: false };
    this.keyHandler = null;
    this.element = document.createElement("div");
    this.screen = document.createElement("div");
    this.screen.className = "xterm-screen";
    this.element.appendChild(this.screen);
    options.container.appendChild(this.element);
    this.screen.getBoundingClientRect = () => ({ width: this.cols * 10, height: this.rows * 20 });
  }

  write(bytes) {
    this.written.push(bytes);
  }

  resize(cols, rows) {
    this.cols = cols;
    this.rows = rows;
    this.resizes.push([cols, rows]);
  }

  reset() {
    this.resets += 1;
    this.written = [];
  }

  focus() {
    this.focused += 1;
  }

  blur() {
    this.blurred += 1;
  }

  paste(text) {
    this.pasted.push(text);
    this.init.onInput(text);
  }

  getSelection() {
    return this.selection;
  }

  attachCustomKeyEventHandler(handler) {
    this.keyHandler = handler;
  }

  dispose() {
    this.disposed = true;
  }

  type(text) {
    if (!this.options.disableStdin) {
      this.init.onInput(text);
    }
  }
}

export function installTerminalHooks(terminalHooks) {
  const original = { ...terminalHooks };
  const clock = fakeClock();
  const rig = { clock, sockets: [], terminals: [], observers: [], clipboard: { text: "", written: [] }, layout: { width: 800, height: 400 }, keyBar: false };
  terminalHooks.loadLibraries = async () => ({});
  terminalHooks.createTerminal = (options) => {
    Object.defineProperty(options.container, "clientWidth", { configurable: true, get: () => rig.layout.width });
    Object.defineProperty(options.container, "clientHeight", { configurable: true, get: () => rig.layout.height });
    const terminal = new FakeTerminal(options);
    rig.terminals.push(terminal);
    return terminal;
  };
  terminalHooks.connection = {
    createSocket: (url, protocols) => {
      const socket = new FakeSocket(url, protocols);
      rig.sockets.push(socket);
      return socket;
    },
    base: () => "https://jaunt.test/#/terminal",
    isHidden: () => document.hidden,
    clock,
  };
  terminalHooks.observeResize = (element, callback) => {
    rig.observers.push(callback);
    return () => {
      rig.observers = rig.observers.filter((item) => item !== callback);
    };
  };
  terminalHooks.clipboard = () => ({
    readText: async () => {
      if (rig.clipboard.denied) {
        throw new Error("denied");
      }
      return rig.clipboard.text;
    },
    writeText: async (text) => {
      if (rig.clipboard.denied) {
        throw new Error("denied");
      }
      rig.clipboard.written.push(text);
    },
  });
  terminalHooks.prefersKeyBar = () => rig.keyBar;
  rig.restore = () => Object.assign(terminalHooks, original);
  return rig;
}

const XTERM_SOURCE = new URL("../../crates/jaunt-web/assets/assets/vendor/xterm/xterm.js", import.meta.url);

export function loadXterm() {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: new VirtualConsole() });
  const { window } = dom;
  window.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} });
  window.eval(readFileSync(XTERM_SOURCE, "utf8"));
  class CanvasAddon {
    activate() {}

    dispose() {}
  }
  return { dom, window, document: window.document, libraries: { Terminal: window.Terminal, CanvasAddon } };
}

export function fakePrintPath() {
  class Line {
    addCodepointToCell() {}

    getString() {
      return "";
    }

    getWidth() {
      return 1;
    }

    isCombined() {
      return 0;
    }

    loadCell(index, cell) {
      return cell;
    }

    setCell() {}
  }
  class InputHandler {
    print() {}
  }
  class RenderService {
    _renderRows() {}
  }
  const handler = new InputHandler();
  handler._parser = { _printHandler: (data, start, end) => handler.print(data, start, end) };
  const render = new RenderService();
  render.dimensions = { device: { cell: { width: 0, height: 0 } } };
  render._renderDebouncer = { _renderCallback: (start, end) => render._renderRows(start, end) };
  const line = new Line();
  const buffer = { ydisp: 0, lines: { get: () => line } };
  return { _inputHandler: handler, _renderService: render, buffer, buffers: { normal: buffer } };
}
