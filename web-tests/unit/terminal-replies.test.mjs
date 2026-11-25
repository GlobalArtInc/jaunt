import assert from "node:assert/strict";
import { test } from "node:test";

import { installDom } from "./support.mjs";
import { fakePrintPath } from "./terminal-support.mjs";

const ADAPTER = "../../crates/jaunt-web/assets/assets/js/recording/terminal.js";
const REPLIES = "../../crates/jaunt-web/assets/assets/js/terminal/replies.js";
const ESC = "\u001b";

function fakeLibraries(log) {
  class Terminal {
    constructor(options) {
      this._core = fakePrintPath();
      this.options = options;
      this.osc = new Map();
      this.csi = new Map();
      this.csiStack = new Map();
      this.dcs = new Map();
      this.buffer = { active: { cursorX: 4, cursorY: 2 } };
      this.parser = {
        registerOscHandler: (id, handler) => this.osc.set(id, handler),
        registerCsiHandler: (identifier, handler) => {
          const key = JSON.stringify(identifier);
          this.csiStack.set(key, [...(this.csiStack.get(key) || []), handler]);
          this.csi.set(key, (params) => [...this.csiStack.get(key)].reverse().some((entry) => entry(params)));
        },
        registerDcsHandler: (identifier, handler) => this.dcs.set(JSON.stringify(identifier), handler),
      };
      this.listeners = {};
      this.textarea = document.createElement("textarea");
      log.created.push(this);
    }

    open() {}

    loadAddon() {}

    onData(listener) {
      this.listeners.data = listener;
    }

    onBinary(listener) {
      this.listeners.binary = listener;
    }
  }
  class CanvasAddon {}
  return { Terminal, CanvasAddon };
}

function build(extra = {}) {
  const dom = installDom();
  const log = { created: [], input: [], replies: [] };
  return import(ADAPTER).then(({ createInteractiveTerminal }) => {
    const container = document.createElement("div");
    document.body.appendChild(container);
    let time = 0;
    const terminal = createInteractiveTerminal({
      container,
      cols: 80,
      rows: 24,
      libraries: fakeLibraries(log),
      now: () => time,
      onInput: (data) => log.input.push(data),
      onReply: (text) => log.replies.push(text),
      ...extra,
    });
    return { dom, terminal, log, setTime: (value) => (time = value) };
  });
}

const csi = (terminal, identifier, params = [0]) => terminal.csi.get(JSON.stringify(identifier))(params);

test("the interactive terminal keeps every protection of the player and starts with input off", async () => {
  const { dom, terminal } = await build();
  const { options } = terminal;
  assert.equal(options.disableStdin, true);
  assert.equal(options.linkHandler, null);
  assert.equal(options.allowProposedApi, false);
  assert.equal(options.screenReaderMode, false);
  assert.deepEqual(options.windowOptions, {});
  assert.equal(options.scrollback > 0, true);
  assert.equal(options.fontSize, 14);
  for (const id of [0, 2, 4, 8, 10, 11, 52, 104, 133, 199]) {
    assert.equal(terminal.osc.get(id)(), true, String(id));
  }
  for (let code = 0x40; code <= 0x7e; code += 1) {
    const final = String.fromCharCode(code);
    if ("cntSTLMZb@PX".includes(final)) {
      continue;
    }
    assert.equal(csi(terminal, { final }, [999999999]), true, final);
    assert.equal(csi(terminal, { final }, [5000]), false, final);
  }
  assert.equal(terminal.textarea.tabIndex, 0);
  assert.equal(terminal.textarea.readOnly, false);
  dom.window.close();
});

test("typed data and binary data reach the input callback, binary as latin-1 bytes", async () => {
  const { dom, terminal, log } = await build();
  terminal.listeners.data("ls");
  terminal.listeners.binary("éÿ");
  assert.equal(log.input[0], "ls");
  assert.deepEqual(Array.from(log.input[1]), [0xe9, 0xff]);
  assert.deepEqual(log.replies, []);
  dom.window.close();
});

test("only device attributes and status and cursor reports are answered, with the fixed texts", async () => {
  const { dom, terminal, log } = await build();
  assert.equal(csi(terminal, { final: "c" }, [0]), true);
  assert.equal(csi(terminal, { final: "c" }, [[0]]), true);
  assert.equal(csi(terminal, { prefix: ">", final: "c" }, [0]), true);
  assert.equal(csi(terminal, { final: "n" }, [5]), true);
  assert.equal(csi(terminal, { final: "n" }, [6]), true);
  assert.equal(csi(terminal, { prefix: "?", final: "n" }, [6]), true);
  assert.deepEqual(log.replies, [ESC + "[?1;2c", ESC + "[?1;2c", ESC + "[>0;276;0c", ESC + "[0n", ESC + "[3;5R", ESC + "[?3;5R"]);
  dom.window.close();
});

test("other reports, nonzero attribute requests, mode queries, window reports and status strings are swallowed without a reply", async () => {
  const { dom, terminal, log } = await build();
  assert.equal(csi(terminal, { final: "c" }, [1]), true);
  assert.equal(csi(terminal, { prefix: ">", final: "c" }, [7]), true);
  assert.equal(csi(terminal, { final: "n" }, [15]), true);
  assert.equal(csi(terminal, { prefix: "?", final: "n" }, [15]), true);
  for (const request of [14, 16, 18, 21, 22, 23]) {
    assert.equal(csi(terminal, { final: "t" }, [request]), true, String(request));
  }
  assert.equal(csi(terminal, { intermediates: "$", final: "p" }, [2004]), true);
  assert.equal(csi(terminal, { prefix: "?", intermediates: "$", final: "p" }, [2004]), true);
  assert.equal(terminal.dcs.get(JSON.stringify({ intermediates: "$", final: "q" }))('"p', []), true);
  assert.deepEqual(log.replies, []);
  dom.window.close();
});

test("a flood of queries is answered at most 16 times a second", async () => {
  const { dom, terminal, log, setTime } = await build();
  for (let index = 0; index < 1000; index += 1) {
    csi(terminal, { final: "n" }, [6]);
  }
  assert.equal(log.replies.length, 16);
  setTime(999);
  csi(terminal, { final: "n" }, [5]);
  assert.equal(log.replies.length, 16);
  setTime(1000);
  csi(terminal, { final: "n" }, [5]);
  assert.equal(log.replies.length, 17);
  dom.window.close();
});

test("the reply budget is exposed for reuse and refills after its window", async () => {
  const { createReplyBudget } = await import(REPLIES);
  let time = 0;
  const allowed = createReplyBudget(() => time, 2, 100);
  assert.deepEqual([allowed(), allowed(), allowed()], [true, true, false]);
  time = 100;
  assert.equal(allowed(), true);
  time = 50;
  assert.equal(allowed(), true);
});

test("every operating system command number from 0 to 199 is swallowed and none above is touched", async () => {
  const { dom, terminal } = await build();
  for (let id = 0; id < 200; id += 1) {
    assert.equal(terminal.osc.get(id)(), true, String(id));
  }
  assert.equal(terminal.osc.size, 200);
  assert.equal(terminal.osc.has(200), false);
  dom.window.close();
});
