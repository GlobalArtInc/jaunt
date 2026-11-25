import assert from "node:assert/strict";
import { test } from "node:test";

import { installDom } from "./support.mjs";

const JS = "../../crates/jaunt-web/assets/assets/js/recording/terminal.js";
const RESET = "\u001bc";

function fakeLibraries(log) {
  class Terminal {
    constructor(options) {
      this.options = options;
      this.rows = options.rows;
      this.oscHandlers = new Map();
      this.csiHandlers = new Map();
      this.textarea = document.createElement("textarea");
      this.element = document.createElement("div");
      this.pendingWrites = [];
      this.parser = {
        registerOscHandler: (id, handler) => this.oscHandlers.set(id, handler),
        registerCsiHandler: (identifier, handler) => this.csiHandlers.set(identifier.final, handler),
      };
      log.created.push(this);
      log.styleDuringConstruction = document.createElement("style").tagName;
    }

    open(container) {
      log.opened = container;
      container.appendChild(this.element);
      log.styleDuringOpen = document.createElement("style").tagName;
      log.divDuringOpen = document.createElement("div").tagName;
    }

    loadAddon(addon) {
      log.addon = addon;
    }

    write(text, callback) {
      this.pendingWrites.push({ text, callback });
      log.writes.push(text);
    }

    flush() {
      const { callback } = this.pendingWrites.shift();
      if (callback) {
        callback();
      }
    }

    refresh() {
      log.refreshes += 1;
    }

    resize(cols, rows) {
      this.rows = rows;
      log.sizes.push([cols, rows]);
    }

    dispose() {
      log.disposed += 1;
    }
  }
  class CanvasAddon {}
  return { Terminal, CanvasAddon };
}

function freshLog() {
  return { created: [], writes: [], sizes: [], refreshes: 0, disposed: 0 };
}

function newContainer() {
  const container = document.createElement("div");
  document.body.appendChild(container);
  return container;
}

test("the terminal is created read-only with links, titles and clipboard escapes swallowed", async () => {
  const dom = installDom();
  const { createTerminalSink } = await import(JS);
  const log = freshLog();
  const container = newContainer();
  createTerminalSink({ container, cols: 120, rows: 40, libraries: fakeLibraries(log) });

  const terminal = log.created[0];
  const { options } = terminal;
  assert.equal(options.cols, 120);
  assert.equal(options.rows, 40);
  assert.equal(options.disableStdin, true);
  assert.equal(options.linkHandler, null);
  assert.equal(options.allowProposedApi, false);
  assert.equal(options.screenReaderMode, false);
  assert.equal(log.opened, container);
  assert.equal(log.addon.constructor.name, "CanvasAddon");
  for (const id of [0, 1, 2, 4, 7, 8, 10, 11, 52, 104, 133, 199]) {
    assert.equal(terminal.oscHandlers.get(id)(), true, String(id));
  }
  assert.equal(terminal.textarea.tabIndex, -1);
  assert.equal(terminal.textarea.readOnly, true);
  dom.window.close();
});

test("every csi final swallows a first parameter above the bound and lets ordinary counts through", async () => {
  const dom = installDom();
  const { createTerminalSink } = await import(JS);
  const log = freshLog();
  createTerminalSink({ container: newContainer(), cols: 80, rows: 24, libraries: fakeLibraries(log) });
  const handlers = log.created[0].csiHandlers;

  assert.equal(handlers.size, 63);
  for (let code = 0x40; code <= 0x7e; code += 1) {
    const final = String.fromCharCode(code);
    assert.equal(handlers.get(final)([999999999]), true, final);
    assert.equal(handlers.get(final)([2147483647, 1]), true, final);
    assert.equal(handlers.get(final)([[5001, 1]]), true, final);
    assert.equal(handlers.get(final)([5000]), false, final);
    assert.equal(handlers.get(final)([]), false, final);
    assert.equal(handlers.get(final)([1, 999999999]), false, final);
  }
  dom.window.close();
});

test("the background and text colours come from the page tokens when there are any", async () => {
  const dom = installDom();
  const { createTerminalSink } = await import(JS);
  const log = freshLog();
  createTerminalSink({ container: newContainer(), cols: 80, rows: 24, libraries: fakeLibraries(log) });
  assert.equal(log.created[0].options.theme.background, "#0b0d10");

  document.documentElement.setAttribute("style", "");
  const container = newContainer();
  window.getComputedStyle = () => ({ getPropertyValue: (name) => ({ "--term-bg": " #07080a ", "--term-text": "#eeeeee" })[name] || "" });
  createTerminalSink({ container, cols: 80, rows: 24, libraries: fakeLibraries(log) });
  assert.equal(log.created[1].options.theme.background, "#07080a");
  assert.equal(log.created[1].options.theme.foreground, "#eeeeee");
  dom.window.close();
});

test("style elements the library creates are inert only while it is being built and other elements are untouched", async () => {
  const dom = installDom();
  const { createTerminalSink, withInertStyleElements } = await import(JS);
  const log = freshLog();
  createTerminalSink({ container: newContainer(), cols: 80, rows: 24, libraries: fakeLibraries(log) });
  assert.equal(log.styleDuringConstruction, "TEMPLATE");
  assert.equal(log.styleDuringOpen, "TEMPLATE");
  assert.equal(log.divDuringOpen, "DIV");
  assert.equal(document.createElement("style").tagName, "STYLE");
  assert.equal(Object.hasOwn(document, "createElement"), false);
  assert.equal(document.createElement("div").tagName, "DIV");

  assert.throws(
    () =>
      withInertStyleElements(() => {
        throw new Error("boom");
      }),
    /boom/,
  );
  assert.equal(document.createElement("style").tagName, "STYLE");
  assert.equal(Object.hasOwn(document, "createElement"), false);
  withInertStyleElements(() => {
    assert.equal(document.createElement("div").tagName, "DIV");
    assert.equal(document.createElement("STYLE").tagName, "TEMPLATE");
  });
  dom.window.close();
});

test("writes go to the terminal one at a time and a reset drops what has not been written", async () => {
  const dom = installDom();
  const { createTerminalSink } = await import(JS);
  const log = freshLog();
  const sink = createTerminalSink({ container: newContainer(), cols: 80, rows: 24, libraries: fakeLibraries(log) });
  const terminal = log.created[0];
  sink.write("one");
  sink.write("two");
  sink.resize(100, 30);
  sink.write("three");
  assert.deepEqual(log.writes, ["one"]);
  sink.reset(90, 20);
  terminal.flush();
  assert.deepEqual(log.writes, ["one", RESET]);
  assert.deepEqual(log.sizes, []);
  terminal.flush();
  assert.deepEqual(log.sizes, [[90, 20]]);
  sink.write("four");
  assert.deepEqual(log.writes, ["one", RESET, "four"]);
  dom.window.close();
});

test("idle resolves once everything queued has been written", async () => {
  const dom = installDom();
  const { createTerminalSink } = await import(JS);
  const log = freshLog();
  const sink = createTerminalSink({ container: newContainer(), cols: 80, rows: 24, libraries: fakeLibraries(log) });
  let idle = false;
  sink.write("a");
  sink.write("b");
  const waiting = sink.idle().then(() => {
    idle = true;
  });
  await Promise.resolve();
  assert.equal(idle, false);
  log.created[0].flush();
  await Promise.resolve();
  assert.equal(idle, false);
  log.created[0].flush();
  await waiting;
  assert.equal(idle, true);
  await sink.idle();
  dom.window.close();
});

test("one terminal is reused for every play, moved into the new container and cleared in between", async () => {
  const dom = installDom();
  const { createTerminalSink } = await import(JS);
  const log = freshLog();
  const libraries = fakeLibraries(log);
  const firstHost = newContainer();
  const first = createTerminalSink({ container: firstHost, cols: 80, rows: 24, libraries });
  first.write("old");
  first.dispose();
  const terminal = log.created[0];
  assert.equal(firstHost.contains(terminal.element), false);
  assert.equal(log.writes.at(-1), RESET);
  assert.equal(log.disposed, 0);

  const secondHost = newContainer();
  const second = createTerminalSink({ container: secondHost, cols: 100, rows: 30, libraries });
  assert.equal(log.created.length, 1);
  assert.equal(second.terminal, terminal);
  assert.equal(secondHost.contains(terminal.element), true);
  assert.deepEqual(log.sizes.at(-1), [100, 30]);
  assert.equal(log.refreshes, 1);

  const third = createTerminalSink({ container: newContainer(), cols: 80, rows: 24, libraries });
  assert.equal(log.created.length, 2);
  third.dispose();
  assert.equal(log.disposed, 1);
  second.dispose();
  assert.equal(log.disposed, 1);
  dom.window.close();
});

test("already loaded libraries are reused without injecting any tag", async () => {
  const dom = installDom();
  const { loadTerminalLibraries } = await import(JS);
  const libraries = fakeLibraries(freshLog());
  const scope = { Terminal: libraries.Terminal, CanvasAddon: { CanvasAddon: libraries.CanvasAddon } };
  const before = document.head.children.length;
  const loaded = await loadTerminalLibraries(document, scope);
  assert.equal(loaded.Terminal, libraries.Terminal);
  assert.equal(loaded.CanvasAddon, libraries.CanvasAddon);
  assert.equal(document.head.children.length, before);
  dom.window.close();
});
