import { JSDOM } from "jsdom";

import { ALL, NOW, session } from "../fixtures.mjs";

export function installDom(url = "https://jaunt.test/") {
  const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', { url, pretendToBeVisual: true });
  const { window } = dom;
  const define = (name, value) => Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  define("window", window);
  define("document", window.document);
  define("history", window.history);
  define("localStorage", window.localStorage);
  Object.defineProperty(globalThis, "location", { get: () => window.location, configurable: true });
  define("KeyboardEvent", window.KeyboardEvent);
  define("MouseEvent", window.MouseEvent);
  define("Event", window.Event);
  return dom;
}

export function json(status, body, headers = {}) {
  return { status, body, headers };
}

export function createServer(routes) {
  const calls = [];
  const table = new Map(Object.entries(routes));
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input, "https://jaunt.test");
    const method = init.method || "GET";
    const request = {
      method,
      path: url.pathname,
      query: url.searchParams,
      headers: Object.fromEntries(Object.entries(init.headers || {}).map(([key, value]) => [key.toLowerCase(), value])),
      body: init.body ? JSON.parse(init.body) : undefined,
      url: String(input),
    };
    calls.push(request);
    let handler = table.get(method + " " + url.pathname);
    if (handler === undefined) {
      return new Response(JSON.stringify({ error: "not_found" }), { status: 404, headers: { "Content-Type": "application/json" } });
    }
    if (Array.isArray(handler)) {
      const queue = handler;
      handler = queue.length > 1 ? queue.shift() : queue[0];
    }
    const reply = typeof handler === "function" ? await handler(request) : handler;
    const headers = new Headers({ "Content-Type": reply.contentType || "application/json", ...(reply.headers || {}) });
    const raw = reply.raw !== undefined;
    const body = reply.status === 204 || (reply.body === undefined && !raw) ? null : raw ? reply.raw : JSON.stringify(reply.body);
    return new Response(body, { status: reply.status, headers });
  };
  return {
    calls,
    fetch: fetchImpl,
    set(key, handler) {
      table.set(key, handler);
    },
    count(method, path) {
      return calls.filter((call) => call.method === method && call.path === path).length;
    },
  };
}

export function signedIn(permissions = ALL, extra = {}) {
  return { "GET /v1/web/session": json(200, session(permissions, extra)) };
}

export async function settle(rounds = 8) {
  for (let index = 0; index < rounds; index += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

export async function until(condition, description) {
  for (let index = 0; index < 400; index += 1) {
    if (condition()) {
      return;
    }
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error("timed out waiting for " + description);
}

export async function mount(routes, hash = "", options = {}) {
  const dom = installDom();
  if (options.before) {
    options.before(dom.window);
  }
  const server = createServer(routes);
  globalThis.fetch = server.fetch;
  if (hash) {
    window.history.replaceState(null, "", hash);
  }
  const { start } = await import("../../crates/jaunt-web/assets/assets/js/app.js");
  const app = start(document.getElementById("app"));
  await app.ready;
  await settle();
  return {
    dom,
    server,
    app,
    root: document.getElementById("app"),
    main: () => document.getElementById("main"),
    text: () => document.getElementById("app").textContent,
    stop: () => {
      app.stop();
      dom.window.close();
    },
  };
}

export function click(node) {
  node.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true }));
}

export function type(input, value) {
  input.value = value;
  input.dispatchEvent(new window.Event("input", { bubbles: true }));
}

export function submit(form) {
  form.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
}

export function press(target, key, options = {}) {
  const event = new window.KeyboardEvent("keydown", { key, bubbles: true, cancelable: true, ...options });
  target.dispatchEvent(event);
  return event;
}

export function byText(root, selector, text) {
  return Array.from(root.querySelectorAll(selector)).find((node) => node.textContent.trim() === text);
}

export function setHidden(hidden) {
  Object.defineProperty(document, "hidden", { configurable: true, get: () => hidden });
}

export { NOW };
