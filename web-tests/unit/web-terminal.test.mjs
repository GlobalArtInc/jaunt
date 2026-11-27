import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";

import { byText, click, json, mount, setHidden, settle, signedIn, until } from "./support.mjs";
import { PROTOCOL, TICKET, installTerminalHooks } from "./terminal-support.mjs";

const HOOKS = "../../crates/jaunt-web/assets/assets/js/terminal/hooks.js";
const TICKET_ROUTE = "POST /v1/web/terminal/ticket";
const TARGETS_ROUTE = "GET /v1/web/terminal/targets";
const RECENT_ROUTE = "GET /v1/web/terminal/recent";
const CONFIG_ROUTE = "GET /v1/client-config";
const CONFIG = { ssh_suffix: "jaunt.example.com" };
const LIMITS_ROUTE = "GET /v1/web/terminal/limits";
const LIMITS = { max_per_user: 4, idle_timeout_secs: 1800 };
const FLEET = [
  { node: "web-01", labels: { env: "prod", team: "web" }, connected: true, logins: ["deploy", "alice"] },
  { node: "web-02", labels: { env: "prod" }, connected: true, logins: ["deploy"] },
  { node: "db-replica-02", labels: {}, connected: false, logins: ["deploy"] },
];
const GRANT = json(200, { ticket: TICKET, expires_in: 30 });

let ui = null;
let rig = null;

beforeEach(async () => {
  const { terminalHooks } = await import(HOOKS);
  rig = installTerminalHooks(terminalHooks);
});

afterEach(() => {
  if (ui) {
    ui.stop();
    ui = null;
  }
  rig.restore();
});

function open(routes = {}, hash = "#/terminal", permissions = []) {
  return mount({ ...signedIn(permissions), [TARGETS_ROUTE]: json(200, FLEET), [RECENT_ROUTE]: json(200, []), [CONFIG_ROUTE]: json(200, CONFIG), [LIMITS_ROUTE]: json(200, LIMITS), [TICKET_ROUTE]: GRANT, ...routes }, hash);
}

async function begin(routes, hash = "#/terminal?node=web-02&login=deploy") {
  ui = await open(routes, hash);
  click(start());
  await until(() => rig.sockets.length > 0, "the socket");
  return rig.sockets[0];
}

async function ready(socket = rig.sockets[0]) {
  socket.accept();
  socket.control({ t: "ready", session_id: "s-1" });
  await settle();
}

const start = () => ui.root.querySelector(".panel.quick footer .btn-primary");
const states = () => ui.root.querySelector(".statusbar [role=status]").textContent;
const bannerText = () => ui.root.querySelector(".term-banner").textContent;

test("opening sends the ticket request with the CSRF header and opens the socket with the exact protocols and no ticket in the address", async () => {
  const socket = await begin();
  const post = ui.server.calls.find((call) => call.method === "POST" && call.path === "/v1/web/terminal/ticket");
  assert.deepEqual(post.body, { node: "web-02", login: "deploy" });
  assert.equal(post.headers["x-jaunt-csrf"], "csrf-token-one");
  const url = new URL(socket.url);
  assert.equal(url.protocol, "wss:");
  assert.equal(url.pathname, "/v1/web/terminal");
  assert.deepEqual(Array.from(url.searchParams.keys()).sort(), ["cols", "login", "node", "rows"]);
  assert.equal(url.searchParams.get("node"), "web-02");
  assert.equal(url.searchParams.get("cols"), "80");
  assert.equal(socket.url.includes(TICKET), false);
  assert.deepEqual(socket.protocols, [PROTOCOL, "jaunt-ticket." + TICKET]);
  assert.equal(window.location.href.includes(TICKET), false);
  assert.equal(states(), "Connecting…");
});

test("a CSRF refusal is retried once but a denial is not, and the denial shows one generic message", async () => {
  const replies = [json(403, { error: "forbidden" }), GRANT];
  ui = await open({ [TICKET_ROUTE]: replies }, "#/terminal?node=web-02&login=deploy");
  click(start());
  await until(() => rig.sockets.length > 0, "the retried ticket");
  assert.equal(ui.server.count("POST", "/v1/web/terminal/ticket"), 2);
  ui.stop();
  rig.sockets.length = 0;

  ui = await open({ [TICKET_ROUTE]: json(403, { error: "denied" }) }, "#/terminal?node=web-02&login=deploy");

  click(start());
  await until(() => bannerText().includes("Access denied"), "the denial");
  assert.equal(ui.server.count("POST", "/v1/web/terminal/ticket"), 1);
  assert.equal(rig.sockets.length, 0);
  assert.match(bannerText(), /node, the login or your access may have changed/);
  assert.equal(states(), "Not opened");
  assert.ok(byText(ui.root, "button", "Try again"));
  assert.equal(byText(ui.root, "button", "Reconnect"), undefined);
});

test("every ticket refusal has its own text and none of them opens a socket", async () => {
  const cases = [
    [json(429, { error: "limit" }), /Too many terminals/],
    [json(429, { error: "too_many_requests", retry_after: 7 }, { "Retry-After": "7" }), /Try again in 7 seconds/],
    [json(404, { error: "not_found" }), /The web terminal is turned off/],
    [json(400, { error: "invalid_request" }), /The request was refused/],
    [json(500, { error: "internal" }), /node became unavailable/],
    [json(200, { ticket: "short" }), /Unexpected reply/],
  ];
  for (const [reply, expected] of cases) {
    ui = await open({ [TICKET_ROUTE]: reply }, "#/terminal?node=web-02&login=deploy");
    click(start());
      await until(() => ui.root.querySelector(".term-banner").textContent !== "", String(expected));
    assert.match(bannerText(), expected);
    assert.equal(rig.sockets.length, 0);
    ui.stop();
  }
  ui = null;
});

test("a signed-out session on the ticket request shows the expired dialog and the ended state", async () => {
  ui = await open({ [TICKET_ROUTE]: json(401, { error: "unauthorized" }) }, "#/terminal?node=web-02&login=deploy");
  click(start());
  await until(() => document.querySelector("[role=dialog]"), "the expired dialog");
  assert.match(document.querySelector("[role=dialog]").textContent, /Session expired/);
  assert.match(bannerText(), /Signed out/);
});

test("nothing is sent before ready, and after it input goes out as binary frames in chunks of at most 64 KiB", async () => {
  const socket = await begin();
  const terminal = rig.terminals[0];
  assert.equal(terminal.options.disableStdin, true);
  socket.accept();
  terminal.init.onInput("early");
  assert.deepEqual(socket.sent, []);
  socket.control({ t: "ready", session_id: "s-1" });
  await settle();
  assert.equal(states(), "Connected");
  assert.equal(terminal.options.disableStdin, false);
  assert.ok(terminal.focused > 0);
  terminal.type("ls\r");
  terminal.type("é");
  assert.deepEqual(socket.input(), [[108, 115, 13], [195, 169]]);
  assert.equal(socket.sent.every((item) => typeof item === "string" || item instanceof Uint8Array), true);
  terminal.type("x".repeat(65536 * 2 + 5));
  assert.deepEqual(socket.sent.filter((item) => typeof item !== "string").slice(2).map((item) => item.length), [65536, 65536, 5]);
});

test("input is refused with a notice when the socket buffer is full", async () => {
  const socket = await begin();
  await ready(socket);
  socket.bufferedAmount = 1048576;
  rig.terminals[0].type("a");
  assert.deepEqual(socket.input(), []);
  assert.match(ui.root.querySelector(".term-note").textContent, /connection is busy/);
});

test("output goes to the terminal as bytes and never into the page", async () => {
  const socket = await begin();
  await ready(socket);
  const hostile = new TextEncoder().encode('<img src=x onerror="window.__pwned=1">\u001b]52;c;ZXZpbA==\u0007\u001b]0;pwned\u0007');
  socket.output(hostile);
  assert.equal(rig.terminals[0].written.join(""), new TextDecoder().decode(hostile));
  assert.equal(ui.root.querySelector("main img"), null);
  assert.equal(ui.root.textContent.includes("pwned"), false);
  assert.equal(document.title.includes("pwned"), false);
  socket.control('{"t":"ready","session_id":"<b>x</b>"}');
  socket.control("not json");
  socket.control({ t: "unknown" });
  assert.equal(ui.root.querySelector("main b"), null);
});

test("a window resize is debounced into one resize frame and an unchanged size sends nothing", async () => {
  const socket = await begin();
  await ready(socket);
  const sizes = () => socket.frames().filter((frame) => frame.t === "resize");
  assert.deepEqual(sizes(), []);
  rig.layout = { width: 1000, height: 500 };
  rig.observers[0]();
  rig.observers[0]();
  rig.layout = { width: 1200, height: 600 };
  rig.observers[0]();
  rig.clock.advance(149);
  assert.equal(sizes().length, 0);
  rig.clock.advance(2);
  assert.deepEqual(sizes(), [{ t: "resize", cols: 120, rows: 30 }]);
  rig.observers[0]();
  rig.clock.advance(200);
  assert.equal(sizes().length, 1);
});

test("the first size comes from the fitted terminal and is in the address", async () => {
  rig.layout = { width: 6000, height: 9000 };
  const socket = await begin();
  const url = new URL(socket.url);
  assert.equal(url.searchParams.get("cols"), "500");
  assert.equal(url.searchParams.get("rows"), "200");
});

test("a ping goes out every 20 seconds and the pong shows the round trip", async () => {
  const socket = await begin();
  await ready(socket);
  rig.clock.advance(20000);
  assert.deepEqual(socket.frames().filter((frame) => frame.t === "ping").length, 2);
  rig.clock.advance(38);
  socket.control({ t: "pong" });
  assert.match(ui.root.querySelector(".statusbar").textContent, /Latency38 ms/);
  rig.clock.advance(20000);
  assert.equal(socket.frames().filter((frame) => frame.t === "ping").length, 3);
  assert.equal(ui.server.count("POST", "/v1/web/terminal/ticket"), 1);
});

test("the first ping goes out as soon as the session is ready, so the latency shows at once", async () => {
  const socket = await begin();
  socket.accept();
  assert.equal(socket.frames().filter((frame) => frame.t === "ping").length, 0);
  socket.control({ t: "ready", session_id: "s-1" });
  await settle();
  assert.equal(socket.frames().filter((frame) => frame.t === "ping").length, 1);
  assert.equal(ui.root.querySelector(".statusbar .lat").closest(".item").hidden, true);
  rig.clock.advance(12);
  socket.control({ t: "pong", node_ms: 30 });
  assert.match(ui.root.querySelector(".statusbar").textContent, /Latency42 ms/);
  assert.equal(ui.root.querySelector(".statusbar .lat").closest(".item").hidden, false);
});

test("pings are not user input: after only pings Disconnect closes without asking", async () => {
  const socket = await begin();
  await ready(socket);
  for (let step = 0; step < 4; step += 1) {
    rig.clock.advance(5000);
    socket.control({ t: "pong" });
  }
  assert.ok(socket.frames().filter((frame) => frame.t === "ping").length >= 2);
  click(byText(ui.root, "button", "Disconnect"));
  assert.equal(document.querySelector("[role=dialog]"), null);
  assert.deepEqual(socket.closed, [1000, ""]);
});

test("the shell exit and every close code or error code end the session with its own text and never reconnect by themselves", async () => {
  const cases = [
    [[{ t: "exit", status: 3, signal: null }], 1000, /exited with status 3/, "Session ended"],
    [[{ t: "exit", status: null, signal: "SIGKILL" }], 1000, /ended on signal SIGKILL/, "Session ended"],
    [[], 1000, /server closed the session/, "Session ended"],
    [[{ t: "error", code: "denied" }], 1008, /Access denied/, "Session ended"],
    [[{ t: "error", code: "limit" }], 1008, /Too many terminals/, "Session ended"],
    [[{ t: "error", code: "timeout" }], 1008, /Time limit reached/, "Session ended"],
    [[{ t: "error", code: "timeout" }], 4002, /Closed for inactivity/, "Session ended"],
    [[{ t: "error", code: "unavailable" }], 1001, /node became unavailable/, "Connection lost"],
    [[{ t: "error", code: "revoked" }], 4001, /Access revoked/, "Cut"],
    [[], 4001, /Access revoked/, "Cut"],
    [[], 4002, /Closed for inactivity/, "Session ended"],
    [[{ t: "error", code: "stalled" }], 4003, /this page stopped taking output/, "Session ended"],
    [[], 4003, /this page stopped taking output/, "Session ended"],
    [[{ t: "error", code: "terminated" }], 4004, /Ended by an administrator/, "Ended"],
    [[], 4004, /Ended by an administrator/, "Ended"],
    [[], 1001, /node became unavailable/, "Connection lost"],
    [[], 1011, /node became unavailable/, "Connection lost"],
    [[{ t: "error", code: "unavailable" }], 1011, /connection to web-02 was lost/, "Connection lost"],
    [[], 1008, /refused a message from this page/, "Session ended"],
    [[], 1009, /message was too large/, "Session ended"],
    [[], 1006, /Connection lost/, "Connection lost"],
  ];
  for (const [frames, code, expected, state] of cases) {
    const socket = await begin();
    await ready(socket);
    for (const frame of frames) {
      socket.control(frame);
    }
    socket.drop(code);
    await settle();
    assert.match(bannerText(), expected, String(code) + " " + JSON.stringify(frames));
    assert.equal(states(), state, String(code) + " " + JSON.stringify(frames));
    if (state === "Connection lost") {
      assert.equal(bannerText().includes("Session ended"), false);
    }
    assert.equal(rig.terminals[0].options.disableStdin, true);
    rig.clock.advance(120000);
    await settle();
    assert.equal(rig.sockets.length, 1);
    assert.equal(ui.server.count("POST", "/v1/web/terminal/ticket"), 1);
    ui.stop();
    rig.sockets.length = 0;
    rig.terminals.length = 0;
  }
  ui = null;
});

test("a socket that closes before it opens says the connection failed, and a wrong subprotocol is refused", async () => {
  let socket = await begin();
  socket.drop(1006);
  await settle();
  assert.match(bannerText(), /Could not connect/);
  ui.stop();
  rig.sockets.length = 0;
  socket = await begin();
  socket.accept("jaunt-ticket." + TICKET);
  await settle();
  assert.match(bannerText(), /Unexpected reply/);
  assert.deepEqual(socket.closed, [1000, ""]);
});

test("reconnect opens a new session with a new ticket and clears the old screen", async () => {
  const socket = await begin();
  await ready(socket);
  socket.control({ t: "exit", status: 0, signal: null });
  socket.drop(1000);
  await settle();
  assert.equal(ui.root.querySelector(".sid .mono").textContent, "s-1");
  assert.match(bannerText(), /not resumed/);
  click(byText(ui.root, "button", "Reconnect"));
  await until(() => rig.sockets.length === 2, "the second socket");
  assert.equal(ui.server.count("POST", "/v1/web/terminal/ticket"), 2);
  assert.equal(rig.terminals.length, 2);
  assert.equal(rig.terminals[0].disposed, true);
  assert.equal(rig.terminals[1].written.length, 0);
  assert.equal(bannerText(), "");
  assert.equal(states(), "Connecting…");
  await ready(rig.sockets[1]);
  assert.equal(states(), "Connected");
  assert.equal(rig.terminals[1].options.disableStdin, false);
});

test("disconnect asks for confirmation only when there was input in the last 10 seconds", async () => {
  let socket = await begin();
  await ready(socket);
  click(byText(ui.root, "button", "Disconnect"));
  assert.equal(document.querySelector("[role=dialog]"), null);
  assert.deepEqual(socket.closed, [1000, ""]);
  assert.match(bannerText(), /You disconnected/);
  ui.stop();
  rig.sockets.length = 0;
  rig.terminals.length = 0;

  socket = await begin();
  await ready(socket);
  rig.terminals[0].type("a");
  rig.clock.advance(9000);
  click(byText(ui.root, "button", "Disconnect"));
  const dialog = document.querySelector("[role=dialog]");
  assert.ok(dialog);
  assert.equal(socket.closed, null);
  click(byText(dialog, "button", "Keep working"));
  assert.equal(socket.closed, null);
  rig.clock.advance(2000);
  click(byText(ui.root, "button", "Disconnect"));
  assert.equal(document.querySelector("[role=dialog]"), null);
  assert.deepEqual(socket.closed, [1000, ""]);
});

test("a confirmed disconnect closes the socket", async () => {
  const socket = await begin();
  await ready(socket);
  rig.terminals[0].type("a");
  click(byText(ui.root, "button", "Disconnect"));
  click(byText(document.querySelector("[role=dialog]"), "button", "Disconnect"));
  await settle();
  assert.deepEqual(socket.closed, [1000, ""]);
  assert.match(bannerText(), /You disconnected/);
});

test("the key bar sends control codes, escape sequences by cursor mode, and sticky modifiers apply once", async () => {
  rig.keyBar = true;
  const socket = await begin();
  await ready(socket);
  const terminal = rig.terminals[0];
  const key = (id) => click(ui.root.querySelector('.key-btn[data-key="' + id + '"]'));
  assert.equal(ui.root.querySelector(".keybar").hidden, false);
  key("esc");
  key("tab");
  key("up");
  key("pgup");
  key("pgdn");
  key("pipe");
  key("tilde");
  key("slash");
  key("dash");
  terminal.modes.applicationCursorKeysMode = true;
  key("left");
  terminal.modes.applicationCursorKeysMode = false;
  key("ctrl");
  assert.equal(ui.root.querySelector('.key-btn[data-key="ctrl"]').getAttribute("aria-pressed"), "true");
  terminal.type("c");
  terminal.type("c");
  key("ctrl");
  key("right");
  key("alt");
  terminal.type("x");
  key("alt");
  key("esc");
  const text = (bytes) => String.fromCharCode(...bytes);
  assert.deepEqual(
    socket.input().map(text),
    ["\u001b", "\t", "\u001b[A", "\u001b[5~", "\u001b[6~", "|", "~", "/", "-", "\u001bOD", "\u0003", "c", "\u001b[1;5C", "\u001bx", "\u001b\u001b"],
  );
  assert.equal(ui.root.querySelector('.key-btn[data-key="ctrl"]').getAttribute("aria-pressed"), "false");
  assert.ok(Array.from(ui.root.querySelectorAll(".key-btn")).every((button) => button.getAttribute("aria-label")));
});

test("the key bar can be shown or hidden by hand", async () => {
  await begin();
  const toggle = ui.root.querySelector('button[data-action="keys"]');
  assert.equal(ui.root.querySelector(".keybar").hidden, true);
  assert.equal(toggle.getAttribute("aria-pressed"), "false");
  click(toggle);
  assert.equal(ui.root.querySelector(".keybar").hidden, false);
  assert.equal(toggle.getAttribute("aria-pressed"), "true");
});

test("pasting removes every escape character, goes through the terminal and is refused before ready", async () => {
  const socket = await begin();
  const terminal = rig.terminals[0];
  const host = ui.root.querySelector(".term-host");
  const dispatch = (value) => {
    const event = new window.Event("paste", { bubbles: true, cancelable: true });
    event.clipboardData = { getData: () => value };
    host.dispatchEvent(event);
    return event;
  };
  assert.equal(dispatch("early").defaultPrevented, true);
  assert.deepEqual(terminal.pasted, []);
  assert.match(ui.root.querySelector(".term-note").textContent, /not connected/);
  await ready(socket);
  dispatch("ls\u001b[201~; rm -rf ~\u001b[200~");
  assert.deepEqual(terminal.pasted, ["ls[201~; rm -rf ~[200~"]);
  terminal.type("c");
  rig.clipboard.text = "from button";
  click(byText(ui.root, "button", "Paste"));
  await settle();
  assert.deepEqual(terminal.pasted, ["ls[201~; rm -rf ~[200~", "from button"]);
  rig.clipboard.denied = true;
  click(byText(ui.root, "button", "Paste"));
  await settle();
  assert.match(ui.root.querySelector(".term-note").textContent, /did not allow reading the clipboard/);
});

test("pasting while a modifier is sticky does not change the pasted text", async () => {
  rig.keyBar = true;
  const socket = await begin();
  await ready(socket);
  click(ui.root.querySelector('.key-btn[data-key="ctrl"]'));
  rig.clipboard.text = "abc";
  click(byText(ui.root, "button", "Paste"));
  await settle();
  assert.deepEqual(socket.input().map((bytes) => String.fromCharCode(...bytes)), ["abc"]);
});

test("copy sends the selection to the clipboard only on request and says when nothing is selected", async () => {
  const socket = await begin();
  await ready(socket);
  click(byText(ui.root, "button", "Copy selection"));
  await settle();
  assert.match(ui.root.querySelector(".term-note").textContent, /Nothing is selected/);
  rig.terminals[0].selection = "picked";
  click(byText(ui.root, "button", "Copy selection"));
  await settle();
  assert.deepEqual(rig.clipboard.written, ["picked"]);
  rig.clipboard.denied = true;
  click(byText(ui.root, "button", "Copy selection"));
  await settle();
  assert.match(ui.root.querySelector(".term-note").textContent, /did not allow copying/);
});

test("the text size buttons step through the sizes, store the choice and refit", async () => {
  const socket = await begin();
  await ready(socket);
  const terminal = rig.terminals[0];
  const smaller = ui.root.querySelector('button[aria-label="Smaller text"]');
  const larger = ui.root.querySelector('button[aria-label="Larger text"]');
  assert.equal(smaller.disabled, true);
  click(larger);
  assert.equal(terminal.options.fontSize, 16);
  assert.match(ui.root.querySelector(".term-size").textContent, /16 px/);
  assert.equal(localStorage.getItem("jaunt-terminal-font"), "16");
  rig.clock.advance(200);
  click(smaller);
  assert.equal(terminal.options.fontSize, 14);
  localStorage.removeItem("jaunt-terminal-font");
});

test("Ctrl+Alt+Esc and the Leave terminal button move focus out of the terminal", async () => {
  const socket = await begin();
  await ready(socket);
  const terminal = rig.terminals[0];
  const event = new window.KeyboardEvent("keydown", { key: "Escape", ctrlKey: true, altKey: true, cancelable: true });
  assert.equal(terminal.keyHandler(event), false);
  assert.equal(terminal.blurred, 1);
  assert.equal(document.activeElement, ui.root.querySelector(".statusbar"));
  assert.equal(terminal.keyHandler(new window.KeyboardEvent("keydown", { key: "Escape", cancelable: true })), true);
  click(byText(ui.root, "button", "Leave terminal"));
  assert.equal(terminal.blurred, 2);
  assert.match(ui.root.querySelector(".term-status").textContent, /Ctrl\+Alt\+Esc/);
});

test("closing the browser tab asks while a terminal is live, pagehide closes the socket and moving around the console keeps the terminal", async () => {
  let socket = await begin();
  await ready(socket);
  const ask = new window.Event("beforeunload", { cancelable: true });
  window.dispatchEvent(ask);
  assert.equal(ask.defaultPrevented, true);
  assert.equal(socket.closed, null);
  window.dispatchEvent(new window.Event("pagehide"));
  assert.deepEqual(socket.closed, [1000, ""]);
  ui.stop();
  rig.sockets.length = 0;
  rig.terminals.length = 0;

  socket = await begin();
  await ready(socket);
  const terminal = rig.terminals[0];
  window.location.hash = "#/nodes";
  await settle();
  assert.equal(socket.closed, null);
  assert.equal(terminal.disposed, false);
  assert.equal(ui.root.querySelector(".ws").hidden, true);
  assert.equal(ui.root.querySelector(".rail-count").textContent, "1");
  window.location.hash = "#/terminal";
  await settle();
  assert.equal(ui.root.querySelector(".ws").hidden, false);
  assert.equal(states(), "Connected");
  assert.equal(rig.sockets.length, 1);
  ui.stop();
  assert.deepEqual(socket.closed, [1000, ""]);
  assert.equal(terminal.disposed, true);
  assert.equal(rig.observers.length, 0);
  assert.equal(rig.clock.state.timers.length, 0);
  const idle = new window.Event("beforeunload", { cancelable: true });
  window.dispatchEvent(idle);
  assert.equal(idle.defaultPrevented, false);
  ui = null;
});

test("a terminal that cannot be loaded is reported and offers a retry", async () => {
  const { terminalHooks } = await import(HOOKS);
  terminalHooks.loadLibraries = async () => {
    throw new Error("missing");
  };
  ui = await open({}, "#/terminal?node=web-02&login=deploy");
  click(start());
  await until(() => bannerText().includes("could not be loaded"), "the failure");
  assert.equal(ui.server.count("POST", "/v1/web/terminal/ticket"), 0);
  assert.ok(byText(ui.root, "button", "Try again"));
  assert.equal(states(), "Not opened");
});

test("a terminal that cannot switch on its output protection does not open, says why and offers no retry", async () => {
  const { terminalHooks } = await import(HOOKS);
  const { UnsafeTerminalError } = await import("../../crates/jaunt-web/assets/assets/js/terminal/cells.js");
  terminalHooks.createTerminal = () => {
    throw new UnsafeTerminalError("the print path of the terminal library was not found");
  };
  ui = await open({}, "#/terminal?node=web-02&login=deploy");
  click(start());
  await until(() => bannerText().includes("cannot start safely"), "the failure");
  assert.equal(ui.server.count("POST", "/v1/web/terminal/ticket"), 0);
  assert.equal(rig.sockets.length, 0);
  assert.equal(byText(ui.root, "button", "Try again"), undefined);
  assert.equal(states(), "Not opened");
});

test("the session id, ticket and typed bytes never reach the address, storage or the document title", async () => {
  const socket = await begin();
  await ready(socket);
  rig.terminals[0].type("hunter2\r");
  const everything = [window.location.href, document.title, JSON.stringify({ ...localStorage }), JSON.stringify({ ...window.sessionStorage })].join("\n");
  assert.equal(everything.includes(TICKET), false);
  assert.equal(everything.includes("s-1"), false);
  assert.equal(everything.includes("hunter2"), false);
  assert.equal(document.title.includes("deploy@web-02"), true);
});

test("every cause a session can end with has a title, a text and a banner kind in the strings module", async () => {
  const { S } = await import("../../crates/jaunt-web/assets/assets/js/strings.js");
  const causes = ["exit", "closed", "user", "denied", "unavailable", "limit", "revoked", "terminated", "stalled", "timeout", "idle", "too_large", "policy", "lost", "connect_failed", "protocol", "expired", "disabled", "invalid", "busy", "network", "library", "unsafe"];
  for (const cause of causes) {
    const [title, body, kind] = S.terminal.session.causes[cause];
    const text = typeof body === "function" ? body("alice", "web-01", { limit: null, idleMinutes: null }) : body;
    assert.ok(title.length > 0 && text.length > 0, cause);
    assert.ok(["info", "warn", "danger"].includes(kind), cause);
  }
});

test("the fitted size follows the cell size, leaves room for the scrollbar and stays inside the server limits", async () => {
  const { fitSize } = await import("../../crates/jaunt-web/assets/assets/js/terminal/fit.js");
  const make = (cols, rows, cell, scrollbar = 0) => {
    const element = document.createElement("div");
    const screen = document.createElement("div");
    screen.className = "xterm-screen";
    screen.getBoundingClientRect = () => ({ width: cols * cell.width, height: rows * cell.height });
    const viewport = document.createElement("div");
    viewport.className = "xterm-viewport";
    Object.defineProperty(viewport, "offsetWidth", { value: 100 + scrollbar });
    Object.defineProperty(viewport, "clientWidth", { value: 100 });
    element.append(screen, viewport);
    return { cols, rows, element };
  };
  const host = (width, height) => ({ clientWidth: width, clientHeight: height });
  assert.deepEqual(fitSize(host(840, 410), make(80, 24, { width: 8.4, height: 17 })), { cols: 100, rows: 24 });
  assert.deepEqual(fitSize(host(840, 410), make(80, 24, { width: 8.4, height: 17 }, 14)), { cols: 98, rows: 24 });
  assert.deepEqual(fitSize(host(90000, 90000), make(80, 24, { width: 8, height: 16 })), { cols: 500, rows: 200 });
  assert.deepEqual(fitSize(host(3, 3), make(80, 24, { width: 8, height: 16 })), { cols: 2, rows: 1 });
  assert.equal(fitSize(host(0, 400), make(80, 24, { width: 8, height: 16 })), null);
  assert.equal(fitSize(host(400, 400), { cols: 80, rows: 24, element: document.createElement("div") }), null);
});

test("a modified click on the current page link is left to the browser", async () => {
  ui = await open({}, "#/terminal");
  const link = ui.root.querySelector('.rail a[href="#/terminal"]');
  const event = new window.MouseEvent("click", { bubbles: true, cancelable: true, ctrlKey: true });
  link.dispatchEvent(event);
  assert.equal(event.defaultPrevented, false);
});

test("a pending sticky modifier is not used up by focus or mouse reports and later keys still get it", async () => {
  rig.keyBar = true;
  const socket = await begin();
  await ready(socket);
  const terminal = rig.terminals[0];
  click(ui.root.querySelector('.key-btn[data-key="ctrl"]'));
  terminal.init.onInput("\u001b[I");
  terminal.init.onInput("\u001b[<0;10;5M");
  terminal.init.onInput("ab");
  assert.equal(ui.root.querySelector('.key-btn[data-key="ctrl"]').getAttribute("aria-pressed"), "true");
  terminal.type("c");
  assert.deepEqual(socket.input().map((bytes) => String.fromCharCode(...bytes)), ["\u001b[I", "\u001b[<0;10;5M", "ab", "\u0003"]);
});

test("replies stay byte-exact with a sticky modifier on, keep it pending and do not count as user input", async () => {
  rig.keyBar = true;
  const socket = await begin();
  await ready(socket);
  const terminal = rig.terminals[0];
  click(ui.root.querySelector('.key-btn[data-key="ctrl"]'));
  terminal.init.onReply("\u001b[?1;2c");
  assert.deepEqual(socket.input().map((bytes) => String.fromCharCode(...bytes)), ["\u001b[?1;2c"]);
  assert.equal(ui.root.querySelector('.key-btn[data-key="ctrl"]').getAttribute("aria-pressed"), "true");
  click(byText(ui.root, "button", "Disconnect"));
  assert.equal(document.querySelector("[role=dialog]"), null);
  assert.deepEqual(socket.closed, [1000, ""]);
});

test("a second ready frame does not start a second ping timer", async () => {
  const socket = await begin();
  await ready(socket);
  const timers = rig.clock.state.timers.length;
  socket.control({ t: "ready", session_id: "s-2" });
  assert.equal(rig.clock.state.timers.length, timers);
  rig.clock.advance(20000);
  assert.equal(socket.frames().filter((frame) => frame.t === "ping").length, 2);
});

test("an exit frame wins over an error frame in either order", async () => {
  for (const frames of [[{ t: "error", code: "denied" }, { t: "exit", status: 2, signal: null }], [{ t: "exit", status: 2, signal: null }, { t: "error", code: "denied" }]]) {
    const socket = await begin();
    await ready(socket);
    for (const frame of frames) {
      socket.control(frame);
    }
    socket.drop(1008);
    await settle();
    assert.match(bannerText(), /exited with status 2/);
    ui.stop();
    rig.sockets.length = 0;
    rig.terminals.length = 0;
  }
  ui = null;
});

test("a hostile session id on the first ready frame is never shown or kept", async () => {
  const socket = await begin();
  socket.accept();
  socket.control('{"t":"ready","session_id":"<b>x</b>"}');
  await settle();
  assert.equal(states(), "Connected");
  socket.drop(1000);
  await settle();
  assert.equal(ui.root.querySelector("main b"), null);
  assert.equal(ui.root.querySelector(".sid").hidden, true);
});

test("pagehide closes the socket with a normal close", async () => {
  const socket = await begin();
  await ready(socket);
  window.dispatchEvent(new window.Event("pagehide"));
  assert.deepEqual(socket.closed, [1000, ""]);
});

test("a peer that stays silent for 60 seconds is reported as lost and closed, while any inbound frame keeps it alive", async () => {
  let socket = await begin();
  await ready(socket);
  rig.clock.advance(40000);
  socket.control({ t: "pong" });
  rig.clock.advance(40000);
  assert.equal(socket.closed, null);
  rig.clock.advance(20000);
  assert.deepEqual(socket.closed, [1000, ""]);
  assert.match(bannerText(), /Connection lost/);
  assert.ok(byText(ui.root, "button", "Try again"));
  assert.equal(states(), "Connection lost");
  ui.stop();
  rig.sockets.length = 0;
  rig.terminals.length = 0;

  socket = await begin();
  await ready(socket);
  rig.clock.advance(50000);
  socket.output([65]);
  rig.clock.advance(50000);
  assert.equal(socket.closed, null);
});

test("a paste above the buffer limit says to paste in parts, a busy connection says to wait", async () => {
  const socket = await begin();
  await ready(socket);
  rig.clipboard.text = "x".repeat(1048576 + 1);
  click(byText(ui.root, "button", "Paste"));
  await settle();
  assert.deepEqual(socket.input(), []);
  assert.match(ui.root.querySelector(".term-note").textContent, /too large.*in parts/);
  socket.bufferedAmount = 1048576;
  rig.terminals[0].type("a");
  assert.match(ui.root.querySelector(".term-note").textContent, /connection is busy/);
});

test("a reconnect builds a fresh terminal and nothing from the old one reaches the new session", async () => {
  const socket = await begin();
  await ready(socket);
  const old = rig.terminals[0];
  socket.drop(1006);
  await settle();
  click(byText(ui.root, "button", "Try again"));
  await until(() => rig.sockets.length === 2, "the second socket");
  await ready(rig.sockets[1]);
  assert.notEqual(rig.terminals[1], old);
  assert.equal(old.disposed, true);
  old.init.onReply("\u001b[0n");
  old.init.onInput("late");
  assert.deepEqual(rig.sockets[1].input(), []);
});

test("the elapsed time stops ticking while the tab is hidden and goes on when it is shown again", async () => {
  const socket = await begin();
  await ready(socket);
  const elapsed = () => ui.root.querySelector(".term-elapsed").textContent;
  rig.clock.advance(3000);
  assert.equal(elapsed(), "00:03");
  setHidden(true);
  document.dispatchEvent(new window.Event("visibilitychange"));
  const timers = rig.clock.state.timers.length;
  rig.clock.advance(5000);
  assert.equal(elapsed(), "00:03");
  setHidden(false);
  document.dispatchEvent(new window.Event("visibilitychange"));
  assert.equal(elapsed(), "00:08");
  assert.equal(rig.clock.state.timers.length, timers + 1);
  rig.clock.advance(1000);
  assert.equal(elapsed(), "00:09");
});

test("output is split into small writes and oversized counts are clamped to the terminal size before they are written", async () => {
  const socket = await begin();
  await ready(socket);
  const terminal = rig.terminals[0];
  socket.output(Array.from(new TextEncoder().encode("x\u001b[5000S" + "y".repeat(5000))));
  const written = terminal.written;
  assert.equal(written.every((piece) => piece.length <= 2048), true);
  assert.equal(written.join(""), "x\u001b[" + terminal.rows + "S" + "y".repeat(5000));
});

test("a reply produced after the session ended is not sent", async () => {
  const socket = await begin();
  await ready(socket);
  socket.drop(1006);
  await settle();
  rig.terminals[0].init.onReply("\u001b[6n");
  assert.deepEqual(socket.input(), []);
});

test("only the documented chord leaves the terminal and every other key goes on to it", async () => {
  const socket = await begin();
  await ready(socket);
  const terminal = rig.terminals[0];
  const key = (init, type = "keydown") => new window.KeyboardEvent(type, { cancelable: true, ...init });
  const passes = [
    key({ key: "Escape" }),
    key({ key: "Escape", ctrlKey: true }),
    key({ key: "Escape", altKey: true }),
    key({ key: "Escape", ctrlKey: true, altKey: true }, "keyup"),
    key({ key: "Escape", ctrlKey: true, altKey: true }, "keypress"),
    key({ key: "a", ctrlKey: true, altKey: true }),
    key({ key: "Tab", ctrlKey: true, altKey: true }),
  ];
  for (const event of passes) {
    assert.equal(terminal.keyHandler(event), true, event.type + " " + event.key);
    assert.equal(event.defaultPrevented, false);
  }
  assert.equal(terminal.blurred, 0);
  const chord = key({ key: "Escape", ctrlKey: true, altKey: true });
  assert.equal(terminal.keyHandler(chord), false);
  assert.equal(chord.defaultPrevented, true);
  assert.equal(terminal.blurred, 1);
});

const pingTimer = () => rig.clock.state.timers.find((timer) => timer.every === 20000);

function lateTick(ms) {
  const timer = pingTimer();
  rig.clock.state.time += ms;
  timer.at = rig.clock.state.time + 20000;
  timer.callback();
}

test("a throttled tick in a hidden tab never declares the peer lost, whatever the silence", async () => {
  const socket = await begin();
  await ready(socket);
  setHidden(true);
  document.dispatchEvent(new window.Event("visibilitychange"));
  for (let step = 0; step < 12; step += 1) {
    lateTick(60000);
  }
  assert.equal(socket.closed, null);
  assert.equal(states(), "Connected");
  assert.equal(socket.frames().filter((frame) => frame.t === "ping").length, 13);
  setHidden(false);
  document.dispatchEvent(new window.Event("visibilitychange"));
  rig.clock.advance(59000);
  assert.equal(socket.closed, null);
  rig.clock.advance(11000);
  assert.deepEqual(socket.closed, [1000, ""]);
  assert.match(bannerText(), /Connection lost/);
});

test("with the tab visible 70 seconds of silence is a loss and a pong at 59.9 seconds starts the count again", async () => {
  let socket = await begin();
  await ready(socket);
  rig.clock.advance(70000);
  assert.deepEqual(socket.closed, [1000, ""]);
  ui.stop();
  rig.sockets.length = 0;
  rig.terminals.length = 0;

  socket = await begin();
  await ready(socket);
  rig.clock.advance(59900);
  socket.control({ t: "pong" });
  rig.clock.advance(20000);
  assert.equal(socket.closed, null);
  rig.clock.advance(40100);
  assert.deepEqual(socket.closed, [1000, ""]);
});

test("coming back to the tab gives a full new interval before any verdict", async () => {
  const socket = await begin();
  await ready(socket);
  rig.clock.advance(50000);
  setHidden(true);
  document.dispatchEvent(new window.Event("visibilitychange"));
  setHidden(false);
  document.dispatchEvent(new window.Event("visibilitychange"));
  rig.clock.advance(50000);
  assert.equal(socket.closed, null);
  rig.clock.advance(20000);
  assert.deepEqual(socket.closed, [1000, ""]);
});

test("a late check at the full silence counts for nothing until two checks have come on time", async () => {
  const socket = await begin();
  await ready(socket);
  lateTick(60000);
  assert.equal(socket.closed, null);
  rig.clock.advance(20000);
  assert.equal(socket.closed, null);
  rig.clock.advance(20000);
  assert.deepEqual(socket.closed, [1000, ""]);
});

test("a link that opens elsewhere is not intercepted even when it points at the current page", async () => {
  ui = await open({}, "#/terminal");
  const link = ui.root.querySelector('.rail a[href="#/terminal"]');
  link.setAttribute("target", "_blank");
  const blank = new window.MouseEvent("click", { bubbles: true, cancelable: true });
  link.dispatchEvent(blank);
  assert.equal(blank.defaultPrevented, false);
  link.setAttribute("target", "_self");
  const same = new window.MouseEvent("click", { bubbles: true, cancelable: true });
  link.dispatchEvent(same);
  assert.equal(same.defaultPrevented, true);
});

test("a hidden tab whose timers still run on time is not declared lost either", async () => {
  const socket = await begin();
  await ready(socket);
  setHidden(true);
  document.dispatchEvent(new window.Event("visibilitychange"));
  rig.clock.advance(300000);
  assert.equal(socket.closed, null);
  assert.equal(states(), "Connected");
});
