import assert from "node:assert/strict";
import { test } from "node:test";

import { HOSTILE } from "../fixtures.mjs";
import { byText, click, json, settle, until } from "./support.mjs";
import { GRANT, HOOKS, TICKET_ROUTE, bannerOf, pane, stateOf, useRig } from "./workspace-support.mjs";

const env = useRig();
async function mountOpen(extra = {}) {
  await env.mount(extra, "#/terminal");
  await env.chooseAndOpen("web-02", "deploy");
}

async function begin(extra = {}) {
  await mountOpen(extra);
  await until(() => env.rig.sockets.length === 1, "the socket");
  return env.rig.sockets[0];
}

async function readyAt(extra = {}, fields = {}) {
  const socket = await begin(extra);
  await env.ready(socket, fields);
  return socket;
}

function measure(socket, clientMs, nodeMs) {
  const at = env.rig.clock.state.time;
  env.rig.clock.advance((Math.floor(at / 20000) + 1) * 20000 - at);
  env.rig.clock.advance(clientMs);
  socket.control(nodeMs === undefined ? { t: "pong" } : { t: "pong", node_ms: nodeMs });
}

function alive(socket, ms) {
  for (let spent = 0; spent < ms; spent += 5000) {
    env.rig.clock.advance(Math.min(5000, ms - spent));
    socket.control({ t: "pong" });
  }
}

const head = () => pane(env.ui.root).querySelector(".statusbar");
const line = () => pane(env.ui.root).querySelector(".term-status");
const title = () => pane(env.ui.root).querySelector(".term-banner .banner-title").textContent;

test("the header latency is the browser leg plus the node leg, with bars, the number and a word, and the bands change above 150 and 400 ms", async () => {
  const socket = await readyAt();
  const cases = [
    [40, undefined, "good", "40 ms", 3, "Good"],
    [18, 24, "good", "42 ms", 3, "Good"],
    [100, 50, "good", "150 ms", 3, "Good"],
    [100, 51, "slow", "151 ms", 2, "Slow"],
    [200, 200, "slow", "400 ms", 2, "Slow"],
    [200, 201, "poor", "401 ms", 1, "Poor"],
    [900, undefined, "poor", "900 ms", 1, "Poor"],
  ];
  assert.equal(head().querySelector(".lat").closest(".item").hidden, true);
  for (const [client, node, band, shown, bars, word] of cases) {
    measure(socket, client, node);
    const lat = head().querySelector(".lat");
    assert.equal(lat.className, "lat lat-" + band, shown);
    assert.equal(lat.querySelector(".mono").textContent, shown);
    assert.equal(lat.querySelectorAll(".lat-bars i.on").length, bars, shown);
    assert.equal(head().querySelector(".lat-word").textContent, word);
    assert.equal(lat.querySelector(".lat-bars").getAttribute("aria-hidden"), "true");
  }
  assert.match(head().textContent, /Latency.*900 msPoor/);
});

test("the status line splits the latency into you to server and server to node, and shows nothing for the node leg when node_ms is absent or invalid", async () => {
  const socket = await readyAt();
  assert.equal(line().querySelector(".w-only[hidden]") !== null, true);
  measure(socket, 18, 24);
  assert.equal(line().textContent.includes("Latency: you to server 18 ms, server to node 24 ms"), true);
  measure(socket, 30);
  assert.equal(line().textContent.includes("Latency: you to server 30 ms"), true);
  assert.equal(line().textContent.includes("server to node"), false);
  for (const bad of [-5, "24", null, 1e12, true, { ms: 1 }]) {
    measure(socket, 20, bad);
    assert.equal(line().textContent.includes("server to node"), false, JSON.stringify(bad));
    assert.equal(head().querySelector(".lat .mono").textContent, "20 ms", JSON.stringify(bad));
  }
  measure(socket, 20, 0);
  assert.equal(line().textContent.includes("server to node 0 ms"), true);
});

test("the status line shows the terminal size and how many terminals closing the browser tab would end", async () => {
  const socket = await readyAt();
  assert.equal(line().querySelector(".mono").textContent, "80 \u00d7 20");
  assert.match(line().textContent, /Closing this browser tab ends this terminal\./);
  assert.match(line().textContent, /Keyboard focus stays in the terminal\. Ctrl\+Alt\+Esc leaves it, Ctrl\+Alt\+PgUp\/PgDn switches terminals\./);
  await env.openTab("web-01", "alice");
  assert.match(line().textContent, /Closing this browser tab ends all 2 terminals\./);
  assert.ok(socket);
});

test("the short session id shows eight characters and Copy puts the full id on the clipboard, saying so, or says it was refused", async () => {
  const socket = await begin();
  const full = "0123456789abcdef-long.id";
  await env.ready(socket, { session_id: full });
  const item = head().querySelector(".sid");
  assert.equal(item.hidden, false);
  assert.equal(item.querySelector(".mono").textContent, "01234567");
  const copy = item.querySelector("button");
  assert.equal(copy.getAttribute("aria-label"), "Copy the full session id");
  click(copy);
  await settle();
  assert.deepEqual(env.rig.clipboard.written, [full]);
  assert.match(pane(env.ui.root).querySelector(".term-note").textContent, /Session id copied/);
  env.rig.clipboard.denied = true;
  click(copy);
  await settle();
  assert.match(pane(env.ui.root).querySelector(".term-note").textContent, /did not allow copying/);
  assert.equal(env.rig.clipboard.written.length, 1);
});

test("the recording indicator says what the node reported and shows nothing for a missing or unknown value", async () => {
  const cases = [
    ["full", "b-rec", "This session is recorded", "Recorded"],
    ["output", "b-ro", "Output is recorded, input is not", "Output only"],
    ["off", "b-off", "Not recorded", "Not recorded"],
  ];
  for (const [mode, className, long, short] of cases) {
    const socket = await begin();
    await env.ready(socket, { recording: mode });
    const badge = head().querySelector(".badge." + className);
    assert.equal(badge.querySelector(".w-only").textContent, long);
    assert.equal(badge.querySelector(".n-only").textContent, short);
    assert.equal(badge.closest(".item").hidden, false);
    env.ui.stop();
    env.rig.sockets.length = 0;
    env.rig.terminals.length = 0;
  }
  for (const value of [undefined, "partial", 5, null, ["full"]]) {
    const socket = await begin();
    await env.ready(socket, { recording: value });
    assert.equal(head().querySelector(".badge.b-rec, .badge.b-ro"), null, JSON.stringify(value));
    assert.equal(head().querySelector(".badge[class*=b-off]"), null);
    env.ui.stop();
    env.rig.sockets.length = 0;
    env.rig.terminals.length = 0;
  }
  env.ui = null;
});

const steps = () => Array.from(pane(env.ui.root).querySelectorAll(".term-steps li")).map((item) => [item.textContent.replace(/^\S/, "").replace(", done", ""), item.classList.contains("done") ? "done" : item.getAttribute("aria-current") === "step" ? "now" : "next"]);

test("the connection steps follow the progress frames, the account step appears only when announced and its banner is shown once", async () => {
  let release = () => undefined;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  await mountOpen({ [TICKET_ROUTE]: async () => (await gate, GRANT) });
  await settle();
  assert.deepEqual(steps(), [["Ticket", "now"], ["Reaching web-02", "next"], ["Starting the shell", "next"]]);
  assert.equal(stateOf(env.ui.root), "Getting a ticket…");
  assert.match(pane(env.ui.root).querySelector(".term-steps").textContent, /Keys typed now are not sent/);
  release();
  await until(() => env.rig.sockets.length === 1, "the socket");
  const socket = env.rig.sockets[0];
  assert.deepEqual(steps(), [["Ticket", "done"], ["Reaching web-02", "now"], ["Starting the shell", "next"]]);
  assert.equal(stateOf(env.ui.root), "Connecting…");
  socket.accept();
  socket.control({ t: "progress", stage: "node" });
  socket.control({ t: "progress", stage: "<img src=x>" });
  socket.control({ t: "progress" });
  socket.control({ t: "progress", stage: "ticket" });
  assert.deepEqual(steps(), [["Ticket", "done"], ["Reaching web-02", "now"], ["Starting the shell", "next"]]);
  assert.equal(bannerOf(env.ui.root), "");
  socket.control({ t: "progress", stage: "account" });
  socket.control({ t: "progress", stage: "account" });
  assert.deepEqual(steps(), [["Ticket", "done"], ["Reaching web-02", "done"], ["Creating your account", "now"], ["Starting the shell", "next"]]);
  assert.equal(pane(env.ui.root).querySelectorAll(".term-banner .banner").length, 1);
  assert.match(bannerOf(env.ui.root), /Creating your account deploy on web-02…/);
  assert.equal(stateOf(env.ui.root), "Creating account…");
  socket.control({ t: "progress", stage: "shell" });
  assert.deepEqual(steps(), [["Ticket", "done"], ["Reaching web-02", "done"], ["Creating your account", "done"], ["Starting the shell", "now"]]);
  socket.control({ t: "ready", session_id: "s-1", account_created: true, home: "/home/deploy" });
  await settle();
  assert.equal(pane(env.ui.root).querySelector(".term-steps").children.length, 0);
  assert.equal(pane(env.ui.root).querySelectorAll(".term-banner .banner").length, 1);
  assert.match(bannerOf(env.ui.root), /^Account created\./);
});

test("without an account step the list has three steps and a progress frame after ready changes nothing", async () => {
  const socket = await begin();
  socket.accept();
  socket.control({ t: "progress", stage: "node" });
  socket.control({ t: "progress", stage: "shell" });
  assert.deepEqual(steps(), [["Ticket", "done"], ["Reaching web-02", "done"], ["Starting the shell", "now"]]);
  socket.control({ t: "ready", session_id: "s-1" });
  await settle();
  socket.control({ t: "progress", stage: "account" });
  assert.equal(pane(env.ui.root).querySelector(".term-steps").children.length, 0);
  assert.equal(bannerOf(env.ui.root), "");
});

test("a refusal before ready keeps the steps where it stopped and a refusal at the account step shows the reference", async () => {
  const socket = await begin();
  socket.accept();
  socket.control({ t: "progress", stage: "account" });
  socket.control({ t: "error", code: "account_refused", ref: "H-9D0311FE" });
  socket.drop(1008);
  await settle();
  assert.deepEqual(steps(), [["Ticket", "done"], ["Reaching web-02", "done"], ["Creating your account", "now"], ["Starting the shell", "next"]]);
  assert.match(bannerOf(env.ui.root), /Your account could not be created\./);
  assert.equal(pane(env.ui.root).querySelector(".ref .mono").textContent, "H-9D0311FE");
});

test("a refusal before any socket or a missing account leaves no steps, and a node that cannot be reached keeps them", async () => {
  await mountOpen({ [TICKET_ROUTE]: json(403, { error: "denied", ref: "D-4C1E82A9" }) });
  await until(() => bannerOf(env.ui.root) !== "", "the refusal");
  assert.equal(pane(env.ui.root).querySelector(".term-steps").children.length, 0);
  env.ui.stop();
  env.rig.sockets.length = 0;
  let socket = await begin();
  socket.accept();
  socket.control({ t: "progress", stage: "node" });
  socket.control({ t: "error", code: "no_account", ref: "D-0B77E310" });
  socket.drop(1008);
  await settle();
  assert.equal(pane(env.ui.root).querySelector(".term-steps").children.length, 0);
  assert.match(bannerOf(env.ui.root), /There is no account deploy on web-02\./);
  env.ui.stop();
  env.rig.sockets.length = 0;
  socket = await begin();
  socket.accept();
  socket.control({ t: "progress", stage: "node" });
  socket.control({ t: "error", code: "unavailable" });
  socket.drop(1011);
  await settle();
  assert.deepEqual(steps(), [["Ticket", "done"], ["Reaching web-02", "now"], ["Starting the shell", "next"]]);
  assert.equal(pane(env.ui.root).querySelector(".term-steps p"), null);
});

test("a ticket refusal shows its reference in the copyable form only when it is a D- or H- reference", async () => {
  const cases = [
    [json(403, { error: "denied", ref: "D-4C1E82A9" }), "D-4C1E82A9"],
    [json(403, { error: "denied", ref: "H-4C1E82A9" }), "H-4C1E82A9"],
    [json(429, { error: "limit", open: 4, max: 4, ref: "D-0B77E310" }), "D-0B77E310"],
    [json(403, { error: "denied", ref: "d-4c1e82a9" }), null],
    [json(403, { error: "denied", ref: HOSTILE.tag }), null],
    [json(403, { error: "denied", ref: "D-4C1E82A9 " }), null],
    [json(403, { error: "denied", ref: 7 }), null],
    [json(403, { error: "denied" }), null],
    [json(429, { error: "limit", ref: "<b>D-4C1E82A9</b>" }), null],
  ];
  for (const [reply, shown] of cases) {
    await mountOpen({ [TICKET_ROUTE]: reply });
    await until(() => bannerOf(env.ui.root) !== "", "the refusal");
    const ref = pane(env.ui.root).querySelector(".term-banner .ref .mono");
    if (shown === null) {
      assert.equal(ref, null, JSON.stringify(reply.body));
    } else {
      assert.equal(ref.textContent, shown);
      click(pane(env.ui.root).querySelector(".term-banner .ref button"));
      await settle();
      assert.deepEqual(env.rig.clipboard.written.at(-1), shown);
    }
    assert.equal(pane(env.ui.root).querySelector(".term-banner img, .term-banner b"), null);
    env.ui.stop();
    env.ui = null;
  }
});

test("the limit text uses the numbers of the answer only when both are sensible, and always says other browsers count", async () => {
  const cases = [
    [{ error: "limit", open: 3, max: 4 }, /You have 3 terminals open, and 4 is the most allowed at once\./],
    [{ error: "limit", open: "3", max: 4 }, /You already have the most terminals open that are allowed at once\./],
    [{ error: "limit", open: -1, max: 4 }, /You already have the most terminals open that are allowed at once\./],
    [{ error: "limit", open: 3 }, /You already have the most terminals open that are allowed at once\./],
    [{ error: "limit", open: 4, max: 1e9 }, /You already have the most terminals open that are allowed at once\./],
  ];
  for (const [body, expected] of cases) {
    await mountOpen({ [TICKET_ROUTE]: json(429, body) });
    await until(() => bannerOf(env.ui.root) !== "", "the limit text");
    assert.match(bannerOf(env.ui.root), expected, JSON.stringify(body));
    assert.match(bannerOf(env.ui.root), /other browser tabs or on other devices count too/);
    env.ui.stop();
    env.ui = null;
  }
});

test("every ending has its own state word and banner text, and the idle text names the configured time", async () => {
  const cases = [
    [4001, [{ t: "error", code: "revoked" }], "Cut", /^Access revoked\. An administrator revoked your access/, ["Close terminal"]],
    [4004, [{ t: "error", code: "terminated" }], "Ended", /^Ended by an administrator\. An administrator ended this session\. You can open a new one/, ["Reconnect", "Close terminal"]],
    [4003, [{ t: "error", code: "stalled" }], "Session ended", /^Closed: this page stopped taking output\. For more than a minute/, ["Reconnect", "Close terminal"]],
    [4002, [{ t: "error", code: "timeout" }], "Session ended", /^Closed for inactivity\. The session had no input or output for 30 minutes and was closed\./, ["Reconnect", "Close terminal"]],
    [1008, [{ t: "error", code: "timeout" }], "Session ended", /^Time limit reached\. The session reached its maximum duration/, ["Reconnect", "Close terminal"]],
    [1011, [], "Connection lost", /^The node became unavailable\. The connection to web-02 was lost, or the node went offline\./, ["Reconnect", "Close terminal"]],
    [1000, [{ t: "exit", status: 0, signal: null }], "Session ended", /^Session ended\. The shell exited with status 0\./, ["Reconnect", "Close terminal"]],
  ];
  for (const [code, frames, state, expected, actions] of cases) {
    const socket = await readyAt();
    for (const frame of frames) {
      socket.control(frame);
    }
    socket.drop(code);
    await settle();
    assert.match(bannerOf(env.ui.root), expected, String(code));
    assert.equal(stateOf(env.ui.root), state);
    assert.deepEqual(Array.from(pane(env.ui.root).querySelectorAll(".term-banner .actions .btn")).map((item) => item.textContent), actions, String(code));
    env.ui.stop();
    env.rig.sockets.length = 0;
    env.rig.terminals.length = 0;
  }
  env.ui = null;
});

test("the denied and limit refusals offer to choose again or to look at the open terminals, and Choose another node opens quick open", async () => {
  await mountOpen({ [TICKET_ROUTE]: json(403, { error: "denied" }) });
  await until(() => bannerOf(env.ui.root) !== "", "the refusal");
  assert.deepEqual(Array.from(pane(env.ui.root).querySelectorAll(".term-banner .actions .btn")).map((item) => item.textContent), ["Try again", "Choose another node"]);
  click(byText(pane(env.ui.root), "button", "Choose another node"));
  assert.ok(document.querySelector("[role=dialog].quick"));
});

const keepOpen = () => byText(pane(env.ui.root), "button", "Keep open");
const activeFrames = (socket) => socket.frames().filter((frame) => frame.t === "active");

async function trusting() {
  const { terminalHooks } = await import(HOOKS);
  const original = terminalHooks.isGesture;
  terminalHooks.isGesture = () => true;
  return () => {
    terminalHooks.isGesture = original;
  };
}

test("an idle frame shows a countdown banner with Keep open, the tab shows attention, and screen readers hear it at the start and at 30 seconds only", async () => {
  const socket = await readyAt();
  socket.control({ t: "idle", seconds_left: 112 });
  assert.equal(title(), "This terminal closes in 1:52.");
  assert.match(bannerOf(env.ui.root), /Nothing happened in it for 28 minutes\. Type in the terminal or choose Keep open\./);
  assert.ok(keepOpen());
  assert.equal(stateOf(env.ui.root), "Idle");
  assert.equal(pane(env.ui.root).querySelector(".term-banner .banner").getAttribute("role"), null);
  const live = pane(env.ui.root).querySelector(".term-pane > p.visually-hidden, p.visually-hidden[role=status]");
  assert.equal(live.textContent, "This terminal closes in 1:52 unless you keep it open.");
  const tab = env.ui.root.querySelector('[role="tab"]');
  assert.equal(tab.querySelector(".st").textContent, "▲");
  assert.match(tab.textContent, /Needs attention, closes soon/);
  alive(socket, 1000);
  assert.equal(title(), "This terminal closes in 1:51.");
  assert.equal(live.textContent, "This terminal closes in 1:52 unless you keep it open.");
  alive(socket, 80000);
  assert.equal(title(), "This terminal closes in 0:31.");
  alive(socket, 1000);
  assert.equal(title(), "This terminal closes in 0:30.");
  assert.equal(live.textContent, "This terminal closes in 0:30 unless you keep it open.");
  alive(socket, 1000);
  assert.equal(live.textContent, "This terminal closes in 0:30 unless you keep it open.");
  alive(socket, 60000);
  assert.equal(title(), "This terminal closes in 0:00.");
});

test("a new idle frame sets the countdown again and the local count never runs past the server value", async () => {
  const socket = await readyAt();
  socket.control({ t: "idle", seconds_left: 120 });
  alive(socket, 50000);
  assert.equal(title(), "This terminal closes in 1:10.");
  socket.control({ t: "idle", seconds_left: 30 });
  assert.equal(title(), "This terminal closes in 0:30.");
  alive(socket, 5000);
  assert.equal(title(), "This terminal closes in 0:25.");
});

test("without a known idle time the warning says nothing happened for a while and the closing text does not name minutes", async () => {
  const socket = await readyAt({ "GET /v1/web/terminal/limits": json(404, { error: "not_found" }) });
  socket.control({ t: "idle", seconds_left: 100 });
  assert.match(bannerOf(env.ui.root), /Nothing happened in it for a while\. Type in the terminal or choose Keep open\./);
  socket.drop(4002);
  await settle();
  assert.match(bannerOf(env.ui.root), /had no input or output for too long and was closed\./);
});

test("an idle frame with a value that is not a number of seconds, or before ready, shows nothing", async () => {
  const socket = await begin();
  socket.accept();
  socket.control({ t: "idle", seconds_left: 60 });
  assert.equal(bannerOf(env.ui.root), "");
  await env.ready(socket);
  for (const value of [-1, 1.5, "60", null, 86401, undefined, [60]]) {
    socket.control({ t: "idle", seconds_left: value });
    assert.equal(bannerOf(env.ui.root), "", JSON.stringify(value));
  }
  assert.equal(stateOf(env.ui.root), "Connected");
});

test("Keep open sends active only from a real click and at most once in ten seconds, then the banner goes away", async () => {
  const socket = await readyAt();
  socket.control({ t: "idle", seconds_left: 100 });
  click(keepOpen());
  assert.deepEqual(activeFrames(socket), []);
  assert.ok(keepOpen());
  const restore = await trusting();
  try {
    click(keepOpen());
    assert.deepEqual(activeFrames(socket), [{ t: "active" }]);
    assert.equal(bannerOf(env.ui.root), "");
    assert.equal(stateOf(env.ui.root), "Connected");
    assert.match(env.ui.root.querySelector('[role="tab"]').textContent, /Connected/);
    env.rig.clock.advance(4000);
    socket.control({ t: "idle", seconds_left: 100 });
    click(keepOpen());
    assert.equal(activeFrames(socket).length, 1);
    assert.equal(bannerOf(env.ui.root), "");
    env.rig.clock.advance(7000);
    socket.control({ t: "idle", seconds_left: 100 });
    click(keepOpen());
    assert.equal(activeFrames(socket).length, 2);
  } finally {
    restore();
  }
});

test("ping and pong never count as activity and terminal replies leave the warning up", async () => {
  const socket = await readyAt();
  socket.control({ t: "idle", seconds_left: 100 });
  alive(socket, 45000);
  assert.deepEqual(activeFrames(socket), []);
  assert.ok(socket.frames().some((frame) => frame.t === "ping"));
  assert.match(title(), /^This terminal closes in/);
  env.rig.terminals[0].init.onReply("\u001b[0n");
  assert.deepEqual(activeFrames(socket), []);
  assert.match(title(), /^This terminal closes in/);
});

test("typing in the terminal ends the warning and tells the server once", async () => {
  const socket = await readyAt();
  socket.control({ t: "idle", seconds_left: 100 });
  env.rig.terminals[0].type("x");
  env.rig.terminals[0].type("y");
  assert.deepEqual(activeFrames(socket), [{ t: "active" }]);
  assert.equal(bannerOf(env.ui.root), "");
  assert.equal(stateOf(env.ui.root), "Connected");
});

test("an ending replaces the idle warning and nothing is left counting down", async () => {
  const socket = await readyAt();
  socket.control({ t: "idle", seconds_left: 100 });
  socket.control({ t: "error", code: "timeout" });
  socket.drop(4002);
  await settle();
  assert.match(bannerOf(env.ui.root), /^Closed for inactivity\./);
  assert.equal(pane(env.ui.root).querySelectorAll(".term-banner .banner").length, 1);
  assert.equal(env.rig.clock.state.timers.length, 1);
});

test("an idle warning on a terminal that is not shown marks its tab and is announced", async () => {
  await mountOpen({});
  await until(() => env.rig.sockets.length === 1, "the first socket");
  const first = env.rig.sockets[0];
  await env.ready(first);
  await env.openTab("web-01", "alice");
  first.control({ t: "idle", seconds_left: 100 });
  const tabs = Array.from(env.ui.root.querySelectorAll('[role="tab"]'));
  assert.equal(tabs[0].querySelector(".st").textContent, "▲");
  assert.equal(tabs[0].getAttribute("aria-selected"), "false");
  assert.match(env.ui.root.querySelector('[role="status"][aria-live="polite"]').textContent, /deploy@web-02: closes soon unless you keep it open/);
});

test("the idle countdown starts from at most one hour even when the server says more, and an absurd value is ignored", async () => {
  const socket = await readyAt();
  socket.control({ t: "idle", seconds_left: 86400 });
  assert.equal(title(), "This terminal closes in 60:00.");
  socket.control({ t: "idle", seconds_left: 90000 });
  assert.equal(title(), "This terminal closes in 60:00.");
  alive(socket, 1000);
  assert.equal(title(), "This terminal closes in 59:59.");
});

test("when the session ends the idle warning and its timer are gone and the text never changes again", async () => {
  const socket = await readyAt();
  socket.control({ t: "idle", seconds_left: 100 });
  assert.equal(env.rig.clock.state.timers.filter((timer) => timer.every === 1000).length, 1);
  socket.drop(1006);
  await settle();
  assert.equal(env.rig.clock.state.timers.filter((timer) => timer.every === 1000).length, 0);
  const before = bannerOf(env.ui.root);
  assert.equal(before.includes("This terminal closes in"), false);
  env.rig.clock.advance(30000);
  assert.equal(bannerOf(env.ui.root), before);
  assert.equal(pane(env.ui.root).querySelector(".visually-hidden[role=status]").textContent, "");
});

test("a terminal that could not be opened shows the header and the banner only, and a retry brings the toolbar and the screen back", async () => {
  await mountOpen({ [TICKET_ROUTE]: [json(403, { error: "denied" }), GRANT] });
  await until(() => bannerOf(env.ui.root) !== "", "the refusal");
  assert.equal(pane(env.ui.root).querySelector(".term-tools").hidden, true);
  assert.equal(pane(env.ui.root).querySelector(".ws-split").hidden, true);
  assert.equal(pane(env.ui.root).querySelector(".term-steps").children.length, 0);
  click(byText(pane(env.ui.root), "button", "Try again"));
  await until(() => env.rig.sockets.length === 1, "the socket");
  assert.equal(pane(env.ui.root).querySelector(".term-tools").hidden, false);
  assert.equal(pane(env.ui.root).querySelector(".ws-split").hidden, false);
});

test("a finished, lost or refused session keeps no live data: the latency and the recording badge go, the session id stays", async () => {
  const endings = [
    (socket) => (socket.control({ t: "exit", status: 0, signal: null }), socket.drop(1000)),
    (socket) => socket.drop(1006),
    (socket) => (socket.control({ t: "error", code: "revoked" }), socket.drop(4001)),
    (socket) => (socket.control({ t: "error", code: "unavailable" }), socket.drop(1011)),
  ];
  for (const end of endings) {
    const socket = await readyAt({}, { recording: "full" });
    measure(socket, 18, 24);
    assert.equal(head().querySelector(".lat").closest(".item").hidden, false);
    assert.equal(head().querySelector(".badge.b-rec").closest(".item").hidden, false);
    end(socket);
    await settle();
    assert.equal(head().querySelector(".lat").closest(".item").hidden, true);
    assert.equal(head().querySelector(".badge.b-rec"), null);
    assert.equal(line().querySelector(".w-only[hidden]") !== null, true);
    assert.equal(line().textContent.includes("server to node"), false);
    assert.equal(head().querySelector(".sid").hidden, false);
    assert.equal(head().querySelector(".sid .mono").textContent.length > 0, true);
    env.ui.stop();
    env.rig.sockets.length = 0;
    env.rig.terminals.length = 0;
  }
  env.ui = null;
});

test("the note about reconnecting is shown only when the banner offers to reconnect", async () => {
  for (const [code, frames, offered] of [[1011, [], true], [4001, [{ t: "error", code: "revoked" }], false]]) {
    const socket = await readyAt();
    for (const frame of frames) {
      socket.control(frame);
    }
    socket.drop(code);
    await settle();
    assert.equal(bannerOf(env.ui.root).includes("Reconnect opens a new session"), offered, String(code));
    env.ui.stop();
    env.rig.sockets.length = 0;
    env.rig.terminals.length = 0;
  }
  env.ui = null;
});
