import assert from "node:assert/strict";
import { test } from "node:test";

import { ALL, HOSTILE, NOW, node } from "../fixtures.mjs";
import { byText, click, json, press, settle, type, until } from "./support.mjs";
import { CONFIG_ROUTE, CONFIG, LIMITS_ROUTE, RECENT_ROUTE, TARGETS_ROUTE, pane, useRig } from "./workspace-support.mjs";

const env = useRig();

const nodesPage = (nodes) => json(200, { nodes, next: null, pending_enrolments: 0 });
const NODES = [node({ id: "n-1", name: "web-01" }), node({ id: "n-2", name: "db-01" }), node({ id: "n-3", name: "web 03" })];
const TARGETS = [
  { node: "web-01", labels: {}, connected: true, pinned: false, logins: ["deploy", "alice", "root"], hidden_logins: ["Alice.M"] },
  { node: "db-01", labels: {}, connected: true, pinned: true, logins: ["postgres"] },
  { node: "web 03", labels: {}, connected: true, pinned: false, logins: ["ops"] },
];

function open(extra = {}, hash = "#/nodes") {
  return env.mount({ "GET /v1/admin/nodes": nodesPage(NODES), [TARGETS_ROUTE]: json(200, TARGETS), ...extra }, hash, ALL);
}

const trigger = (label) => Array.from(env.ui.root.querySelectorAll("button")).find((button) => button.getAttribute("aria-label") === label);
const menuLabels = () => Array.from(env.ui.root.querySelectorAll('.menu [role^="menuitem"] .menu-label')).map((item) => item.textContent);
const names = (section) => Array.from(section.querySelectorAll(".node-name")).map((link) => link.textContent);
const grids = () => Array.from(env.ui.root.querySelectorAll(".results .node-grid"));
const heads = () => Array.from(env.ui.root.querySelectorAll(".results .section-head h2")).map((item) => item.textContent);

test("pinned nodes are in their own section first, the rest follow under All nodes", async () => {
  await open();
  assert.deepEqual(heads(), ["Pinned", "All nodes"]);
  assert.equal(env.ui.root.querySelector(".results .section-head .sub").textContent, "1 node, kept for you on the server");
  assert.deepEqual(grids().map(names), [["db-01"], ["web 03", "web-01"]]);
  assert.equal(trigger("Unpin db-01").getAttribute("aria-pressed"), "true");
  assert.equal(trigger("Pin web-01").getAttribute("aria-pressed"), "false");
});

test("without a pinned node there are no section headings, and a node that is not a terminal target has no pin button", async () => {
  await open({ [TARGETS_ROUTE]: json(200, [{ ...TARGETS[0], pinned: false }, { ...TARGETS[1], pinned: false }]) });
  assert.deepEqual(heads(), []);
  assert.equal(grids().length, 1);
  assert.ok(trigger("Pin web-01"));
  assert.equal(trigger("Pin web 03"), undefined);
  env.ui.stop();
  await open({ [TARGETS_ROUTE]: json(404, { error: "not_found" }) });
  assert.equal(env.ui.root.querySelector(".pin-btn"), null);
});

test("pinning sends PUT with the CSRF header and keeps focus on the toggle, unpinning sends DELETE, names are encoded in the path", async () => {
  await open({ "PUT /v1/web/pins/web-01": json(204), "PUT /v1/web/pins/web%2003": json(204), "DELETE /v1/web/pins/db-01": json(204) });
  click(trigger("Pin web-01"));
  await settle();
  const put = env.ui.server.calls.find((call) => call.method === "PUT");
  assert.equal(put.path, "/v1/web/pins/web-01");
  assert.equal(put.headers["x-jaunt-csrf"], "csrf-token-one");
  assert.equal(put.body, undefined);
  assert.deepEqual(grids().map(names), [["db-01", "web-01"], ["web 03"]]);
  assert.equal(trigger("Unpin web-01").getAttribute("aria-pressed"), "true");
  assert.equal(document.activeElement, trigger("Unpin web-01"));
  assert.equal(env.ui.root.querySelector('[role="status"][aria-live="polite"]').textContent, "web-01 pinned.");
  click(trigger("Pin web 03"));
  await settle();
  assert.ok(env.ui.server.calls.some((call) => call.method === "PUT" && call.path === "/v1/web/pins/web%2003"));
  click(trigger("Unpin db-01"));
  await settle();
  const del = env.ui.server.calls.find((call) => call.method === "DELETE");
  assert.equal(del.path, "/v1/web/pins/db-01");
  assert.equal(del.headers["x-jaunt-csrf"], "csrf-token-one");
  assert.deepEqual(grids().map(names), [["web 03", "web-01"], ["db-01"]]);
  assert.equal(env.ui.root.querySelector('[role="status"][aria-live="polite"]').textContent, "db-01 unpinned.");
});

test("a refused pin leaves the toggle as it was, the limit has its own text and other failures a general one", async () => {
  await open({ "PUT /v1/web/pins/web-01": [json(409, { error: "too_many_pins" }), json(500, { error: "internal" })] });
  click(trigger("Pin web-01"));
  await settle();
  const page = () => env.ui.root.querySelector(".results").parentElement.textContent;
  assert.match(page(), /You can pin at most 50 nodes\. Unpin one first\./);
  assert.equal(trigger("Pin web-01").getAttribute("aria-pressed"), "false");
  assert.deepEqual(heads(), ["Pinned", "All nodes"]);
  assert.equal(env.ui.root.querySelector("[data-pin='web-01']").getAttribute("aria-pressed"), "false");
  click(trigger("Pin web-01"));
  await settle();
  assert.match(page(), /The pin could not be changed\. Try again\./);
  assert.equal(page().includes("at most 50"), false);
  assert.equal(trigger("Pin web-01").getAttribute("aria-pressed"), "false");
});

test("a pin path escapes the node name, and the name only counts as pinned once the server answered", async () => {
  const nodes = [node({ id: "n-p", name: "a%b/c d" })];
  const targets = [{ node: "a%b/c d", labels: {}, connected: true, pinned: false, logins: ["ok"] }];
  await open({ "GET /v1/admin/nodes": nodesPage(nodes), [TARGETS_ROUTE]: json(200, targets), "PUT /v1/web/pins/a%25b%2Fc%20d": json(204), "DELETE /v1/web/pins/a%25b%2Fc%20d": json(204) });
  click(trigger("Pin a%b/c d"));
  await settle();
  assert.deepEqual(env.ui.server.calls.filter((call) => call.method === "PUT").map((call) => call.path), ["/v1/web/pins/a%25b%2Fc%20d"]);
  assert.equal(trigger("Unpin a%b/c d").getAttribute("aria-pressed"), "true");
  click(trigger("Unpin a%b/c d"));
  await settle();
  assert.deepEqual(env.ui.server.calls.filter((call) => call.method === "DELETE").map((call) => call.path), ["/v1/web/pins/a%25b%2Fc%20d"]);
});

test("choosing a login in the Connect menu opens that terminal with one ticket and shows the workspace", async () => {
  await open();
  click(trigger("Connect to web-01"));
  click(byText(env.ui.root, '.menu [role="menuitem"]', "deploy"));
  await until(() => env.rig.sockets.length === 1, "the socket");
  const posts = env.ui.server.calls.filter((call) => call.method === "POST" && call.path === "/v1/web/terminal/ticket");
  assert.deepEqual(posts.map((call) => call.body), [{ node: "web-01", login: "deploy" }]);
  assert.equal(window.location.hash, "#/terminal");
  assert.equal(pane(env.ui.root).querySelector(".statusbar .mono").textContent, "web-01");
});

test("choosing a login in the Connect menu at the terminal limit opens nothing and pre-fills quick open with the limit note", async () => {
  await open({ [LIMITS_ROUTE]: json(200, { max_per_user: 1, idle_timeout_secs: 1800 }) });
  click(trigger("Connect to web-01"));
  click(byText(env.ui.root, '.menu [role="menuitem"]', "deploy"));
  await until(() => env.rig.sockets.length === 1, "the first socket");
  window.location.hash = "#/nodes";
  await settle();
  click(trigger("Connect to db-01"));
  click(byText(env.ui.root, '.menu [role="menuitem"]', "postgres"));
  await settle();
  assert.equal(env.rig.sockets.length, 1);
  assert.equal(window.location.hash, "#/terminal?node=db-01&login=postgres");
  const modal = document.querySelector("[role=dialog].quick");
  assert.match(modal.querySelector("footer").textContent, /All 1 terminals are open/);
  assert.equal(modal.querySelector("footer .btn-primary").disabled, true);
});

test("the recent terminals are one-click buttons above the nodes, only for pairs that are still allowed, and a click opens that terminal", async () => {
  const recent = [
    { node: "web-01", login: "alice", last_at: NOW - 7200 },
    { node: "db-01", login: "postgres", last_at: NOW - 90000 },
    { node: "db-01", login: "gone", last_at: NOW - 100 },
  ];
  await open({ [RECENT_ROUTE]: json(200, recent) });
  const buttons = Array.from(env.ui.root.querySelectorAll(".recent-row .recent-btn"));
  assert.deepEqual(buttons.map((button) => button.querySelector(".mono").textContent), ["alice@web-01", "postgres@db-01"]);
  assert.deepEqual(buttons.map((button) => button.querySelector(".when").textContent), ["2 h ago", "yesterday"]);
  assert.equal(env.ui.root.querySelector("#recent-heading").textContent, "Recent terminals");
  click(buttons[0]);
  await until(() => env.rig.sockets.length === 1, "the socket");
  const post = env.ui.server.calls.find((call) => call.method === "POST" && call.path === "/v1/web/terminal/ticket");
  assert.deepEqual(post.body, { node: "web-01", login: "alice" });
  assert.equal(window.location.hash, "#/terminal");
  assert.equal(pane(env.ui.root).querySelector(".statusbar .mono").textContent, "web-01");
});

test("the Connect menu lists logins as terminal links with the last used one first and marked, the hidden logins in one line and no filter below six", async () => {
  await open({ [RECENT_ROUTE]: json(200, [{ node: "web-01", login: "root", last_at: NOW - 7200 }]) });
  click(trigger("Connect to web-01"));
  assert.equal(env.ui.root.querySelector(".menu .menu-heading").textContent, "Open a terminal as");
  assert.deepEqual(menuLabels().slice(0, 3), ["root", "deploy", "alice"]);
  assert.equal(env.ui.root.querySelector(".menu .menu-meta").textContent, "Last used 2 h ago");
  assert.equal(env.ui.root.querySelectorAll(".menu .menu-meta").length, 1);
  assert.equal(env.ui.root.querySelector('.menu a[href^="#/terminal"]'), null);
  assert.equal(env.ui.root.querySelector('.menu a[role="menuitem"]').getAttribute("href"), "#/nodes/n-1");
  assert.equal(env.ui.root.querySelector(".menu .menu-search"), null);
  assert.match(env.ui.root.querySelector(".menu .menu-note").textContent, /^Not shown: Alice\.M, from your roles, because it cannot be an account name on a node\.$/);
  assert.equal(env.ui.root.querySelector(".menu .menu-note .mono").textContent, "Alice.M");
});

test("with six or more logins the menu has a filter that narrows the list and keeps its focus", async () => {
  const many = ["alice", "deploy", "backup", "monitor", "nginx", "release", "root"];
  await open({ [TARGETS_ROUTE]: json(200, [{ ...TARGETS[0], logins: many }, TARGETS[1]]) });
  click(trigger("Connect to web-01"));
  const input = env.ui.root.querySelector(".menu .menu-search input");
  assert.equal(input.getAttribute("aria-label"), "Filter logins");
  assert.equal(env.ui.root.querySelector(".menu .menu-scroll").querySelectorAll('[role="menuitem"]').length, 7);
  input.focus();
  type(input, "re");
  assert.deepEqual(menuLabels().slice(0, 1), ["release"]);
  assert.equal(document.activeElement, input);
  assert.equal(env.ui.root.querySelector(".menu .menu-search input"), input);
  type(input, "zzz");
  assert.match(env.ui.root.querySelector(".menu").textContent, /No login matches the filter/);
  const down = press(input, "ArrowDown");
  assert.equal(down.defaultPrevented, true);
  const home = press(input, "Home");
  assert.equal(home.defaultPrevented, false);
  type(input, "");
  assert.equal(env.ui.root.querySelector(".menu .menu-scroll").querySelectorAll('[role="menuitem"]').length, 7);
  click(trigger("Connect to web-01"));
  click(trigger("Connect to web-01"));
  assert.equal(env.ui.root.querySelector(".menu .menu-search input").value, "");
});

test("the login filter appears at exactly six logins and not at five", async () => {
  const five = ["alice", "deploy", "backup", "monitor", "nginx"];
  await open({ [TARGETS_ROUTE]: json(200, [{ ...TARGETS[0], logins: five }, { ...TARGETS[1], logins: [...five, "root"] }]) });
  click(trigger("Connect to web-01"));
  assert.equal(env.ui.root.querySelector(".menu .menu-search"), null);
  assert.equal(env.ui.root.querySelector(".menu .menu-scroll"), null);
  click(trigger("Connect to web-01"));
  click(trigger("Connect to db-01"));
  assert.ok(env.ui.root.querySelector(".menu .menu-search input"));
  assert.equal(env.ui.root.querySelector(".menu .menu-scroll").querySelectorAll('[role="menuitem"]').length, 6);
});

test("a node with one login says so, an offline node disables its logins with a note, and no allowed login is stated", async () => {
  const targets = [
    { node: "web-01", labels: {}, connected: true, logins: ["deploy"] },
    { node: "db-01", labels: {}, connected: true, logins: [], hidden_logins: ["Bob.X"] },
    { node: "web 03", labels: {}, connected: true, logins: ["ops"] },
  ];
  const nodes = [node({ id: "n-1", name: "web-01" }), node({ id: "n-2", name: "db-01" }), node({ id: "n-3", name: "web 03", connected: false, connected_since: null })];
  await open({ [TARGETS_ROUTE]: json(200, targets), "GET /v1/admin/nodes": nodesPage(nodes) });
  click(trigger("Connect to web-01"));
  assert.equal(menuLabels()[0], "deploy");
  assert.match(env.ui.root.querySelector(".menu").textContent, /Your roles allow one login on this node\./);
  assert.equal(document.activeElement.textContent.startsWith("deploy"), true);
  click(trigger("Connect to web-01"));
  click(trigger("Connect to db-01"));
  assert.equal(env.ui.root.querySelector('.menu [role="menuitem"]').getAttribute("aria-disabled"), "true");
  assert.match(env.ui.root.querySelector(".menu").textContent, /No login availableYour roles allow no login on this node\./);
  assert.match(env.ui.root.querySelector(".menu-note").textContent, /Not shown: Bob\.X/);
  click(trigger("Connect to db-01"));
  click(trigger("Connect to web 03"));
  assert.equal(env.ui.root.querySelector('.menu [role="menuitem"]').getAttribute("aria-disabled"), "true");
  assert.match(env.ui.root.querySelector(".menu-note").textContent, /web 03 is offline, so a terminal cannot open now\./);
});

test("hostile hidden logins and node names in the menu and the pin labels are text only", async () => {
  const targets = [{ node: HOSTILE.tag, labels: {}, connected: true, pinned: true, logins: ["ok"], hidden_logins: [HOSTILE.tag, HOSTILE.control, HOSTILE.long, 5, null] }];
  const nodes = [node({ id: "n-x", name: HOSTILE.tag })];
  await open({ [TARGETS_ROUTE]: json(200, targets), "GET /v1/admin/nodes": nodesPage(nodes) });
  assert.equal(env.ui.root.querySelector(".results img"), null);
  assert.equal(env.ui.root.querySelector(".pin-btn").getAttribute("aria-label"), "Unpin " + HOSTILE.tag);
  click(env.ui.root.querySelector(".btn-connect"));
  assert.equal(env.ui.root.querySelector(".menu img, .menu script"), null);
  const note = Array.from(env.ui.root.querySelectorAll(".menu-note")).at(-1).textContent;
  assert.ok(note.includes(HOSTILE.tag));
  assert.equal(note.includes("A".repeat(100)), false);
  assert.equal(window.__pwned, undefined);
});

test("the node list keeps working when quick-open data is missing, and the Connect menu says the terminal is off", async () => {
  await open({ [TARGETS_ROUTE]: json(404, { error: "not_found" }), [RECENT_ROUTE]: json(404, { error: "not_found" }), [CONFIG_ROUTE]: json(200, CONFIG), [LIMITS_ROUTE]: json(404, { error: "not_found" }) });
  assert.equal(env.ui.root.querySelector(".recent-row"), null);
  click(trigger("Connect to web-01"));
  assert.deepEqual(menuLabels().slice(0, 1), ["Open terminal"]);
  assert.ok(byText(env.ui.root, "button", "Connect"));
});

function recentPair(targets) {
  return open({ [TARGETS_ROUTE]: json(200, targets), [RECENT_ROUTE]: json(200, [{ node: "web-01", login: "alice", last_at: NOW - 100 }]) });
}

const ticketCount = () => env.ui.server.calls.filter((call) => call.path === "/v1/web/terminal/ticket").length;

test("a recent pair whose node is offline requests no ticket, opens no socket and only shows quick open pre-filled", async () => {
  await recentPair([{ node: "web-01", labels: {}, connected: false, pinned: false, logins: ["alice"] }, TARGETS[1]]);
  click(env.ui.root.querySelector(".recent-row .recent-btn"));
  await settle();
  assert.equal(ticketCount(), 0);
  assert.equal(env.rig.sockets.length, 0);
  assert.equal(window.location.hash, "#/terminal?node=web-01&login=alice");
  assert.equal(env.ui.main().querySelector(".ws").hidden, true);
  assert.equal(env.ui.main().querySelector('input[name="quick-login"]'), null);
  assert.equal(env.ui.main().querySelector(".panel.quick footer .btn-primary").disabled, true);
  assert.ok(Array.from(env.ui.main().querySelectorAll(".quick-row.is-off .name")).some((item) => item.textContent === "web-01"));
});

test("a recent pair at the terminal limit requests no ticket beyond the open ones and only shows the pre-filled dialog", async () => {
  await open({ [RECENT_ROUTE]: json(200, [{ node: "web-01", login: "alice", last_at: NOW - 100 }]), [LIMITS_ROUTE]: json(200, { max_per_user: 1, idle_timeout_secs: 1800 }) });
  click(trigger("Connect to db-01"));
  click(byText(env.ui.root, '.menu [role="menuitem"]', "postgres"));
  await until(() => env.rig.sockets.length === 1, "the first socket");
  window.location.hash = "#/nodes";
  await settle();
  click(env.ui.root.querySelector(".recent-row .recent-btn"));
  await settle();
  assert.equal(ticketCount(), 1);
  assert.equal(env.rig.sockets.length, 1);
  assert.equal(window.location.hash, "#/terminal?node=web-01&login=alice");
  const modal = document.querySelector("[role=dialog].quick");
  assert.ok(modal);
  assert.equal(modal.querySelector('input[name="quick-login"]:checked').value, "alice");
  assert.equal(modal.querySelector("footer .btn-primary").disabled, true);
});

test("a recent pair that is connected, allowed and under the limit opens with one ticket", async () => {
  await recentPair(TARGETS);
  click(env.ui.root.querySelector(".recent-row .recent-btn"));
  await until(() => env.rig.sockets.length === 1, "the socket");
  assert.equal(ticketCount(), 1);
  assert.equal(window.location.hash, "#/terminal");
});

test("opening a pair is refused for an unknown node, an offline node, a login that is no longer allowed and a full limit, and allowed otherwise", async () => {
  const { openPair } = await import("../../crates/jaunt-web/assets/assets/js/views/nodes-list.js");
  const make = ({ connected = true, logins = ["alice"], atLimit = false, known = true } = {}) => {
    const calls = { opened: [], navigated: [] };
    const ctx = {
      connect: { target: (node) => (known && node === "web-01" ? { node, connected, logins } : null) },
      workspace: { atLimit: () => atLimit, open: (pair) => calls.opened.push(pair) },
      navigate: (path, query) => calls.navigated.push([path, query === undefined ? null : query]),
    };
    return { ctx, calls };
  };
  const cases = [
    [{ connected: false }, false],
    [{ logins: ["deploy"] }, false],
    [{ atLimit: true }, false],
    [{ known: false }, false],
    [{}, true],
  ];
  for (const [state, opens] of cases) {
    const { ctx, calls } = make(state);
    openPair(ctx, "web-01", "alice");
    assert.deepEqual(calls.opened, opens ? [{ node: "web-01", login: "alice" }] : [], JSON.stringify(state));
    assert.deepEqual(calls.navigated, [opens ? ["/terminal", null] : ["/terminal", { node: "web-01", login: "alice" }]], JSON.stringify(state));
  }
});
