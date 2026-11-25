import assert from "node:assert/strict";
import { afterEach, mock, test } from "node:test";

import { NOW, node, nodeDetail, sessionRow } from "../fixtures.mjs";
import { byText, click, json, mount, press, setHidden, settle, signedIn } from "./support.mjs";

let ui = null;
afterEach(() => {
  mock.timers.reset();
  if (ui) {
    ui.stop();
    ui = null;
  }
});

const nodesPage = (nodes, extra = {}) => json(200, { nodes, next: null, pending_enrolments: 0, ...extra });
const sessionsPage = json(200, { sessions: [sessionRow()], next: null });
const hrefs = (scope) => Array.from(scope.querySelectorAll("a")).map((link) => link.getAttribute("href"));

test("the shell has a header, one navigation landmark and a main region, with the wordmark and the server", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([]) }, "#/nodes");
  assert.equal(ui.root.querySelectorAll("header.topbar").length, 1);
  assert.equal(ui.root.querySelectorAll("nav.sidebar").length, 1);
  assert.equal(ui.root.querySelectorAll("main#main").length, 1);
  assert.equal(ui.root.querySelector(".wordmark-text").textContent, "Jaunt");
  assert.match(ui.root.querySelector(".subnav-foot").textContent, /jaunt\.test/);
});

test("the rail and the secondary panel show what the session may use and mark the current area and page", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([], { pending_enrolments: 4 }) }, "#/nodes");
  assert.deepEqual(hrefs(ui.root.querySelector(".rail-list")), ["#/nodes", "#/sessions", "#/terminal", "#/revocations", "#/audit"]);
  assert.deepEqual(hrefs(ui.root.querySelector(".rail-foot")), ["#/approve"]);
  assert.equal(ui.root.querySelector(".rail [aria-current]").textContent, "Nodes");
  assert.equal(ui.root.querySelector(".subnav-title").textContent, "Nodes");
  assert.deepEqual(hrefs(ui.root.querySelector(".subnav-list")), ["#/nodes", "#/nodes?tab=pending", "#/approve"]);
  assert.equal(ui.root.querySelector(".subnav [aria-current]").textContent, "All nodes");
  window.location.hash = "#/nodes?tab=pending";
  await settle();
  assert.match(ui.root.querySelector(".subnav [aria-current]").textContent, /^Pending enrolments/);
  window.location.hash = "#/approve";
  await settle();
  assert.equal(ui.root.querySelector(".subnav [aria-current]").textContent, "Approve node");
  assert.equal(ui.root.querySelector(".rail [aria-current]").textContent, "Nodes");
});

test("a session with fewer permissions sees fewer areas and no add new item", async () => {
  ui = await mount({ ...signedIn(["audit.read"]), "GET /v1/admin/audit": json(200, { events: [], next_cursor: null }) }, "#/audit");
  assert.deepEqual(hrefs(ui.root.querySelector(".rail-list")), ["#/terminal", "#/audit"]);
  assert.equal(ui.root.querySelector(".rail-foot").children.length, 0);
  assert.equal(ui.root.querySelector(".bell"), null);
  assert.equal(ui.root.querySelector(".subnav-title").textContent, "Audit");
});

test("the terminal area opens a placeholder page for any signed-in user", async () => {
  ui = await mount({ ...signedIn([]) }, "#/terminal");
  assert.match(ui.main().textContent, /The web terminal is coming/);
  assert.match(ui.main().textContent, /Node picker: Coming with the terminal/);
  assert.equal(ui.root.querySelector(".rail [aria-current]").textContent, "Terminal");
});

test("the bell shows the pending enrolments from any page, links to Approve and hides at zero", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/sessions": sessionsPage, "GET /v1/admin/nodes": nodesPage([], { pending_enrolments: 120 }) }, "#/sessions");
  const bell = ui.root.querySelector(".bell");
  assert.equal(bell.getAttribute("href"), "#/approve");
  assert.equal(bell.querySelector(".bell-count").textContent, "99+");
  assert.equal(bell.getAttribute("aria-label"), "120 pending enrolments");
  assert.equal(ui.server.calls.find((call) => call.path === "/v1/admin/nodes").query.get("limit"), "1");
  ui.stop();
  ui = await mount({ ...signedIn(), "GET /v1/admin/sessions": sessionsPage, "GET /v1/admin/nodes": nodesPage([], { pending_enrolments: 0 }) }, "#/sessions");
  assert.equal(ui.root.querySelector(".bell-count"), null);
  assert.equal(ui.root.querySelector(".bell").getAttribute("aria-label"), "No pending enrolments");
});

test("the account menu names the user, switches the theme and signs out", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([]) }, "#/nodes");
  const trigger = ui.root.querySelector(".account-btn");
  assert.equal(trigger.querySelector(".account-name").textContent, "alice@example.com");
  assert.equal(trigger.querySelector(".avatar").textContent, "A");
  click(trigger);
  const items = Array.from(ui.root.querySelectorAll('.menu [role^="menuitem"]'));
  assert.deepEqual(items.map((item) => item.querySelector(".menu-label").textContent), ["Auto (system)", "Light", "Dark", "Sign out"]);
  assert.equal(items[0].getAttribute("aria-checked"), "true");
  click(items[2]);
  assert.equal(document.documentElement.getAttribute("data-theme"), "dark");
  assert.equal(window.localStorage.getItem("jaunt-theme"), "dark");
  assert.equal(ui.root.querySelector(".menu"), null);
});

test("the drawer opens from the hamburger, makes the page inert, traps focus and returns it on Escape", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([]) }, "#/nodes");
  const hamburger = ui.root.querySelector(".hamburger");
  const sidebar = ui.root.querySelector("#sidebar");
  assert.equal(hamburger.getAttribute("aria-expanded"), "false");
  hamburger.focus();
  click(hamburger);
  assert.equal(hamburger.getAttribute("aria-expanded"), "true");
  assert.ok(ui.root.querySelector(".app").classList.contains("drawer-open"));
  assert.ok(ui.root.querySelector("header.topbar").hasAttribute("inert"));
  assert.ok(ui.main().hasAttribute("inert"));
  assert.ok(sidebar.contains(document.activeElement));
  const focusables = Array.from(sidebar.querySelectorAll("a[href], button")).filter((item) => !item.classList.contains("collapse-btn"));
  focusables[focusables.length - 1].focus();
  const wrapped = press(sidebar, "Tab");
  assert.equal(wrapped.defaultPrevented, true);
  assert.equal(document.activeElement, focusables[0]);
  const back = press(sidebar, "Tab", { shiftKey: true });
  assert.equal(back.defaultPrevented, true);
  assert.equal(document.activeElement, focusables[focusables.length - 1]);
  press(sidebar, "Escape");
  assert.equal(hamburger.getAttribute("aria-expanded"), "false");
  assert.equal(ui.main().hasAttribute("inert"), false);
  assert.equal(document.activeElement, hamburger);
});

test("choosing a destination or the close button closes the drawer, and a route change closes it too", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([]), "GET /v1/admin/sessions": sessionsPage }, "#/nodes");
  const hamburger = ui.root.querySelector(".hamburger");
  click(hamburger);
  click(ui.root.querySelector(".drawer-close"));
  assert.equal(ui.root.querySelector(".app").classList.contains("drawer-open"), false);
  click(hamburger);
  click(byText(ui.root, ".rail-item", "Sessions"));
  assert.equal(ui.root.querySelector(".app").classList.contains("drawer-open"), false);
  click(hamburger);
  window.location.hash = "#/nodes";
  await settle();
  assert.equal(ui.root.querySelector(".app").classList.contains("drawer-open"), false);
  assert.equal(ui.main().hasAttribute("inert"), false);
  click(hamburger);
  click(ui.root.querySelector(".drawer-scrim"));
  assert.equal(hamburger.getAttribute("aria-expanded"), "false");
});

test("collapsing the secondary panel is remembered in local storage and restored", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([]) }, "#/nodes");
  const toggle = ui.root.querySelector(".collapse-btn");
  assert.equal(toggle.getAttribute("aria-expanded"), "true");
  click(toggle);
  assert.ok(ui.root.querySelector(".app").classList.contains("nav-collapsed"));
  assert.equal(toggle.getAttribute("aria-expanded"), "false");
  assert.equal(toggle.getAttribute("aria-label"), "Expand navigation");
  assert.equal(window.localStorage.getItem("jaunt-nav-collapsed"), "1");
  ui.stop();
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([]) }, "#/nodes", { before: (win) => win.localStorage.setItem("jaunt-nav-collapsed", "1") });
  assert.ok(ui.root.querySelector(".app").classList.contains("nav-collapsed"));
  click(ui.root.querySelector(".collapse-btn"));
  assert.equal(window.localStorage.getItem("jaunt-nav-collapsed"), null);
});

test("opening a node detail keeps the nodes area marked", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes/n-web-01": json(200, nodeDetail()), "GET /v1/admin/nodes": nodesPage([]) }, "#/nodes/n-web-01");
  assert.equal(ui.root.querySelector(".rail [aria-current]").textContent, "Nodes");
  assert.equal(ui.root.querySelector(".subnav [aria-current]").textContent, "All nodes");
});

test("table pages show an empty state with an icon and a sentence", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/sessions": json(200, { sessions: [], next: null }), "GET /v1/admin/nodes": nodesPage([]) }, "#/sessions");
  const empty = ui.root.querySelector(".empty");
  assert.ok(empty.querySelector("svg.icon"));
  assert.equal(empty.querySelector("h2").textContent, "No sessions yet.");
});

const nodeCalls = () => ui.server.calls.filter((call) => call.method === "GET" && call.path === "/v1/admin/nodes");

test("the bell makes no request while the tab is hidden", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/sessions": sessionsPage, "GET /v1/admin/nodes": nodesPage([], { pending_enrolments: 3 }) }, "#/sessions", { before: () => setHidden(true) });
  assert.equal(nodeCalls().length, 0);
  assert.equal(ui.root.querySelector(".bell-count"), null);
  setHidden(false);
  window.location.hash = "#/audit";
  await settle();
  assert.equal(nodeCalls().length, 1);
});

test("the bell asks again only after a minute, however often the route changes", async () => {
  mock.timers.enable({ apis: ["Date"], now: NOW * 1000 });
  ui = await mount({ ...signedIn(), "GET /v1/admin/sessions": sessionsPage, "GET /v1/admin/audit": json(200, { events: [], next_cursor: null }), "GET /v1/admin/nodes": nodesPage([], { pending_enrolments: 1 }) }, "#/sessions");
  assert.equal(nodeCalls().length, 1);
  for (const hash of ["#/audit", "#/sessions", "#/audit"]) {
    window.location.hash = hash;
    await settle();
  }
  assert.equal(nodeCalls().length, 1);
  mock.timers.tick(59_000);
  window.location.hash = "#/sessions";
  await settle();
  assert.equal(nodeCalls().length, 1);
  mock.timers.tick(2_000);
  window.location.hash = "#/audit";
  await settle();
  assert.equal(nodeCalls().length, 2);
});

test("a session without nodes.approve never asks for the pending count", async () => {
  ui = await mount({ ...signedIn(["sessions.read"]), "GET /v1/admin/sessions": sessionsPage, "GET /v1/admin/nodes": json(403, { error: "forbidden" }) }, "#/sessions");
  window.location.hash = "#/revocations";
  await settle();
  assert.equal(nodeCalls().length, 0);
  assert.equal(ui.root.querySelector(".bell"), null);
});

test("an answer that repaints the navigation keeps the keyboard focus on the same item", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  ui = await mount({ ...signedIn(), "GET /v1/admin/sessions": sessionsPage, "GET /v1/admin/nodes": async () => {
    await gate;
    return nodesPage([], { pending_enrolments: 5 });
  } }, "#/sessions");
  const before = byText(ui.root, ".rail-item", "Audit");
  before.focus();
  assert.equal(document.activeElement, before);
  release();
  await settle();
  assert.equal(ui.root.querySelector(".bell-count").textContent, "5");
  const after = byText(ui.root, ".rail-item", "Audit");
  assert.notEqual(after, before);
  assert.equal(document.activeElement, after);
});

function brokenStorage(win) {
  const refuse = () => {
    throw new Error("storage refused");
  };
  Object.defineProperty(globalThis, "localStorage", { configurable: true, writable: true, value: { getItem: refuse, setItem: refuse, removeItem: refuse } });
  Object.defineProperty(win, "localStorage", { configurable: true, get: refuse });
}

test("with storage that throws on every call the nodes page renders and the view and the panel still switch", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([node()]) }, "#/nodes", { before: brokenStorage });
  assert.equal(ui.root.querySelectorAll(".node-card").length, 1);
  click(ui.root.querySelector('button[aria-label="List view"]'));
  assert.equal(ui.root.querySelectorAll(".node-row").length, 1);
  click(ui.root.querySelector(".collapse-btn"));
  assert.ok(ui.root.querySelector(".app").classList.contains("nav-collapsed"));
  click(ui.root.querySelector(".collapse-btn"));
  assert.equal(ui.root.querySelector(".app").classList.contains("nav-collapsed"), false);
});
