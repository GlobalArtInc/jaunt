import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { HOSTILE, NOW, node } from "../fixtures.mjs";
import { byText, click, json, mount, press, settle, signedIn, submit, type } from "./support.mjs";

let ui = null;
afterEach(() => {
  if (ui) {
    ui.stop();
    ui = null;
  }
  delete globalThis.navigator;
});

const page = (nodes, extra = {}) => json(200, { nodes, next: null, pending_enrolments: 0, ...extra });
const config = { "GET /v1/client-config": json(200, { ssh_suffix: "jaunt.example.com", gate: { host: "g", port: 22 }, host_ca_keys: [] }) };
const names = () => Array.from(ui.root.querySelectorAll(".node-name")).map((link) => link.textContent);
const menuLabels = () => Array.from(ui.root.querySelectorAll('.menu [role^="menuitem"] .menu-label')).map((item) => item.textContent);
const trigger = (text) => Array.from(ui.root.querySelectorAll("button")).find((button) => button.getAttribute("aria-label") === text || button.textContent.trim() === text);

const FLEET = [
  node({ id: "n-b", name: "beta", connected_since: NOW - 100, labels: { env: "prod", team: "web" } }),
  node({ id: "n-a", name: "alpha", connected: false, connected_since: null, labels: { env: "dev" } }),
  node({ id: "n-c", name: "gamma", connected_since: NOW - 10, labels: { env: "prod", tier: "gold", region: "eu", owner: "ops" } }),
];

test("the search bar sends the name prefix on Enter and on submit, and keeps the value", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page(FLEET) }, "#/nodes?q=al");
  const input = ui.root.querySelector(".search-input");
  assert.equal(input.value, "al");
  type(input, "be");
  const enter = press(input, "Enter");
  assert.equal(enter.defaultPrevented, true);
  await settle();
  assert.equal(window.location.hash, "#/nodes?q=be");
  type(ui.root.querySelector(".search-input"), "ga");
  submit(ui.root.querySelector("form.filters"));
  await settle();
  assert.equal(window.location.hash, "#/nodes?q=ga");
  assert.equal(ui.server.calls.filter((call) => call.path === "/v1/admin/nodes").at(-1).query.get("q"), "ga");
});

test("the Advanced switch shows the label filter and opens by itself when labels are active", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page(FLEET) }, "#/nodes");
  const toggle = ui.root.querySelector(".switch-input");
  const advanced = ui.root.querySelector(".advanced");
  assert.equal(toggle.getAttribute("role"), "switch");
  assert.equal(advanced.hidden, true);
  toggle.checked = true;
  toggle.dispatchEvent(new window.Event("change", { bubbles: true }));
  assert.equal(advanced.hidden, false);
  const labels = advanced.querySelector("input");
  type(labels, "env:prod team:web");
  submit(ui.root.querySelector("form.filters"));
  await settle();
  assert.equal(window.location.hash, "#/nodes?label=env%3Aprod&label=team%3Aweb");
  assert.equal(ui.root.querySelector(".advanced").hidden, false);
});

test("a malformed label filter is explained and sends nothing", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page(FLEET) }, "#/nodes?label=env%3Aprod");
  const before = ui.server.count("GET", "/v1/admin/nodes");
  type(ui.root.querySelector(".advanced input"), "nocolon");
  submit(ui.root.querySelector("form.filters"));
  assert.match(ui.main().textContent, /A label must look like key:value/);
  assert.equal(ui.server.count("GET", "/v1/admin/nodes"), before);
});

test("the State menu sets the state, marks the current choice and the Labels menu toggles labels from the loaded nodes", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page(FLEET) }, "#/nodes");
  click(trigger("State: Active"));
  const radios = Array.from(ui.root.querySelectorAll('.menu [role="menuitemradio"]'));
  assert.deepEqual(radios.map((item) => [item.textContent, item.getAttribute("aria-checked")]), [["Active", "true"], ["Removed", "false"]]);
  click(radios[1]);
  await settle();
  assert.equal(window.location.hash, "#/nodes?state=removed");
  window.location.hash = "#/nodes";
  await settle();
  click(trigger("Labels"));
  assert.deepEqual(menuLabels(), ["env:dev", "env:prod", "owner:ops", "region:eu", "team:web", "tier:gold"]);
  click(byText(ui.root, '[role="menuitemcheckbox"]', "env:prod"));
  await settle();
  assert.equal(window.location.hash, "#/nodes?label=env%3Aprod");
  assert.ok(trigger("Labels (1)"));
  click(trigger("Labels (1)"));
  assert.equal(byText(ui.root, '[role="menuitemcheckbox"]', "env:prod").getAttribute("aria-checked"), "true");
});

test("sorting orders the cards by name or by recent connection, is kept in the address and is noted while more pages exist", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page(FLEET, { next: "c1" }) }, "#/nodes");
  assert.deepEqual(names(), ["alpha", "beta", "gamma"]);
  assert.equal(ui.root.querySelector(".sort-note").hidden, true);
  click(trigger("Sort nodes: Name, A–Z"));
  click(byText(ui.root, '[role="menuitemradio"]', "Name, Z–A"));
  await settle();
  assert.equal(window.location.hash, "#/nodes?sort=name-desc");
  assert.deepEqual(names(), ["gamma", "beta", "alpha"]);
  window.location.hash = "#/nodes?sort=recent";
  await settle();
  assert.deepEqual(names(), ["gamma", "beta", "alpha"]);
  assert.equal(ui.root.querySelector(".sort-note").hidden, false);
});

test("the grid and list views show the same nodes, the choice is stored and the labels toggle works in the list", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page(FLEET) }, "#/nodes");
  const grid = ui.root.querySelector('button[aria-label="Grid view"]');
  const list = ui.root.querySelector('button[aria-label="List view"]');
  assert.equal(grid.getAttribute("aria-pressed"), "true");
  assert.equal(ui.root.querySelectorAll(".node-card").length, 3);
  assert.equal(byText(ui.root, "button", "Collapse all labels").hidden, true);
  click(list);
  assert.equal(window.localStorage.getItem("jaunt-nodes-view"), "list");
  assert.equal(ui.root.querySelectorAll(".node-card").length, 0);
  assert.equal(ui.root.querySelectorAll(".node-row").length, 3);
  assert.equal(list.getAttribute("aria-pressed"), "true");
  const rowOf = (name) => Array.from(ui.root.querySelectorAll(".node-row")).find((row) => row.querySelector(".node-name").textContent === name);
  assert.equal(rowOf("gamma").querySelectorAll(".chip").length, 4);
  click(byText(ui.root, "button", "Collapse all labels"));
  assert.equal(rowOf("gamma").querySelectorAll(".chip").length, 3);
  assert.ok(byText(ui.root, "button", "Expand all labels"));
  ui.stop();
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page(FLEET) }, "#/nodes", { before: (win) => win.localStorage.setItem("jaunt-nodes-view", "list") });
  assert.equal(ui.root.querySelectorAll(".node-row").length, 3);
});

test("a card shows three labels and a plus-more control that expands and collapses the rest", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page([FLEET[2]]) }, "#/nodes");
  const card = ui.root.querySelector(".node-card");
  assert.equal(card.querySelectorAll(".chip").length, 3);
  const more = card.querySelector(".link-btn");
  assert.equal(more.textContent, "+1 more");
  assert.equal(more.getAttribute("aria-expanded"), "false");
  click(more);
  assert.equal(card.querySelectorAll(".chip").length, 4);
  const fewer = card.querySelector(".link-btn");
  assert.equal(fewer.textContent, "Show fewer");
  assert.equal(fewer.getAttribute("aria-expanded"), "true");
  assert.equal(document.activeElement, fewer);
  click(fewer);
  assert.equal(card.querySelectorAll(".chip").length, 3);
});

test("the Connect menu without targets disables Open terminal with its reason, copies the ssh command and links to the details", async () => {
  const written = [];
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async (text) => written.push(text) } } });
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page([FLEET[0]]) }, "#/nodes");
  assert.equal(ui.server.count("GET", "/v1/web/terminal/targets"), 1);
  click(trigger("Connect"));
  assert.deepEqual(menuLabels(), ["Open terminal", "Copy SSH command", "Details"]);
  const open = byText(ui.root, '[role="menuitem"]', "Open terminalAvailable with the web terminal");
  assert.equal(open.getAttribute("aria-disabled"), "true");
  click(open);
  assert.ok(ui.root.querySelector(".menu"));
  assert.match(ui.root.querySelector(".menu").textContent, /Available with the web terminal/);
  assert.equal(ui.root.querySelector('.menu a[role="menuitem"]').getAttribute("href"), "#/nodes/n-b");
  click(ui.root.querySelectorAll('.menu [role="menuitem"]')[1]);
  await settle();
  assert.deepEqual(written, ["ssh YOUR_LOGIN@beta.jaunt.example.com"]);
  assert.equal(ui.root.querySelector('[role="status"][aria-live="polite"]').textContent, "SSH command copied.");
  assert.equal(ui.root.querySelector(".menu"), null);
});

test("the Connect menu with targets lists the allowed logins as terminal links and copies the command for the only login", async () => {
  const targets = [{ node: "beta", labels: {}, connected: true, logins: ["deploy", "root"] }, { node: "alpha", labels: {}, connected: false, logins: ["ops"] }];
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async () => {} } } });
  ui = await mount({ ...signedIn(), ...config, "GET /v1/web/terminal/targets": json(200, targets), "GET /v1/admin/nodes": page(FLEET) }, "#/nodes");
  await settle();
  click(trigger("Connect to beta"));
  assert.deepEqual(menuLabels(), ["Open terminal as deploy", "Open terminal as root", "Copy SSH command", "Details"]);
  assert.deepEqual(Array.from(ui.root.querySelectorAll('.menu a[role="menuitem"]')).map((link) => link.getAttribute("href")), ["#/terminal?node=beta&login=deploy", "#/terminal?node=beta&login=root", "#/nodes/n-b"]);
  click(trigger("Connect to beta"));
  click(trigger("Connect to alpha"));
  assert.deepEqual(menuLabels(), ["Open terminal as ops", "Copy SSH command as ops", "Details"]);
  click(trigger("Connect to gamma"));
  assert.match(ui.root.querySelector(".menu").textContent, /Your roles allow no login on this node/);
});

test("a node name or login that is not safe for a shell never produces a command", async () => {
  const evil = [node({ id: "n-x", name: "web; rm -rf ~" }), node({ id: "n-y", name: "ok-node" })];
  const targets = [{ node: "ok-node", labels: {}, connected: true, logins: ["good", "bad;touch x", "$(id)"] }];
  ui = await mount({ ...signedIn(), ...config, "GET /v1/web/terminal/targets": json(200, targets), "GET /v1/admin/nodes": page(evil) }, "#/nodes");
  await settle();
  click(trigger("Connect to web; rm -rf ~"));
  const copy = byText(ui.root, '[role="menuitem"]', "Copy SSH commandThe SSH address of this server is not configured, so no command can be built.");
  assert.equal(copy.getAttribute("aria-disabled"), "true");
  click(trigger("Connect to web; rm -rf ~"));
  click(trigger("Connect to ok-node"));
  assert.deepEqual(menuLabels(), ["Open terminal as good", "Copy SSH command as good", "Details"]);
});

test("without a configured ssh address the copy action is disabled and says why", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/client-config": json(404, { error: "not_configured" }), "GET /v1/admin/nodes": page([FLEET[0]]) }, "#/nodes");
  click(trigger("Connect"));
  const copy = ui.root.querySelectorAll('.menu [role="menuitem"]')[1];
  assert.equal(copy.getAttribute("aria-disabled"), "true");
  assert.match(copy.textContent, /not configured/);
});

test("when the browser refuses clipboard access the command is shown in a dialog to copy by hand", async () => {
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async () => Promise.reject(new Error("denied")) } } });
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page([FLEET[0]]) }, "#/nodes");
  click(trigger("Connect"));
  click(ui.root.querySelectorAll('.menu [role="menuitem"]')[1]);
  await settle();
  const dialog = document.querySelector('[role="dialog"]');
  assert.match(dialog.textContent, /Copy this command/);
  assert.equal(dialog.querySelector("pre").textContent, "ssh YOUR_LOGIN@beta.jaunt.example.com");
});

test("a removed node offers Details instead of Connect", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page([node({ state: "removed", connected: false })]) }, "#/nodes?state=removed");
  assert.equal(trigger("Connect to web-01"), undefined);
  assert.equal(byText(ui.root, "a", "Details").getAttribute("href"), "#/nodes/n-web-01");
});

test("hostile node data in cards, list rows and menus is text and the command stays disabled", async () => {
  const hostile = node({ id: "n-h", name: HOSTILE.tag, hostname: HOSTILE.quote, labels: { [HOSTILE.tag]: HOSTILE.quote, long: HOSTILE.long, rtl: HOSTILE.rtl } });
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page([hostile]) }, "#/nodes");
  assert.equal(ui.root.querySelectorAll("img, script, iframe").length, 0);
  assert.ok(ui.root.querySelector(".node-name").textContent.includes("<img"));
  click(trigger("Connect to " + HOSTILE.tag));
  assert.equal(ui.root.querySelectorAll("img, script, iframe").length, 0);
  assert.equal(ui.root.querySelectorAll('.menu [role="menuitem"]')[1].getAttribute("aria-disabled"), "true");
  click(ui.root.querySelector('button[aria-label="List view"]'));
  assert.equal(ui.root.querySelectorAll("img, script, iframe").length, 0);
  assert.equal(window.__pwned, undefined);
});

test("the Pending enrolments tab shows the count and the way to enter a code", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page([], { pending_enrolments: 2 }) }, "#/nodes?tab=pending");
  assert.equal(ui.root.querySelector(".tab[aria-current]").textContent.startsWith("Pending enrolments"), true);
  assert.match(ui.main().textContent, /2 enrolment requests are waiting/);
  assert.equal(byText(ui.root, "a", "Enter code").getAttribute("href"), "#/approve");
  ui.stop();
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page([], { pending_enrolments: 0 }) }, "#/nodes?tab=pending");
  assert.match(ui.main().textContent, /No enrolment requests are waiting/);
});

test("the nodes tabs link between the two views and an empty registry shows the enrol command", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page([]) }, "#/nodes");
  assert.deepEqual(Array.from(ui.root.querySelectorAll(".tab")).map((tab) => tab.getAttribute("href")), ["#/nodes", "#/nodes?tab=pending"]);
  assert.match(ui.main().textContent, /jaunt-agent enroll/);
});

test("the sessions and audit pages use the search bar and a state menu", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/sessions": json(200, { sessions: [], next: null }), "GET /v1/admin/nodes": page([]) }, "#/sessions");
  type(ui.root.querySelector(".search-input"), "bob@example.com");
  submit(ui.root.querySelector("form.filters"));
  await settle();
  assert.equal(window.location.hash, "#/sessions?user=bob%40example.com");
  click(trigger("State: Any"));
  click(byText(ui.root, '[role="menuitemradio"]', "Live"));
  await settle();
  assert.equal(window.location.hash, "#/sessions?state=active&user=bob%40example.com");
  assert.ok(trigger("State: Live"));
  ui.stop();
  ui = await mount({ ...signedIn(), "GET /v1/admin/audit": json(200, { events: [], next_cursor: null }), "GET /v1/admin/nodes": page([]) }, "#/audit");
  type(ui.root.querySelector(".search-input"), "login.");
  submit(ui.root.querySelector("form.filters"));
  await settle();
  assert.equal(window.location.hash, "#/audit?type=login.");
});

test("long node names keep the full text, carry it as a title and are not cut by the script", async () => {
  const long = "db-postgres-backoffice-ru-prod-01";
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page([node({ id: "n1", name: long }), node({ id: "n2", name: "db-postgres-backoffice-ru-prod-02" })]) }, "#/nodes");
  const links = Array.from(ui.root.querySelectorAll(".node-name"));
  assert.deepEqual(links.map((link) => link.textContent), [long, "db-postgres-backoffice-ru-prod-02"]);
  assert.deepEqual(links.map((link) => link.getAttribute("title")), [long, "db-postgres-backoffice-ru-prod-02"]);
  click(ui.root.querySelector('button[aria-label="List view"]'));
  assert.equal(ui.root.querySelector(".node-row .node-name").getAttribute("title"), long);
});

test("the Labels menu says when it lists only the nodes loaded so far", async () => {
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page(FLEET, { next: "c1" }) }, "#/nodes");
  click(trigger("Labels"));
  assert.match(ui.root.querySelector(".menu").textContent, /loaded so far/);
  ui.stop();
  ui = await mount({ ...signedIn(), ...config, "GET /v1/admin/nodes": page(FLEET) }, "#/nodes");
  click(trigger("Labels"));
  assert.doesNotMatch(ui.root.querySelector(".menu").textContent, /loaded so far/);
});
