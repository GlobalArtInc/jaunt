import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";

import { HOSTILE, NOW, node } from "../fixtures.mjs";
import { byText, click, json, mount, settle, signedIn } from "./support.mjs";
import { TICKET, installTerminalHooks } from "./terminal-support.mjs";

const HOOKS = "../../crates/jaunt-web/assets/assets/js/terminal/hooks.js";
const TICKET_ROUTE = "POST /v1/web/terminal/ticket";
const TARGETS_ROUTE = "GET /v1/web/terminal/targets";
const NODES_ROUTE = "GET /v1/admin/nodes";
const BASE = { "GET /v1/web/terminal/recent": json(200, []), "GET /v1/client-config": json(200, { ssh_suffix: "jaunt.example.com" }), "GET /v1/web/terminal/limits": json(200, { max_per_user: 4, idle_timeout_secs: 1800 }) };
const FLEET = [
  { node: "db-02", labels: {}, connected: true, creates_accounts: true, logins: ["alice"] },
  { node: "web-01", labels: {}, connected: true, creates_accounts: false, logins: ["alice"] },
  { node: "web-02", labels: {}, connected: true, logins: ["alice"] },
];
const LONG = "A".repeat(3000);
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

async function begin(nodeName = "db-02", fleet = FLEET) {
  ui = await mount({ ...signedIn([]), ...BASE, [TARGETS_ROUTE]: json(200, fleet), [TICKET_ROUTE]: GRANT }, "#/terminal?node=" + encodeURIComponent(nodeName) + "&login=alice");
  click(ui.root.querySelector(".panel.quick footer .btn-primary"));
  for (let round = 0; round < 50 && rig.sockets.length === 0; round += 1) {
    await settle();
  }
  const socket = rig.sockets[0];
  socket.accept();
  return socket;
}

const bannerText = () => ui.root.querySelector(".term-banner").textContent;
const states = () => ui.root.querySelector(".statusbar [role=status]").textContent;

test("the Creates accounts marker shows for true and not for false or a missing field, in quick open and on the node cards", async () => {
  ui = await mount({ ...signedIn([]), ...BASE, [TARGETS_ROUTE]: json(200, FLEET) }, "#/terminal");
  const marked = Array.from(ui.main().querySelectorAll(".quick-row")).filter((row) => row.textContent.includes("Creates accounts"));
  assert.deepEqual(marked.map((row) => row.querySelector(".name").textContent), ["db-02"]);
  ui.stop();

  const nodes = [node({ id: "n-1", name: "db-02", creates_accounts: true }), node({ id: "n-2", name: "web-01", creates_accounts: false }), node({ id: "n-3", name: "web-02", connected_since: NOW - 5 })];
  ui = await mount({ ...signedIn(), [NODES_ROUTE]: json(200, { nodes, next: null, pending_enrolments: 0 }) }, "#/nodes");
  const cards = Array.from(ui.root.querySelectorAll(".node-card"));
  assert.deepEqual(cards.map((card) => card.textContent.includes("Creates accounts")), [true, false, false]);
  const mark = ui.root.querySelector(".badge.b-acct");
  assert.equal(mark.textContent, "Creates accounts");
  assert.match(mark.getAttribute("title"), /first login with a new name creates the account/);
});

test("the Connect menu explains account creation only for a node that creates accounts", async () => {
  const nodes = [node({ id: "n-1", name: "db-02", creates_accounts: true }), node({ id: "n-2", name: "web-01" })];
  ui = await mount({ ...signedIn(), ...BASE, [TARGETS_ROUTE]: json(200, FLEET), [NODES_ROUTE]: json(200, { nodes, next: null, pending_enrolments: 0 }) }, "#/nodes");
  await settle();
  const trigger = (label) => Array.from(ui.root.querySelectorAll("button")).find((button) => button.getAttribute("aria-label") === label);
  click(trigger("Connect to db-02"));
  assert.match(ui.root.querySelector(".menu-info").textContent, /db-02 creates your account at your first login/);
  click(trigger("Connect to db-02"));
  click(trigger("Connect to web-01"));
  assert.equal(ui.root.querySelector(".menu-info"), null);
});

test("the account progress frame shows the banner until ready, and any other stage is ignored", async () => {
  const socket = await begin();
  socket.control({ t: "progress", stage: "node" });
  socket.control({ t: "progress", stage: "<img src=x>" });
  socket.control({ t: "progress" });
  await settle();
  assert.equal(bannerText(), "");
  socket.control({ t: "progress", stage: "account" });
  await settle();
  assert.match(bannerText(), /Creating your account alice on db-02…/);
  assert.equal(states(), "Creating account…");
  socket.control({ t: "ready", session_id: "s-1", account_created: true, home: "/home/alice" });
  await settle();
  assert.doesNotMatch(bannerText(), /Creating your account/);
  assert.equal(states(), "Connected");
});

test("an end or an error clears the progress banner and a progress frame after ready is ignored", async () => {
  let socket = await begin();
  socket.control({ t: "progress", stage: "account" });
  socket.control({ t: "error", code: "account_failed", ref: "H-51C07A42" });
  socket.drop(1008);
  await settle();
  assert.doesNotMatch(bannerText(), /Creating your account/);
  assert.match(bannerText(), /could not create your account/);
  ui.stop();
  rig.sockets.length = 0;

  socket = await begin();
  socket.control({ t: "ready", session_id: "s-1" });
  socket.control({ t: "progress", stage: "account" });
  await settle();
  assert.equal(bannerText(), "");
});

test("ready with account_created shows a one-time banner with the home path, without it when home is absent, and nothing for false or missing", async () => {
  const cases = [
    [{ account_created: true, home: "/home/alice" }, /^Account created\. The account alice was created on db-02 at this login, with the home directory \/home\/alice\.Dismiss$/],
    [{ account_created: true }, /^Account created\. The account alice was created on db-02 at this login\.Dismiss$/],
    [{ account_created: false, home: "/home/alice" }, null],
    [{}, null],
    [{ account_created: "true", home: "/home/alice" }, null],
  ];
  for (const [fields, expected] of cases) {
    const socket = await begin();
    socket.control({ t: "ready", session_id: "s-1", ...fields });
    await settle();
    if (expected === null) {
      assert.equal(bannerText(), "", JSON.stringify(fields));
    } else {
      assert.match(bannerText(), expected, JSON.stringify(fields));
    }
    assert.deepEqual(rig.terminals[0].written, []);
    ui.stop();
    rig.sockets.length = 0;
    rig.terminals.length = 0;
  }
  ui = null;
});

test("the account created banner can be dismissed and never writes into the terminal", async () => {
  const socket = await begin();
  socket.control({ t: "ready", session_id: "s-1", account_created: true, home: "/home/alice" });
  socket.output(Array.from(new TextEncoder().encode("node output")));
  await settle();
  click(byText(ui.root, "button", "Dismiss"));
  assert.equal(bannerText(), "");
  assert.equal(rig.terminals[0].written.join(""), "node output");
});

test("a hostile or very long home path is shown as text and bounded", async () => {
  for (const home of [HOSTILE.tag, HOSTILE.quote, HOSTILE.control, LONG]) {
    const socket = await begin();
    socket.control({ t: "ready", session_id: "s-1", account_created: true, home });
    await settle();
    const banner = ui.root.querySelector(".term-banner .banner");
    assert.equal(banner.querySelector(".banner-body img, .banner-body script, .banner-body svg"), null);
    assert.equal(window.__pwned, undefined);
    assert.ok(banner.textContent.length < 600, String(banner.textContent.length));
    if (home === HOSTILE.tag) {
      assert.ok(banner.textContent.includes(HOSTILE.tag));
    }
    ui.stop();
    rig.sockets.length = 0;
    rig.terminals.length = 0;
  }
  ui = null;
});

test("each account error code has its own text, shows the reference and the right actions", async () => {
  const cases = [
    ["account_refused", "H-9D0311FE", /Your account could not be created\. db-02 does not allow creating the account alice\./, ["Choose another login"], "danger"],
    ["account_failed", "H-51C07A42", /The node could not create your account\. Something went wrong on db-02 while creating alice\./, ["Try again"], "warn"],
    ["no_account", "H-0000000D", /There is no account alice on db-02\. This node does not create accounts\./, ["Choose another login"], "warn"],
  ];
  for (const [code, reference, expected, actions, kind] of cases) {
    const socket = await begin();
    socket.control({ t: "progress", stage: "account" });
    socket.control({ t: "error", code, ref: reference });
    socket.drop(1008);
    await settle();
    assert.match(bannerText(), expected, code);
    assert.ok(ui.root.querySelector(".term-banner .banner-" + kind), code);
    const line = ui.root.querySelector(".term-banner .ref");
    assert.equal(line.querySelector(".mono").textContent, reference);
    assert.match(line.textContent, /Reference for your administrator:/);
    assert.deepEqual(Array.from(ui.root.querySelectorAll(".term-banner .actions .btn")).map((item) => item.textContent), actions, code);
    assert.equal(states(), "Not opened");
    click(line.querySelector("button"));
    await settle();
    assert.deepEqual(rig.clipboard.written.at(-1), reference);
    assert.equal(rig.sockets.length, 1);
    ui.stop();
    rig.sockets.length = 0;
    rig.terminals.length = 0;
    rig.clipboard.written.length = 0;
  }
  ui = null;
});

test("Choose another login opens quick open with the node unfolded", async () => {
  const socket = await begin();
  socket.control({ t: "error", code: "account_refused", ref: "H-9D0311FE" });
  socket.drop(1008);
  await settle();
  click(byText(ui.root, "button", "Choose another login"));
  const dialog = document.querySelector("[role=dialog]");
  assert.ok(dialog);
  assert.equal(dialog.querySelector(".quick-row.is-open .name").textContent, "db-02");
  assert.equal(dialog.querySelector('input[name="quick-login"]').value, "alice");
});

test("a reference that does not match D- or H- and eight capital hex digits is never rendered, and the cause text stays", async () => {
  const bad = ["X-0B77E310", "D-0b77e310", "H-9d0311fe", "H-9D0311F", "H-9D0311FE0", "h-9D0311FE", " H-9D0311FE", "H-9D0311FE\n", HOSTILE.tag, "<b>H-9D0311FE</b>", LONG, 5, null, ["H-9D0311FE"]];
  for (const reference of bad) {
    const socket = await begin();
    socket.control({ t: "error", code: "account_refused", ref: reference });
    socket.drop(1008);
    await settle();
    assert.match(bannerText(), /Your account could not be created\./);
    assert.equal(ui.root.querySelector(".term-banner .ref"), null, JSON.stringify(reference));
    assert.equal(ui.root.querySelector(".term-banner img, .term-banner b"), null);
    ui.stop();
    rig.sockets.length = 0;
    rig.terminals.length = 0;
  }
  ui = null;
});

test("an unknown error code keeps the generic fallback and never shows a reference", async () => {
  const socket = await begin();
  socket.control({ t: "error", code: "account_vanished", ref: "H-9D0311FE" });
  socket.drop(1008);
  await settle();
  assert.match(bannerText(), /refused a message from this page/);
  assert.equal(ui.root.querySelector(".term-banner .ref"), null);
});

test("when the browser refuses copying the reference stays selectable and the note says so", async () => {
  const socket = await begin();
  socket.control({ t: "error", code: "no_account", ref: "H-0000000D" });
  socket.drop(1008);
  await settle();
  rig.clipboard.denied = true;
  click(ui.root.querySelector(".term-banner .ref button"));
  await settle();
  assert.match(ui.root.querySelector(".term-note").textContent, /did not allow copying/);
  assert.equal(ui.root.querySelector(".term-banner .ref .mono").textContent, "H-0000000D");
});

test("the three account causes are in the strings module with a title, a text and a kind", async () => {
  const { S } = await import("../../crates/jaunt-web/assets/assets/js/strings.js");
  for (const cause of ["account_refused", "account_failed", "no_account"]) {
    const [title, body, kind] = S.terminal.session.causes[cause];
    assert.ok(title("alice", "db-02").length > 0 && body("alice", "db-02").length > 0, cause);
    assert.ok(["info", "warn", "danger"].includes(kind), cause);
  }
});

test("the Connect menu has no account explanation for a node without the field or with false", async () => {
  const targets = [{ node: "web-02", labels: {}, connected: true, logins: ["alice"] }, { node: "web-01", labels: {}, connected: true, creates_accounts: false, logins: ["alice"] }];
  const nodes = [node({ id: "n-1", name: "web-01" }), node({ id: "n-2", name: "web-02" })];
  ui = await mount({ ...signedIn(), ...BASE, [TARGETS_ROUTE]: json(200, targets), [NODES_ROUTE]: json(200, { nodes, next: null, pending_enrolments: 0 }) }, "#/nodes");
  await settle();
  const trigger = (label) => Array.from(ui.root.querySelectorAll("button")).find((button) => button.getAttribute("aria-label") === label);
  for (const name of ["web-02", "web-01"]) {
    click(trigger("Connect to " + name));
    assert.ok(ui.root.querySelector(".menu"), name);
    assert.equal(ui.root.querySelector(".menu-info"), null, name);
    click(trigger("Connect to " + name));
  }
});

test("progress then a ready without account_created clears the banner and shows no account created banner", async () => {
  const socket = await begin();
  socket.control({ t: "progress", stage: "account" });
  await settle();
  assert.match(bannerText(), /Creating your account/);
  socket.control({ t: "ready", session_id: "s-1" });
  await settle();
  assert.equal(bannerText(), "");
  assert.equal(ui.root.querySelector(".term-banner .banner"), null);
});

test("Choose another login keeps a node name with spaces and separators intact in the address", async () => {
  const fleet = [{ node: "a b&c#d", labels: {}, connected: true, logins: ["alice"] }];
  const socket = await begin("a b&c#d", fleet);
  socket.control({ t: "error", code: "no_account", ref: "H-0000000D" });
  socket.drop(1008);
  await settle();
  click(byText(ui.root, "button", "Choose another login"));
  assert.equal(document.querySelector("[role=dialog] .quick-row.is-open .name").textContent, "a b&c#d");
});

test("control characters in the home path are replaced one by one and nothing else changes", async () => {
  const socket = await begin();
  socket.control({ t: "ready", session_id: "s-1", account_created: true, home: "/home/a\u0007b\u0000c\u001bd" });
  await settle();
  assert.ok(bannerText().includes("with the home directory /home/a\uFFFDb\uFFFDc\uFFFDd."), bannerText());
});

test("a node that is not active or not connected shows no creates accounts marker even when the field is true", async () => {
  const nodes = [
    node({ id: "n-1", name: "gone", state: "removed", creates_accounts: true }),
    node({ id: "n-2", name: "waiting", state: "pending", creates_accounts: true }),
    node({ id: "n-3", name: "live", creates_accounts: true }),
  ];
  ui = await mount({ ...signedIn(), ...BASE, [NODES_ROUTE]: json(200, { nodes, next: null, pending_enrolments: 0 }) }, "#/nodes?state=");
  const marked = Array.from(ui.root.querySelectorAll(".node-card")).filter((card) => card.querySelector(".badge.b-acct")).map((card) => card.querySelector(".node-name").textContent);
  const shown = Array.from(ui.root.querySelectorAll(".node-card .node-name")).map((link) => link.textContent);
  assert.deepEqual(shown.sort(), ["gone", "live", "waiting"]);
  assert.deepEqual(marked, ["live"]);
  ui.stop();

  const targets = [{ node: "off-01", labels: {}, connected: false, creates_accounts: true, logins: ["alice"] }, { node: "on-01", labels: {}, connected: true, creates_accounts: true, logins: ["alice"] }];
  ui = await mount({ ...signedIn([]), ...BASE, [TARGETS_ROUTE]: json(200, targets) }, "#/terminal");
  const rows = Array.from(ui.main().querySelectorAll(".quick-row")).filter((row) => row.querySelector(".badge.b-acct"));
  assert.deepEqual(rows.map((row) => row.querySelector(".name").textContent), ["on-01"]);
});

test("every refusal carries the reference when it is valid, also for the older error codes, and an invalid one is not shown", async () => {
  const cases = [["denied", 1008], ["limit", 1008], ["revoked", 4001]];
  for (const [code, close] of cases) {
    for (const [reference, shown] of [["H-4C1E82A9", true], ["D-4C1E82A9", true], ["<b>x</b>", false]]) {
      const socket = await begin();
      socket.control({ t: "error", code, ref: reference });
      socket.drop(close);
      await settle();
      const line = ui.root.querySelector(".term-banner .ref");
      if (shown) {
        assert.equal(line.querySelector(".mono").textContent, reference, code);
      } else {
        assert.equal(line, null, code + " " + reference);
      }
      ui.stop();
      rig.sockets.length = 0;
      rig.terminals.length = 0;
    }
  }
  ui = null;
});

test("the reference Copy button and the account created banner carry the copy and check icons", async () => {
  let socket = await begin();
  socket.control({ t: "error", code: "account_refused", ref: "H-9D0311FE" });
  socket.drop(1008);
  await settle();
  assert.ok(ui.root.querySelector(".term-banner .ref button svg"));
  assert.equal(ui.root.querySelector(".term-banner .ref button").getAttribute("aria-label"), "Copy reference H-9D0311FE");
  ui.stop();
  rig.sockets.length = 0;
  socket = await begin();
  socket.control({ t: "ready", session_id: "s-1", account_created: true });
  await settle();
  assert.ok(ui.root.querySelector(".term-banner .banner-icon svg path[d^='M5 12.5']"));
});
