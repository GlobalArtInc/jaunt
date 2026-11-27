import assert from "node:assert/strict";
import { test } from "node:test";

import { HOSTILE, NOW } from "../fixtures.mjs";
import { byText, click, json, press, settle, type, until } from "./support.mjs";
import { LIMITS, LIMITS_ROUTE, RECENT_ROUTE, TARGETS_ROUTE, TICKET_ROUTE, activeTab, bannerOf, pane, stateOf, tabLabels, useRig } from "./workspace-support.mjs";

const env = useRig();

const quickRows = (root, index) => Array.from(root.querySelectorAll(".quick-body section")[index].querySelectorAll(".quick-row"));
const rowNames = (root, index) => quickRows(root, index).map((row) => row.querySelector(".name").textContent);
const dialog = () => document.querySelector("[role=dialog]");
const newButton = () => Array.from(env.ui.root.querySelectorAll(".tabbar button")).find((button) => button.textContent.trim() === "New terminal");
const closeButton = (label) => Array.from(env.ui.root.querySelectorAll("button[data-close]")).find((button) => button.getAttribute("aria-label") === "Close " + label);

test("with no terminal open quick open is inline: recent pairs first, then nodes with the pinned one first, offline nodes cannot be opened", async () => {
  const recent = [
    { node: "web-01", login: "alice", last_at: NOW - 7200 },
    { node: "db-01", login: "postgres", last_at: NOW - 90000 },
  ];
  await env.mount({ [RECENT_ROUTE]: json(200, recent) });
  const main = env.ui.main();
  assert.equal(main.querySelector(".ws").hidden, true);
  assert.equal(main.querySelector(".panel.quick h2").textContent, "Open a terminal");
  assert.deepEqual(rowNames(main, 0), ["alice@web-01", "postgres@db-01"]);
  assert.deepEqual(quickRows(main, 0).map((row) => row.querySelector(".muted").textContent), ["2 h ago", "yesterday"]);
  assert.deepEqual(rowNames(main, 1), ["db-01", "web-01", "web-02", "db-replica-02"]);
  const rows = quickRows(main, 1);
  assert.match(rows[0].textContent, /Pinned/);
  assert.equal(rows[1].textContent.includes("Pinned"), false);
  assert.match(rows[2].textContent, /Creates accounts/);
  assert.equal(rows[3].classList.contains("is-off"), true);
  assert.match(rows[3].textContent, /Offline/);
  assert.match(rows[3].textContent, /Cannot open while offline/);
  assert.equal(rows[3].querySelector("button"), null);
  assert.equal(main.querySelector(".panel.quick footer .btn-primary").disabled, true);
  assert.match(main.querySelector(".panel.quick footer").textContent, /0 of 4 terminals open/);
});

test("choosing a login unfolds it in place with the hidden logins line, and the primary button names the choice", async () => {
  await env.mount();
  const main = env.ui.main();
  const primary = () => main.querySelector(".panel.quick footer .btn-primary");
  click(byText(quickRows(main, 1)[1], "button", "Choose login"));
  const row = quickRows(main, 1)[1];
  assert.equal(row.classList.contains("is-open"), true);
  assert.equal(row.querySelector("legend").textContent, "Logins you may use on web-01");
  assert.deepEqual(Array.from(row.querySelectorAll('input[name="quick-login"]')).map((input) => input.value), ["deploy", "alice"]);
  assert.match(row.querySelector(".logins").textContent, /Not shown: Alice\.M, from your roles, because it cannot be an account name on a node\./);
  assert.equal(row.querySelector(".logins p .mono").textContent, "Alice.M");
  assert.equal(byText(row, "button", "Hide logins").getAttribute("aria-expanded"), "true");
  assert.equal(primary().disabled, true);
  const alice = row.querySelectorAll('input[name="quick-login"]')[1];
  alice.checked = true;
  alice.dispatchEvent(new window.Event("change", { bubbles: true }));
  assert.equal(primary().disabled, false);
  assert.equal(primary().textContent, "Open terminal as alice on web-01");
  click(byText(quickRows(main, 1)[1], "button", "Hide logins"));
  assert.equal(quickRows(main, 1)[1].querySelector("fieldset"), null);
  assert.equal(primary().disabled, true);
  click(byText(quickRows(main, 1)[2], "button", "Choose login"));
  assert.equal(quickRows(main, 1)[2].querySelector('input[name="quick-login"]').checked, true);
  assert.match(quickRows(main, 1)[2].textContent, /Your roles allow one login on this node: deploy\. It is selected\./);
  assert.match(quickRows(main, 1)[2].querySelector(".menu-info").textContent, /web-02 creates your account at your first login/);
  assert.equal(primary().textContent, "Open terminal as deploy on web-02");
});

test("searching narrows recent pairs and nodes by name and label and says when nothing matches", async () => {
  const recent = [{ node: "web-01", login: "alice", last_at: NOW - 100 }, { node: "db-01", login: "postgres", last_at: NOW - 100 }];
  await env.mount({ [RECENT_ROUTE]: json(200, recent) });
  const main = env.ui.main();
  type(main.querySelector(".quick-body input[type=search]"), "team:web");
  assert.deepEqual(rowNames(main, 1), ["web-01"]);
  assert.equal(main.querySelectorAll(".quick-body section")[0].hidden, true);
  type(main.querySelector(".quick-body input[type=search]"), "postgres");
  assert.deepEqual(rowNames(main, 0), ["postgres@db-01"]);
  type(main.querySelector(".quick-body input[type=search]"), "no such thing");
  assert.match(main.querySelector(".quick-body").textContent, /No node matches your search/);
  const enter = press(main.querySelector(".quick-body input[type=search]"), "Enter");
  assert.equal(enter.defaultPrevented, true);
});

test("recent pairs for logins or nodes that are no longer allowed are left out, and an offline pair cannot be opened", async () => {
  const recent = [
    { node: "web-01", login: "alice", last_at: NOW - 100 },
    { node: "web-01", login: "gone", last_at: NOW - 100 },
    { node: "ghost", login: "alice", last_at: NOW - 100 },
    { node: "db-replica-02", login: "deploy", last_at: NOW - 100 },
    { node: "web-01", login: "bad login", last_at: NOW - 100 },
  ];
  await env.mount({ [RECENT_ROUTE]: json(200, recent) });
  const main = env.ui.main();
  assert.deepEqual(rowNames(main, 0), ["alice@web-01", "deploy@db-replica-02"]);
  assert.equal(quickRows(main, 0)[1].querySelector("button").disabled, true);
  assert.equal(quickRows(main, 0)[0].querySelector("button").getAttribute("aria-label"), "Open alice@web-01");
});

test("one click on a recent pair opens a terminal with a ticket for that pair, and the workspace replaces quick open", async () => {
  await env.mount({ [RECENT_ROUTE]: json(200, [{ node: "web-01", login: "alice", last_at: NOW - 100 }]) });
  const main = env.ui.main();
  click(quickRows(main, 0)[0].querySelector("button"));
  await until(() => env.rig.sockets.length === 1, "the socket");
  const post = env.ui.server.calls.find((call) => call.method === "POST" && call.path === "/v1/web/terminal/ticket");
  assert.deepEqual(post.body, { node: "web-01", login: "alice" });
  assert.equal(post.headers["x-jaunt-csrf"], "csrf-token-one");
  assert.deepEqual(tabLabels(main), ["alice@web-01"]);
  assert.equal(main.querySelector(".quick"), null);
  assert.equal(main.querySelector(".ws").hidden, false);
  assert.equal(document.title.startsWith("alice@web-01"), true);
});

test("the tab strip is a tablist with one tab per terminal, the state in the accessible name and a count of how many are open", async () => {
  await env.mount();
  const first = await env.openTab("web-01", "alice");
  await env.ready(first);
  await env.openTab("web-02", "deploy");
  const root = env.ui.root;
  const list = root.querySelector('[role="tablist"]');
  assert.equal(list.getAttribute("aria-label"), "Open terminals");
  assert.deepEqual(tabLabels(root), ["alice@web-01", "deploy@web-02"]);
  const tabs = Array.from(root.querySelectorAll('[role="tab"]'));
  assert.deepEqual(tabs.map((tab) => tab.getAttribute("aria-selected")), ["false", "true"]);
  assert.deepEqual(tabs.map((tab) => tab.tabIndex), [-1, 0]);
  assert.match(tabs[0].textContent, /alice@web-01, Connected$/);
  assert.match(tabs[1].textContent, /deploy@web-02, Connecting$/);
  assert.equal(tabs[0].querySelector(".st").getAttribute("aria-hidden"), "true");
  assert.equal(tabs[0].querySelector(".st").textContent, "●");
  assert.equal(tabs[1].querySelector(".st").textContent, "◌");
  assert.equal(tabs[0].getAttribute("aria-controls"), root.querySelectorAll(".term-pane")[0].id);
  assert.equal(root.querySelectorAll(".term-pane")[0].getAttribute("aria-labelledby"), tabs[0].id);
  assert.match(root.querySelector(".tabbar-end").textContent, /2 of 4 open/);
  assert.match(root.querySelector(".tabbar-end [role=status]").textContent, /The limit counts the terminals in all your browser tabs and on all your devices\./);
  assert.equal(root.querySelector(".rail-count").textContent, "2");
  assert.match(root.querySelector(".rail a[href='#/terminal']").textContent, /, 2 open/);
  assert.equal(root.querySelector(".switcher-btn .count").textContent, "2 of 2");
  assert.match(root.querySelector(".switcher-btn").textContent, /deploy@web-02, Connecting, terminal/);
  assert.equal(root.querySelectorAll(".term-pane").length, 2);
  assert.deepEqual(Array.from(root.querySelectorAll(".term-pane")).map((item) => item.hidden), [true, false]);
  click(tabs[0]);
  assert.equal(activeTab(root), "alice@web-01");
  assert.deepEqual(Array.from(root.querySelectorAll(".term-pane")).map((item) => item.hidden), [false, true]);
  assert.equal(document.title.startsWith("alice@web-01"), true);
});

test("the arrow keys, Home and End move between tabs once focus is on the strip", async () => {
  await env.mount();
  for (const [node, login] of [["web-01", "alice"], ["web-02", "deploy"], ["db-01", "postgres"]]) {
    await env.openTab(node, login);
  }
  const tabs = () => Array.from(env.ui.root.querySelectorAll('[role="tab"]'));
  tabs()[2].focus();
  press(tabs()[2], "ArrowRight");
  assert.equal(activeTab(env.ui.root), "alice@web-01");
  assert.equal(document.activeElement, tabs()[0]);
  press(tabs()[0], "ArrowLeft");
  assert.equal(activeTab(env.ui.root), "postgres@db-01");
  press(document.activeElement, "Home");
  assert.equal(activeTab(env.ui.root), "alice@web-01");
  press(document.activeElement, "End");
  assert.equal(activeTab(env.ui.root), "postgres@db-01");
});

test("Ctrl+Alt+PageUp and PageDown switch terminals in a ring and focus the shown terminal, and the terminal never receives them", async () => {
  await env.mount();
  const sockets = [];
  for (const [node, login] of [["web-01", "alice"], ["web-02", "deploy"], ["db-01", "postgres"]]) {
    sockets.push(await env.openTab(node, login));
    await env.ready(sockets.at(-1));
  }
  const root = env.ui.root;
  const send = (key, extra = {}) => {
    const host = pane(root).querySelector(".term-host");
    return press(host, key, { ctrlKey: true, altKey: true, ...extra });
  };
  assert.equal(activeTab(root), "postgres@db-01");
  const event = send("PageDown");
  assert.equal(event.defaultPrevented, true);
  assert.equal(activeTab(root), "alice@web-01");
  assert.ok(env.rig.terminals[0].focused > 1);
  send("PageUp");
  assert.equal(activeTab(root), "postgres@db-01");
  send("PageUp");
  assert.equal(activeTab(root), "deploy@web-02");
  for (const terminal of env.rig.terminals) {
    const handled = new window.KeyboardEvent("keydown", { key: "PageUp", ctrlKey: true, altKey: true, cancelable: true });
    assert.equal(terminal.keyHandler(handled), false);
  }
  for (const extra of [{ ctrlKey: false }, { altKey: false }, { shiftKey: true }, { metaKey: true }]) {
    const before = activeTab(root);
    const other = send("PageDown", extra);
    assert.equal(other.defaultPrevented, false);
    assert.equal(activeTab(root), before);
    const passes = new window.KeyboardEvent("keydown", { key: "PageDown", ctrlKey: true, altKey: true, cancelable: true, ...extra });
    assert.equal(env.rig.terminals[0].keyHandler(passes), true);
  }
  assert.deepEqual(sockets.map((socket) => socket.input()), [[], [], []]);
  const plain = new window.KeyboardEvent("keydown", { key: "PageUp", cancelable: true });
  assert.equal(env.rig.terminals[0].keyHandler(plain), true);
});

test("switching with one terminal does nothing", async () => {
  await env.mount();
  await env.openTab("web-01", "alice");
  const event = press(pane(env.ui.root).querySelector(".term-host"), "PageDown", { ctrlKey: true, altKey: true });
  assert.equal(event.defaultPrevented, true);
  assert.equal(activeTab(env.ui.root), "alice@web-01");
});

test("New terminal opens quick open as a dialog, the count is in its footer and the second terminal opens next to the first", async () => {
  await env.mount();
  await env.openTab("web-01", "alice");
  click(newButton());
  const modal = dialog();
  assert.ok(modal.classList.contains("quick"));
  assert.equal(modal.querySelector("h2").textContent, "Open a terminal");
  assert.match(modal.querySelector("footer").textContent, /1 of 4 terminals open/);
  assert.ok(byText(modal, "button", "Cancel"));
  assert.equal(modal.querySelector('button[aria-label="Close"]').closest("header") !== null, true);
  click(byText(Array.from(modal.querySelectorAll(".quick-row")).find((row) => row.querySelector(".name").textContent === "web-02"), "button", "Choose login"));
  click(byText(modal, "button", "Open terminal as deploy on web-02"));
  await until(() => env.rig.sockets.length === 2, "the second socket");
  assert.equal(dialog(), null);
  assert.deepEqual(tabLabels(env.ui.root), ["alice@web-01", "deploy@web-02"]);
  assert.equal(activeTab(env.ui.root), "deploy@web-02");
});

test("quick open in a dialog can be cancelled and closed with Escape without opening anything", async () => {
  await env.mount();
  await env.openTab("web-01", "alice");
  click(newButton());
  click(byText(dialog(), "button", "Cancel"));
  assert.equal(dialog(), null);
  click(newButton());
  press(dialog(), "Escape");
  assert.equal(dialog(), null);
  assert.equal(env.rig.sockets.length, 1);
});

test("at the limit New terminal is disabled with its reason and quick open cannot open anything", async () => {
  await env.mount({ [LIMITS_ROUTE]: json(200, { ...LIMITS, max_per_user: 2 }) });
  await env.openTab("web-01", "alice");
  assert.equal(newButton().disabled, false);
  await env.openTab("web-02", "deploy");
  assert.equal(newButton().disabled, true);
  assert.match(newButton().title, /All 2 terminals are open/);
  assert.ok(env.ui.root.querySelector("#" + newButton().getAttribute("aria-describedby")).textContent.includes("All 2 terminals are open"));
  assert.match(env.ui.root.querySelector(".tabbar-end").textContent, /2 of 2 open/);
  assert.equal(env.ui.root.querySelector(".switcher .icon-btn[aria-label='New terminal']").disabled, true);
  const menu = env.ui.root.querySelector(".tabbar-end .btn-menu");
  click(menu);
  const entry = Array.from(env.ui.root.querySelectorAll(".menu [role=menuitem]")).find((item) => item.textContent.startsWith("New terminal"));
  assert.equal(entry.getAttribute("aria-disabled"), "true");
  click(menu);
  window.location.hash = "#/terminal?node=db-01&login=postgres";
  await settle();
  assert.equal(env.rig.sockets.length, 2);
  const modal = dialog();
  assert.ok(modal);
  assert.match(modal.querySelector("footer").textContent, /All 2 terminals are open\. Close one to open another\./);
  assert.equal(modal.querySelector("footer .btn-primary").disabled, true);
  assert.equal(Array.from(modal.querySelectorAll(".quick-row")).find((row) => row.querySelector(".name").textContent === "db-01").classList.contains("is-open"), true);
});

test("closing a connected terminal always asks with the effects named, an ended or unopened one never asks", async () => {
  await env.mount();
  const first = await env.openTab("web-01", "alice");
  await env.ready(first, { recording: "full" });
  click(closeButton("alice@web-01"));
  let modal = dialog();
  assert.equal(modal.querySelector("h2").textContent, "Close alice@web-01?");
  assert.match(modal.querySelector(".body").textContent, /This terminal is still connected\. Closing it ends the shell on web-01 and every program running in it\./);
  assert.equal(modal.querySelector(".body strong").textContent, "web-01");
  assert.deepEqual(Array.from(modal.querySelectorAll(".effects li")).map((item) => item.textContent), ["The session ends now and cannot be resumed.", "What was on the screen is kept only in the recording."]);
  click(byText(modal, "button", "Keep open"));
  assert.equal(dialog(), null);
  assert.equal(first.closed, null);
  assert.deepEqual(tabLabels(env.ui.root), ["alice@web-01"]);
  click(closeButton("alice@web-01"));
  click(byText(dialog(), "button", "Close terminal"));
  await settle();
  assert.deepEqual(first.closed, [1000, ""]);
  assert.deepEqual(tabLabels(env.ui.root), []);
  assert.equal(env.rig.terminals[0].disposed, true);
  assert.equal(env.ui.root.querySelector(".ws").hidden, true);
  assert.ok(env.ui.main().querySelector(".panel.quick"));
  assert.equal(env.ui.root.querySelector(".rail-count"), null);

  const second = await env.openTab("web-01", "alice");
  await env.ready(second);
  second.control({ t: "exit", status: 0, signal: null });
  second.drop(1000);
  await settle();
  click(closeButton("alice@web-01"));
  assert.equal(dialog(), null);
  assert.deepEqual(tabLabels(env.ui.root), []);

  await env.openTab("web-02", "deploy");
  click(closeButton("deploy@web-02"));
  assert.equal(dialog(), null);
  assert.deepEqual(tabLabels(env.ui.root), []);
});

test("the confirmation says so when the session is not recorded", async () => {
  await env.mount();
  const socket = await env.openTab("web-01", "alice");
  await env.ready(socket, { recording: "off" });
  click(closeButton("alice@web-01"));
  assert.deepEqual(Array.from(dialog().querySelectorAll(".effects li")).map((item) => item.textContent), ["The session ends now and cannot be resumed.", "This session is not recorded, so what was on the screen is lost."]);
});

test("closing the shown terminal shows its neighbour and a banner button closes an ended tab", async () => {
  await env.mount();
  const sockets = [];
  for (const [node, login] of [["web-01", "alice"], ["web-02", "deploy"], ["db-01", "postgres"]]) {
    sockets.push(await env.openTab(node, login));
    await env.ready(sockets.at(-1));
  }
  sockets[2].control({ t: "exit", status: 0, signal: null });
  sockets[2].drop(1000);
  await settle();
  assert.equal(stateOf(env.ui.root), "Session ended");
  click(byText(pane(env.ui.root), "button", "Close terminal"));
  assert.deepEqual(tabLabels(env.ui.root), ["alice@web-01", "deploy@web-02"]);
  assert.equal(activeTab(env.ui.root), "deploy@web-02");
  assert.equal(pane(env.ui.root).querySelector(".statusbar .mono").textContent, "web-02");
  assert.equal(document.activeElement.getAttribute("role"), "tab");
  assert.equal(document.activeElement.querySelector(".lbl").textContent, "deploy@web-02");
});

test("All terminals lists every terminal with its state in words, switches on selection and closes only the ended ones", async () => {
  await env.mount();
  const sockets = [];
  for (const [node, login] of [["web-01", "alice"], ["web-02", "deploy"], ["db-01", "postgres"]]) {
    sockets.push(await env.openTab(node, login));
  }
  await env.ready(sockets[0]);
  await env.ready(sockets[1]);
  env.rig.clock.advance(5000);
  sockets[1].drop(1006);
  await settle();
  click(env.ui.root.querySelector(".tabbar-end .btn-menu"));
  const entries = Array.from(env.ui.root.querySelectorAll(".menu [role=menuitemradio]"));
  assert.equal(env.ui.root.querySelector(".menu .menu-heading").textContent, "Open terminals (3 of 4)");
  assert.deepEqual(entries.map((item) => item.querySelector(".menu-label").textContent.trim()), ["● alice@web-01", "✕ deploy@web-02", "◌ postgres@db-01"]);
  assert.deepEqual(entries.map((item) => item.querySelector(".menu-hint").textContent), ["Connected, 00:05", "Ended: connection lost", "Connecting, 00:00"]);
  assert.deepEqual(entries.map((item) => item.getAttribute("aria-checked")), ["false", "false", "true"]);
  click(entries[0]);
  assert.equal(activeTab(env.ui.root), "alice@web-01");
  click(env.ui.root.querySelector(".tabbar-end .btn-menu"));
  const closeEnded = Array.from(env.ui.root.querySelectorAll(".menu [role=menuitem]")).find((item) => item.textContent === "Close ended terminals");
  assert.equal(closeEnded.getAttribute("aria-disabled"), null);
  click(closeEnded);
  assert.deepEqual(tabLabels(env.ui.root), ["alice@web-01", "postgres@db-01"]);
  click(env.ui.root.querySelector(".tabbar-end .btn-menu"));
  assert.equal(Array.from(env.ui.root.querySelectorAll(".menu [role=menuitem]")).find((item) => item.textContent === "Close ended terminals").getAttribute("aria-disabled"), "true");
});

test("on a narrow screen the switcher button names the shown terminal and opens the same list", async () => {
  await env.mount({}, "#/terminal", [], { before: (win) => (win.matchMedia = () => ({ matches: true })) });
  await env.openTab("web-01", "alice");
  await env.openTab("web-02", "deploy");
  const switcher = env.ui.root.querySelector(".switcher-btn");
  assert.equal(switcher.getAttribute("aria-haspopup"), "menu");
  assert.equal(switcher.querySelector(".count").textContent, "2 of 2");
  click(switcher);
  assert.equal(env.ui.root.querySelectorAll(".switcher .menu [role=menuitemradio]").length, 2);
  click(env.ui.root.querySelector(".switcher .menu [role=menuitemradio]"));
  assert.equal(activeTab(env.ui.root), "alice@web-01");
  assert.equal(switcher.querySelector(".mono").textContent, "alice@web-01");
  click(closeButton("alice@web-01"));
  await settle();
  assert.equal(document.activeElement, switcher);
});

test("moving around the console keeps every terminal and Show my terminals opens the list", async () => {
  await env.mount();
  const socket = await env.openTab("web-01", "alice");
  await env.ready(socket);
  window.location.hash = "#/sessions";
  await settle();
  assert.equal(socket.closed, null);
  assert.equal(env.ui.root.querySelector(".ws").hidden, true);
  assert.equal(env.ui.root.querySelector(".rail-count").textContent, "1");
  window.location.hash = "#/terminal";
  await settle();
  assert.equal(env.ui.root.querySelector(".ws").hidden, false);
  assert.equal(env.ui.main().querySelectorAll(".term-pane").length, 1);
  assert.equal(env.rig.terminals.length, 1);
});

test("a hostile node name or login is text in the tab, the header, the title, quick open and the close question", async () => {
  const hostile = [{ node: HOSTILE.tag, labels: { [HOSTILE.quote]: HOSTILE.rtl }, connected: true, pinned: false, logins: ["ok", "no way"], hidden_logins: [HOSTILE.tag, HOSTILE.control] }];
  await env.mount({ [TARGETS_ROUTE]: json(200, hostile) });
  const main = env.ui.main();
  assert.equal(main.querySelector("img, script"), null);
  assert.ok(main.querySelector(".quick-row .name").textContent.includes(HOSTILE.tag));
  click(byText(main.querySelector(".quick-row"), "button", "Choose login"));
  assert.deepEqual(Array.from(main.querySelectorAll('input[name="quick-login"]')).map((input) => input.value), ["ok"]);
  assert.equal(main.querySelector("img, script"), null);
  assert.ok(main.querySelector(".logins").textContent.includes(HOSTILE.tag));
  click(main.querySelector(".panel.quick footer .btn-primary"));
  await until(() => env.rig.sockets.length === 1, "the socket");
  const socket = env.rig.sockets[0];
  await env.ready(socket);
  const label = "ok@" + HOSTILE.tag;
  assert.deepEqual(tabLabels(env.ui.root), [label]);
  assert.equal(env.ui.root.querySelector(".ttab img, .statusbar img, .switcher img, .term-pane img"), null);
  assert.ok(pane(env.ui.root).querySelector(".statusbar").textContent.includes(HOSTILE.tag));
  assert.ok(document.title.includes(HOSTILE.tag));
  assert.equal(window.__pwned, undefined);
  click(closeButton(label));
  assert.equal(dialog().querySelector("img, script"), null);
  assert.ok(dialog().querySelector("strong").textContent.includes(HOSTILE.tag));
});

test("a hash never opens a socket: it only pre-fills quick open, and a click on Open does", async () => {
  await env.mount({}, "#/terminal?node=web-01&login=alice");
  await settle();
  assert.equal(env.rig.sockets.length, 0);
  assert.equal(env.ui.server.count("POST", "/v1/web/terminal/ticket"), 0);
  assert.equal(env.ui.main().querySelector(".ws").hidden, true);
  assert.equal(env.ui.main().querySelector('input[name="quick-login"]:checked').value, "alice");
  const primary = env.ui.main().querySelector(".panel.quick footer .btn-primary");
  assert.equal(primary.textContent, "Open terminal as alice on web-01");
  assert.equal(primary.disabled, false);
  window.location.hash = "#/sessions";
  await settle();
  window.location.hash = "#/terminal?node=web-01&login=alice";
  await settle();
  assert.equal(env.ui.server.count("POST", "/v1/web/terminal/ticket"), 0);
  click(env.ui.main().querySelector(".panel.quick footer .btn-primary"));
  await until(() => env.rig.sockets.length === 1, "the socket");
  assert.equal(env.ui.server.count("POST", "/v1/web/terminal/ticket"), 1);
});

test("a hash with tabs open shows the dialog pre-filled and still opens nothing, an offline node or a login the node does not offer pre-selects no login", async () => {
  await env.mount();
  await env.openTab("web-02", "deploy");
  window.location.hash = "#/terminal?node=web-01&login=alice";
  await settle();
  const modal = dialog();
  assert.ok(modal);
  assert.equal(modal.querySelector('input[name="quick-login"]:checked').value, "alice");
  assert.equal(env.ui.server.count("POST", "/v1/web/terminal/ticket"), 1);
  assert.equal(env.rig.sockets.length, 1);
  click(byText(modal, "button", "Cancel"));
  env.ui.stop();
  env.ui = null;
  env.rig.sockets.length = 0;
  for (const [node, login] of [["db-replica-02", "deploy"], ["web-01", "root"], ["ghost", "alice"]]) {
    await env.mount({}, "#/terminal?node=" + node + "&login=" + login);
    assert.equal(env.rig.sockets.length, 0, node + login);
    assert.equal(env.ui.main().querySelector('input[name="quick-login"]:checked'), null);
    assert.equal(env.ui.main().querySelector(".panel.quick footer .btn-primary").disabled, true);
    env.ui.stop();
    env.ui = null;
  }
});

test("a refused first load of the node list says so with a retry, and an empty list says no nodes are available", async () => {
  await env.mount({ [TARGETS_ROUTE]: json(500, { error: "internal" }) });
  assert.match(env.ui.main().textContent, /The list of nodes could not be loaded/);
  assert.ok(byText(env.ui.root, "button", "Try again"));
  env.ui.stop();
  await env.mount({ [TARGETS_ROUTE]: json(200, []) });
  assert.match(env.ui.main().textContent, /No nodes available to you/);
  env.ui.stop();
  await env.mount({ [TARGETS_ROUTE]: json(404, { error: "not_found" }) });
  assert.match(env.ui.main().textContent, /The web terminal is turned off/);
  assert.equal(env.ui.root.querySelector('.rail a[href="#/terminal"]'), null);
  env.ui = null;
});

test("opening is refused by the server limit with the numbers of the answer and a reference, and the tab can be closed", async () => {
  await env.mount({ [TICKET_ROUTE]: json(429, { error: "limit", open: 4, max: 4, ref: "D-4C1E82A9" }) });
  await env.chooseAndOpen("web-01", "alice");
  await until(() => bannerOf(env.ui.root) !== "", "the limit banner");
  const text = bannerOf(env.ui.root);
  assert.match(text, /^Too many terminals\. You have/);
  assert.match(text, /You have 4 terminals open, and 4 is the most allowed at once\./);
  assert.match(text, /Terminals in other browser tabs or on other devices count too\. Close one and try again\./);
  assert.equal(pane(env.ui.root).querySelector(".ref .mono").textContent, "D-4C1E82A9");
  assert.equal(stateOf(env.ui.root), "Not opened");
  assert.deepEqual(Array.from(pane(env.ui.root).querySelectorAll(".term-banner .actions .btn")).map((item) => item.textContent), ["Try again", "Show my terminals"]);
  click(byText(pane(env.ui.root), "button", "Show my terminals"));
  assert.ok(env.ui.root.querySelector(".tabbar-end .menu"));
  assert.equal(env.rig.sockets.length, 0);
});

test("without a limits answer the counter only says how many are open and nothing is refused here, and a nonsensical limit is ignored", async () => {
  for (const reply of [json(404, { error: "not_found" }), json(200, { max_per_user: 0 }), json(200, { max_per_user: "4" }), json(200, { max_per_user: 1e9 }), json(200, []), json(500, {})]) {
    await env.mount({ [LIMITS_ROUTE]: reply });
    await env.openTab("web-01", "alice");
    await env.openTab("web-02", "deploy");
    assert.match(env.ui.root.querySelector(".tabbar-end [role=status]").firstChild.textContent, /^2 open$/, JSON.stringify(reply.body));
    assert.equal(newButton().disabled, false);
    env.ui.stop();
    env.ui = null;
  }
});

test("closing the browser tab asks only while a terminal is live", async () => {
  await env.mount();
  const ask = () => {
    const event = new window.Event("beforeunload", { cancelable: true });
    window.dispatchEvent(event);
    return event.defaultPrevented;
  };
  assert.equal(ask(), false);
  const socket = await env.openTab("web-01", "alice");
  assert.equal(ask(), true);
  await env.ready(socket);
  assert.equal(ask(), true);
  socket.control({ t: "exit", status: 0, signal: null });
  socket.drop(1000);
  await settle();
  assert.equal(ask(), false);
});

test("the tab label is cleaned: bidirectional controls and line breaks in node and login names are replaced", async () => {
  const name = "evil\u202egpj.exe\nnext";
  await env.mount({ [TARGETS_ROUTE]: json(200, [{ node: name, labels: {}, connected: true, pinned: false, logins: ["ok"] }]) });
  await env.chooseAndOpen("evil\uFFFDgpj.exe\uFFFDnext", "ok");
  await until(() => env.rig.sockets.length === 1, "the socket");
  const label = tabLabels(env.ui.root)[0];
  assert.equal(label, "ok@evil\uFFFDgpj.exe\uFFFDnext");
  assert.equal(label.includes("\u202e"), false);
  assert.equal(label.includes("\n"), false);
  assert.equal(env.ui.root.querySelector(".switcher-btn .mono").textContent, label);
  assert.equal(document.title.includes("\u202e"), false);
});

test("Enter in the search field of quick open only filters: it never opens a session, inline or in a dialog", async () => {
  await env.mount({}, "#/terminal?node=web-01&login=alice");
  const search = () => env.ui.main().querySelector(".quick-body input[type=search]");
  assert.equal(env.ui.main().querySelector(".panel.quick footer .btn-primary").disabled, false);
  const enter = press(search(), "Enter");
  assert.equal(enter.defaultPrevented, true);
  type(search(), "web");
  press(search(), "Enter");
  await settle();
  assert.equal(env.ui.server.count("POST", "/v1/web/terminal/ticket"), 0);
  assert.equal(env.rig.sockets.length, 0);
  env.ui.stop();
  env.ui = null;
  await env.mount();
  await env.openTab("web-02", "deploy");
  window.location.hash = "#/terminal?node=web-01&login=alice";
  await settle();
  const field = dialog().querySelector("input[type=search]");
  assert.equal(dialog().querySelector("footer .btn-primary").disabled, false);
  press(field, "Enter");
  await settle();
  assert.equal(env.ui.server.count("POST", "/v1/web/terminal/ticket"), 1);
  assert.equal(env.rig.sockets.length, 1);
});
