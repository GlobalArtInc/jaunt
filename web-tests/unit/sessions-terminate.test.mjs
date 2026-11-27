import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { ALL, HOSTILE, NOW, sessionRow } from "../fixtures.mjs";
import { byText, click, json, mount, settle, signedIn, type } from "./support.mjs";

let ui = null;
afterEach(() => {
  if (ui) {
    ui.stop();
    ui = null;
  }
});

const PERMISSIONS = [...ALL, "sessions.terminate"];
const ID = "5b1c0a42-aaaa-bbbb-cccc-111122223333";
const ROUTE = "POST /v1/admin/sessions/" + ID + "/terminate";
const CAROL = "2c9d11f0-aaaa-bbbb-cccc-111122223333";
const page = (sessions) => json(200, { sessions, next: null });
const ROWS = [
  sessionRow({ origin: "web" }),
  sessionRow({ id: CAROL, origin: "ssh", user_email: "carol@example.com", user_id: "u-carol", node_name: "db-01", login: "postgres", created_at: NOW - 2520 }),
  sessionRow({ id: "e8a01b33-aaaa-bbbb-cccc-111122223333", state: "ended", ended_at: NOW - 60, end_reason: "terminated", origin: "web" }),
  sessionRow({ id: "90ff2c4d-aaaa-bbbb-cccc-111122223333", state: "ended", ended_at: NOW - 60, end_reason: "closed", exit_status: 0 }),
];
const dialog = () => document.querySelector("[role=dialog]");
const terminateButtons = () => Array.from(ui.root.querySelectorAll("table.data button")).filter((button) => button.textContent === "Terminate…");

function open(extra = {}, permissions = PERMISSIONS, hash = "#/sessions") {
  return mount({ ...signedIn(permissions), "GET /v1/admin/sessions": page(ROWS), ...extra }, hash);
}

test("the table has the Origin column with an icon and a word, a dash when the origin is missing or unknown, and an Actions column", async () => {
  ui = await open({ "GET /v1/admin/sessions": page([...ROWS.slice(0, 2), sessionRow({ id: "11111111-aaaa-bbbb-cccc-111122223333", origin: HOSTILE.tag }), sessionRow({ id: "22222222-aaaa-bbbb-cccc-111122223333" })]) });
  assert.deepEqual(Array.from(ui.root.querySelectorAll("table.data thead th")).map((cell) => cell.textContent), ["Session", "State", "Origin", "User", "Node", "Login", "Started", "Ended", "Outcome", "Actions"]);
  const cells = Array.from(ui.root.querySelectorAll("table.data tbody tr")).map((row) => row.querySelector(".cell-origin"));
  assert.deepEqual(cells.map((cell) => cell.textContent), ["Web terminal", "ssh", "—", "—"]);
  assert.ok(cells[0].querySelector(".chip svg"));
  assert.ok(cells[1].querySelector(".chip svg"));
  assert.equal(cells[2].querySelector("img"), null);
});

test("the Origin filter sends origin to the server, keeps it in the address and ignores a value that is not web or ssh", async () => {
  ui = await open();
  const origin = Array.from(ui.root.querySelectorAll("button")).find((button) => button.textContent.trim() === "Origin: Any");
  click(origin);
  assert.deepEqual(Array.from(ui.root.querySelectorAll(".menu [role=menuitemradio]")).map((item) => item.textContent), ["Any", "Web terminal", "ssh"]);
  click(byText(ui.root, '[role="menuitemradio"]', "ssh"));
  await settle();
  assert.equal(window.location.hash, "#/sessions?origin=ssh");
  const last = ui.server.calls.filter((call) => call.path === "/v1/admin/sessions").at(-1);
  assert.equal(last.query.get("origin"), "ssh");
  assert.ok(Array.from(ui.root.querySelectorAll("button")).some((button) => button.textContent.trim() === "Origin: ssh"));
  ui.stop();
  ui = await open({}, PERMISSIONS, "#/sessions?origin=bogus");
  const call = ui.server.calls.find((entry) => entry.path === "/v1/admin/sessions");
  assert.equal(call.query.has("origin"), false);
});

test("Terminate is offered only on live sessions and only with the permission", async () => {
  ui = await open();
  assert.equal(terminateButtons().length, 2);
  assert.equal(terminateButtons()[0].getAttribute("aria-label"), "Terminate session 5b1c0a42");
  assert.equal(terminateButtons()[0].classList.contains("btn-danger-outline"), true);
  ui.stop();
  ui = await open({}, ALL);
  assert.equal(terminateButtons().length, 0);
});

test("the confirmation names the session and every consequence, the reason is optional and the request carries the CSRF header", async () => {
  const calls = [];
  ui = await open({ ["POST /v1/admin/sessions/" + CAROL + "/terminate"]: (request) => (calls.push(request), json(204)) });
  const before = ui.server.count("GET", "/v1/admin/sessions");
  click(terminateButtons()[1]);
  const modal = dialog();
  assert.equal(modal.getAttribute("role"), "dialog");
  assert.equal(modal.classList.contains("danger"), true);
  assert.equal(modal.querySelector("h2").textContent, "Terminate session 2c9d11f0?");
  assert.deepEqual(Array.from(modal.querySelectorAll("dt")).map((item) => item.textContent), ["User", "Node", "Login", "Origin", "Started"]);
  assert.deepEqual(Array.from(modal.querySelectorAll("dd")).map((item) => item.textContent).slice(0, 4), ["carol@example.com", "db-01", "postgres", "ssh"]);
  assert.match(modal.querySelectorAll("dd")[4].textContent, /UTC, 42 min ago$/);
  assert.deepEqual(Array.from(modal.querySelectorAll(".effects li")).map((item) => item.textContent), [
    "Ends carol’s shell on db-01 and every program running in it, within 5 seconds.",
    "carol sees: “An administrator ended this session.” Your name is not shown to them; it is in the audit log.",
    "People watching the session are disconnected.",
    "The recording is kept. carol can connect again: to stop that, revoke the user instead.",
  ]);
  const label = modal.querySelector("label");
  assert.equal(label.textContent, "Reason (optional, stored in the audit log)");
  type(modal.querySelector("#" + label.getAttribute("for")), "  Long query is locking the table.  ");
  click(byText(modal, "button", "Terminate session"));
  await settle();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, "/v1/admin/sessions/" + CAROL + "/terminate");
  assert.equal(calls[0].headers["x-jaunt-csrf"], "csrf-token-one");
  assert.deepEqual(calls[0].body, { reason: "Long query is locking the table." });
  assert.equal(dialog(), null);
  assert.equal(ui.server.count("GET", "/v1/admin/sessions"), before + 1);
  assert.equal(ui.root.querySelector('[role="status"][aria-live="polite"]').textContent, "Session 2c9d11f0 terminated.");
});

test("a terminate without a reason sends an empty object and Cancel sends nothing", async () => {
  const calls = [];
  ui = await open({ [ROUTE]: (request) => (calls.push(request), json(204)) });
  click(terminateButtons()[0]);
  click(byText(dialog(), "button", "Cancel"));
  assert.equal(dialog(), null);
  assert.equal(calls.length, 0);
  click(terminateButtons()[0]);
  click(byText(dialog(), "button", "Terminate session"));
  await settle();
  assert.deepEqual(calls[0].body, {});
});

test("every refusal is explained by its status, the dialog stays open and the button can be used again", async () => {
  const cases = [
    [json(404, { error: "not_found" }), /This session no longer exists\./],
    [json(409, { error: "already_ended" }), /This session has already ended\./],
    [json(422, { error: "invalid_reason" }), /The reason is not valid\. Use at most 200 characters on one line, without control characters, and do not write anything that looks like a secret/],
    [json(403, { error: "denied" }), /The server refused this request\./],
    [json(500, { error: "internal" }), /server/i],
    [() => {
      throw new Error("offline");
    }, /could not be reached/],
  ];
  for (const [reply, expected] of cases) {
    ui = await open({ [ROUTE]: reply });
    click(terminateButtons()[0]);
    click(byText(dialog(), "button", "Terminate session"));
    await settle();
    assert.ok(dialog(), String(expected));
    assert.match(dialog().querySelector(".inline-error").textContent, expected);
    assert.equal(byText(dialog(), "button", "Terminate session").disabled, false);
    ui.stop();
    ui = null;
    document.querySelectorAll(".scrim").forEach((node) => node.remove());
  }
});

test("hostile user, node, login and reason text are shown and sent as text only", async () => {
  const calls = [];
  const row = sessionRow({ user_email: HOSTILE.tag + "@example.com", node_name: HOSTILE.quote, login: "ok", origin: "web" });
  ui = await open({ "GET /v1/admin/sessions": page([row]), [ROUTE]: (request) => (calls.push(request), json(204)) });
  click(terminateButtons()[0]);
  const modal = dialog();
  assert.equal(modal.querySelector("img, script"), null);
  assert.ok(modal.querySelector("dd").textContent.includes(HOSTILE.tag));
  assert.equal(modal.querySelector(".effects").textContent.includes(HOSTILE.tag), true);
  const label = modal.querySelector("label");
  type(modal.querySelector("#" + label.getAttribute("for")), HOSTILE.tag);
  click(byText(modal, "button", "Terminate session"));
  await settle();
  assert.deepEqual(calls[0].body, { reason: HOSTILE.tag });
  assert.equal(window.__pwned, undefined);
  assert.equal(ui.root.querySelector("table img"), null);
});

test("the reason is one line of at most 200 characters, control characters become spaces and Cancel has the first focus", async () => {
  const calls = [];
  ui = await open({ [ROUTE]: (request) => (calls.push(request), json(204)) });
  click(terminateButtons()[0]);
  const modal = dialog();
  const input = modal.querySelector("#" + modal.querySelector("label").getAttribute("for"));
  assert.equal(input.tagName, "INPUT");
  assert.equal(input.getAttribute("type"), "text");
  assert.equal(input.getAttribute("maxlength"), "200");
  assert.equal(document.activeElement, byText(modal, "button", "Cancel"));
  type(input, "first\tsecond\u0007third end");
  click(byText(modal, "button", "Terminate session"));
  await settle();
  assert.deepEqual(calls[0].body, { reason: "first second third end" });
});

test("the terminate path escapes the session id", async () => {
  const id = "a/b%c d";
  const calls = [];
  ui = await open({ "GET /v1/admin/sessions": page([sessionRow({ id })]), "POST /v1/admin/sessions/a%2Fb%25c%20d/terminate": (request) => (calls.push(request), json(204)) });
  click(terminateButtons()[0]);
  click(byText(dialog(), "button", "Terminate session"));
  await settle();
  assert.deepEqual(calls.map((call) => call.path), ["/v1/admin/sessions/a%2Fb%25c%20d/terminate"]);
});

test("the session detail shows where the session came from", async () => {
  ui = await open({ ["GET /v1/admin/sessions/" + ID]: json(200, { ...ROWS[0], serial: "1", expires_at: NOW + 60, max_duration_secs: 60, client_addr: "203.0.113.9:1" }) }, PERMISSIONS, "#/sessions/" + ID);
  const terms = Array.from(ui.root.querySelectorAll("dt")).map((item) => item.textContent);
  assert.ok(terms.includes("Origin"));
  const value = ui.root.querySelectorAll("dt")[terms.indexOf("Origin")].nextElementSibling.textContent;
  assert.equal(value, "Web terminal");
});

test("invisible and directional characters are stripped from the reason before it is sent, and a refusal for a secret-looking text says why", async () => {
  const calls = [];
  ui = await open({ [ROUTE]: (request) => (calls.push(request), calls.length === 1 ? json(204) : json(422, { error: "invalid_reason" })) });
  click(terminateButtons()[0]);
  let modal = dialog();
  const input = modal.querySelector("#" + modal.querySelector("label").getAttribute("for"));
  type(input, "  ab\u200bc\u202ed\u2066e\u2060f\ufeffg\u061ch\u0085i\u2028j\u200fk  ");
  click(byText(modal, "button", "Terminate session"));
  await settle();
  assert.deepEqual(calls[0].body, { reason: "abcdefgh i jk" });
  ui.stop();
  ui = await open({ [ROUTE]: () => json(422, { error: "invalid_reason" }) });
  click(terminateButtons()[0]);
  modal = dialog();
  type(modal.querySelector("#" + modal.querySelector("label").getAttribute("for")), "Bearer abc");
  click(byText(modal, "button", "Terminate session"));
  await settle();
  assert.match(dialog().querySelector(".inline-error").textContent, /looks like a secret, such as a password or a token/);
});
