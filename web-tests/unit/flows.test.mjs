import assert from "node:assert/strict";
import { afterEach, mock, test } from "node:test";

import { NOW, access, lookup, node, nodeDetail, revocation, session, sessionRow } from "../fixtures.mjs";
import { byText, click, json, mount, press, setHidden, settle, signedIn, submit, type } from "./support.mjs";

let ui = null;
afterEach(() => {
  mock.timers.reset();
  setHidden(false);
  if (ui) {
    ui.stop();
    ui = null;
  }
});

const LOOKUP = "POST /v1/admin/enrolments/lookup";
const APPROVE = "POST /v1/admin/enrolments/e-1/approve";
const approved = (replaced = null) => json(200, { enrolment_id: "e-1", node: { id: "n-3", name: "web-03" }, labels: { env: "prod" }, replaced });

async function enterCode(code = "K7QM-4TRD") {
  type(ui.root.querySelector("input.code-input"), code);
  submit(ui.root.querySelector("form"));
  await settle();
}

test("every unsafe request carries the token from the session in the guard header and no secret appears in a URL or storage", async () => {
  ui = await mount({ ...signedIn(), [LOOKUP]: json(200, lookup()) }, "#/approve");
  await enterCode();
  const call = ui.server.calls.find((entry) => entry.path === "/v1/admin/enrolments/lookup");
  assert.equal(call.headers["x-jaunt-csrf"], "csrf-token-one");
  assert.deepEqual(call.body, { code: "K7QM-4TRD" });
  for (const entry of ui.server.calls) {
    assert.ok(!entry.url.includes("csrf-token-one") && !entry.url.includes("K7QM"), entry.url);
  }
  assert.ok(!window.location.href.includes("K7QM") && !window.location.href.includes("csrf"));
  assert.equal(window.localStorage.length, 0);
  assert.ok(!document.body.innerHTML.includes("csrf-token-one"));
});

test("a 403 re-reads the session once and retries once with the fresh token", async () => {
  const tokens = [];
  ui = await mount({
    "GET /v1/web/session": [{ status: 200, body: session(["nodes.approve"]) }, { status: 200, body: session(["nodes.approve"], { csrf_token: "csrf-token-two" }) }],
    [LOOKUP]: (request) => {
      tokens.push(request.headers["x-jaunt-csrf"]);
      return tokens.length === 1 ? json(403, { error: "forbidden" }) : json(200, lookup());
    },
  }, "#/approve");
  await enterCode();
  assert.deepEqual(tokens, ["csrf-token-one", "csrf-token-two"]);
  assert.equal(ui.server.count("GET", "/v1/web/session"), 2);
  assert.match(ui.text(), /Is this the server you expect/);
});

test("a second 403 is reported and the request is not retried again", async () => {
  ui = await mount({ ...signedIn(["nodes.approve"]), [LOOKUP]: json(403, { error: "forbidden" }) }, "#/approve");
  await enterCode();
  assert.equal(ui.server.count("POST", "/v1/admin/enrolments/lookup"), 2);
  assert.equal(ui.server.count("GET", "/v1/web/session"), 2);
  assert.match(ui.text(), /refused this request/);
});

test("a 401 shows the expired dialog on top of the page and keeps what was typed", async () => {
  const state = { out: true };
  ui = await mount({
    "GET /v1/web/session": () => (state.out && state.started ? json(401, { error: "unauthorized" }) : json(200, session(["nodes.approve"]))),
    [LOOKUP]: json(401, { error: "unauthorized" }),
  }, "#/approve");
  state.started = true;
  await enterCode("KEEP-ME");
  const dialog = document.querySelector('[role="dialog"]');
  assert.match(dialog.textContent, /Session expired/);
  assert.equal(dialog.querySelector("a").getAttribute("target"), "_blank");
  assert.equal(dialog.querySelector("a").getAttribute("rel"), "noopener");
  assert.equal(ui.root.querySelector("input.code-input").value, "KEEP-ME");
  click(byText(dialog, "button", "I have signed in, continue"));
  await settle();
  assert.match(dialog.textContent, /not signed in yet/);
  state.out = false;
  click(byText(dialog, "button", "I have signed in, continue"));
  await settle();
  assert.equal(document.querySelector('[role="dialog"]'), null);
  assert.equal(ui.root.querySelector("input.code-input").value, "KEEP-ME");
});

test("approval walks through code, preview with editable labels and done, sending the intent and the edited labels", async () => {
  ui = await mount({ ...signedIn(), [LOOKUP]: json(200, lookup()), [APPROVE]: approved() }, "#/approve");
  assert.equal(ui.root.querySelector(".step-list [aria-current='step']").textContent, "1Enter the code");
  await enterCode();
  assert.equal(ui.root.querySelector("input.code-input"), null);
  assert.match(ui.text(), /web-03/);
  assert.match(ui.text(), /SHA256:q3Nf0ZyKc1v8/);
  assert.match(ui.text(), /Compare the fingerprints/);
  assert.equal(ui.root.querySelector(".step-list [aria-current='step']").textContent, "2Check the details");
  const rows = ui.root.querySelectorAll(".label-rows .label-row");
  assert.equal(rows.length, 2);
  click(rows[1].querySelector("button"));
  const adders = ui.root.querySelectorAll(".label-row input[placeholder]");
  type(adders[0], "tier");
  type(adders[1], "db");
  click(byText(ui.root, "button", "Approve web-03"));
  await settle();
  const call = ui.server.calls.find((entry) => entry.path === "/v1/admin/enrolments/e-1/approve");
  assert.deepEqual(call.body, { intent: "intent-opaque-1", labels: { env: "prod", tier: "db" } });
  assert.match(ui.text(), /web-03 is approved/);
  assert.equal(ui.root.querySelector(".step-list [aria-current='step']").textContent, "3Done");
  assert.equal(byText(ui.root, "a", "Open the node").getAttribute("href"), "#/nodes/n-3");
});

test("the replace explanation shows when the name is taken by an existing node and the result names the replaced node", async () => {
  ui = await mount({ ...signedIn(), [LOOKUP]: json(200, lookup({ replace_existing: true })), [APPROVE]: approved({ id: "n-old", name: "web-03" }) }, "#/approve");
  await enterCode();
  assert.match(ui.text(), /A node named web-03 already exists/);
  assert.match(ui.text(), /replaces the existing node/);
  click(byText(ui.root, "button", "Approve web-03"));
  await settle();
  assert.match(ui.text(), /It replaced the earlier node web-03/);
});

test("duplicate or half-filled labels stop the approval before any request", async () => {
  ui = await mount({ ...signedIn(), [LOOKUP]: json(200, lookup()), [APPROVE]: approved() }, "#/approve");
  await enterCode();
  const adders = ui.root.querySelectorAll(".label-row input[placeholder]");
  type(adders[0], "env");
  type(adders[1], "stage");
  click(byText(ui.root, "button", "Approve web-03"));
  assert.match(ui.text(), /Each label key can be used once/);
  type(adders[1], "");
  click(byText(ui.root, "button", "Approve web-03"));
  assert.match(ui.text(), /Fill in both the key and the value/);
  assert.equal(ui.server.count("POST", "/v1/admin/enrolments/e-1/approve"), 0);
});

test("lookup failures each have their own message and keep the form usable", async () => {
  const cases = [
    [json(422, { error: "no_pending_enrolment" }), /not found or has expired/],
    [json(409, { error: "enrolment_rejected" }), /rejected earlier/],
    [json(409, { error: "already_approved" }), /already approved/],
    [json(500, { error: "internal" }), /failed to complete/],
  ];
  for (const [reply, pattern] of cases) {
    ui = await mount({ ...signedIn(), [LOOKUP]: reply }, "#/approve");
    await enterCode("WRONG");
    assert.match(ui.text(), pattern);
    assert.equal(ui.root.querySelector("input.code-input").disabled, false);
    assert.equal(byText(ui.root, "button", "Continue").disabled, false);
    ui.stop();
    ui = null;
  }
  ui = await mount({ ...signedIn(), [LOOKUP]: json(200, lookup()) }, "#/approve");
  submit(ui.root.querySelector("form"));
  assert.match(ui.text(), /Type the code first/);
  assert.equal(ui.server.count("POST", "/v1/admin/enrolments/lookup"), 0);
});

test("a rate limit disables the form and counts down the Retry-After seconds", async () => {
  ui = await mount({ ...signedIn(), [LOOKUP]: json(429, { error: "too_many_requests", retry_after: 3 }, { "Retry-After": "3" }) }, "#/approve");
  mock.timers.enable({ apis: ["setTimeout", "Date"], now: NOW * 1000 });
  await enterCode();
  const submitButton = byText(ui.root, "button", "Continue");
  assert.match(ui.text(), /Try again in 3 s/);
  assert.equal(submitButton.disabled, true);
  mock.timers.tick(1000);
  assert.match(ui.text(), /Try again in 2 s/);
  mock.timers.tick(2000);
  assert.match(ui.text(), /You can try again now/);
  assert.equal(submitButton.disabled, false);
});

test("a refused approval spends the intent, so the admin is sent back to the code step with the reason at once", async () => {
  const cases = [
    [json(409, { error: "name_taken" }), /name already exists and cannot be replaced/],
    [json(409, { error: "enrolment_not_pending" }), /no longer pending/],
    [json(409, { error: "already_approved" }), /already approved/],
    [json(409, { error: "enrolment_rejected" }), /rejected earlier/],
    [json(500, { error: "internal" }), /failed to complete/],
  ];
  for (const [reply, pattern] of cases) {
    ui = await mount({ ...signedIn(), [LOOKUP]: json(200, lookup()), [APPROVE]: reply }, "#/approve");
    await enterCode();
    click(byText(ui.root, "button", "Approve web-03"));
    await settle();
    assert.match(ui.text(), pattern);
    assert.ok(ui.root.querySelector("input.code-input"));
    assert.equal(byText(ui.root, "button", "Approve web-03"), undefined);
    ui.stop();
    ui = null;
  }
});

test("invalid labels keep the form open and an expired intent sends the admin back to the code step", async () => {
  ui = await mount({ ...signedIn(), [LOOKUP]: json(200, lookup()), [APPROVE]: json(422, { error: "invalid_labels" }) }, "#/approve");
  await enterCode();
  click(byText(ui.root, "button", "Approve web-03"));
  await settle();
  assert.match(ui.text(), /did not accept these labels/);
  assert.equal(byText(ui.root, "button", "Approve web-03").disabled, false);
  ui.stop();
  ui = await mount({ ...signedIn(), [LOOKUP]: json(200, lookup()), [APPROVE]: json(422, { error: "invalid_intent" }) }, "#/approve");
  await enterCode();
  click(byText(ui.root, "button", "Approve web-03"));
  await settle();
  assert.match(ui.text(), /approval step expired/);
  click(byText(ui.root, "button", "Start again"));
  assert.ok(ui.root.querySelector("input.code-input"));
});

test("approving or rejecting refreshes the pending count in the navigation", async () => {
  ui = await mount({
    ...signedIn(),
    [LOOKUP]: json(200, lookup()),
    [APPROVE]: approved(),
    "GET /v1/admin/nodes": json(200, { nodes: [], next: null, pending_enrolments: 3 }),
  }, "#/approve");
  assert.equal(ui.root.querySelector(".bell-count"), null);
  await enterCode();
  click(byText(ui.root, "button", "Approve web-03"));
  await settle();
  assert.equal(ui.root.querySelector(".bell-count").textContent, "3");
  assert.equal(ui.root.querySelector(".bell").getAttribute("aria-label"), "3 pending enrolments");
  assert.equal(ui.server.calls.find((entry) => entry.path === "/v1/admin/nodes").query.get("limit"), "1");
});

test("the intent lifetime is enforced by the clock without a request", async () => {
  ui = await mount({ ...signedIn(), [LOOKUP]: json(200, lookup()) }, "#/approve");
  mock.timers.enable({ apis: ["setTimeout", "Date"], now: NOW * 1000 });
  await enterCode();
  mock.timers.tick(299_000);
  assert.match(ui.text(), /Is this the server you expect/);
  mock.timers.tick(2_000);
  assert.match(ui.text(), /approval step expired/);
});

test("rejecting names the effect, needs a confirmation and sends the intent", async () => {
  ui = await mount({ ...signedIn(), [LOOKUP]: json(200, lookup()), "POST /v1/admin/enrolments/e-1/reject": json(200, { enrolment_id: "e-1", name: "web-03" }) }, "#/approve");
  await enterCode();
  click(byText(ui.root, "button", "Reject request…"));
  const dialog = document.querySelector('[role="dialog"]');
  assert.match(dialog.textContent, /Reject the request from web-03\?/);
  assert.match(dialog.textContent, /code stops working/);
  click(byText(dialog, "button", "Reject request"));
  await settle();
  const call = ui.server.calls.find((entry) => entry.path === "/v1/admin/enrolments/e-1/reject");
  assert.deepEqual(call.body, { intent: "intent-opaque-1" });
  assert.match(ui.text(), /The request from web-03 was rejected/);
});

test("removing a node needs the exact typed name and sends it for the server to check again", async () => {
  const remove = (request) => json(200, { id: "n-web-01", name: request.body.confirm_name, state: "removed", removed_at: NOW, sessions_closed: 2 });
  ui = await mount({
    ...signedIn(),
    "GET /v1/admin/nodes/n-web-01": json(200, nodeDetail()),
    "GET /v1/admin/nodes/n-web-01/access": json(200, access()),
    "DELETE /v1/admin/nodes/n-web-01": remove,
    "GET /v1/admin/nodes": json(200, { nodes: [], next: null, pending_enrolments: 0 }),
  }, "#/nodes/n-web-01");
  click(byText(ui.root, "button", "Remove…"));
  const dialog = document.querySelector('[role="dialog"]');
  const confirm = byText(dialog, "button", "Remove web-01");
  const input = dialog.querySelector("input");
  assert.match(dialog.textContent, /Ends 2 open sessions/);
  assert.equal(confirm.disabled, true);
  for (const wrong of ["", "web-0", "WEB-01", "web-01 ", " web-01", "web‑01", "web-011"]) {
    type(input, wrong);
    assert.equal(confirm.disabled, true, JSON.stringify(wrong));
  }
  type(input, "web-01");
  assert.equal(confirm.disabled, false);
  click(confirm);
  await settle();
  const call = ui.server.calls.find((entry) => entry.method === "DELETE");
  assert.deepEqual(call.body, { confirm_name: "web-01" });
  assert.equal(call.headers["x-jaunt-csrf"], "csrf-token-one");
  assert.equal(document.querySelector('[role="dialog"]'), null);
  assert.equal(window.location.hash, "#/nodes");
  assert.match(ui.text(), /Node web-01 was removed\. 2 open sessions were closed\./);
});

test("a server refusal of the typed name or a node that is already gone stays inside the dialog", async () => {
  const reply = { current: json(422, { error: "confirm_name_mismatch" }) };
  ui = await mount({
    ...signedIn(),
    "GET /v1/admin/nodes/n-web-01": json(200, nodeDetail()),
    "GET /v1/admin/nodes/n-web-01/access": json(200, access()),
    "DELETE /v1/admin/nodes/n-web-01": () => reply.current,
  }, "#/nodes/n-web-01");
  click(byText(ui.root, "button", "Remove…"));
  const dialog = document.querySelector('[role="dialog"]');
  type(dialog.querySelector("input"), "web-01");
  click(byText(dialog, "button", "Remove web-01"));
  await settle();
  assert.match(dialog.textContent, /does not match this node/);
  reply.current = json(409, { error: "node_not_active" });
  click(byText(dialog, "button", "Remove web-01"));
  await settle();
  assert.match(dialog.textContent, /already removed/);
  assert.ok(document.querySelector('[role="dialog"]'));
});

test("creating a revocation validates, names the effect, requires acknowledgement and then posts", async () => {
  ui = await mount({
    ...signedIn(),
    "GET /v1/admin/revocations": json(200, { revocations: [], next: null }),
    "POST /v1/admin/revocations": json(201, { revocation: revocation(), created: true, terminated_sessions: 2 }),
  }, "#/revocations");
  click(byText(ui.root, "button", "New revocation"));
  const dialog = document.querySelector('[role="dialog"]');
  click(byText(dialog, "button", "Review effect…"));
  assert.match(dialog.textContent, /Enter who or what to revoke/);
  type(dialog.querySelector("#revoke-subject"), "u-bob");
  click(byText(dialog, "button", "Review effect…"));
  assert.match(dialog.textContent, /Enter a reason/);
  type(dialog.querySelector("#revoke-reason"), "Credentials exposed");
  click(byText(dialog, "button", "Review effect…"));
  assert.match(dialog.textContent, /u-bob/);
  assert.match(dialog.textContent, /Ends every open session of this user/);
  assert.match(dialog.textContent, /Credentials exposed/);
  const confirm = byText(dialog, "button", "Revoke now");
  assert.equal(confirm.disabled, true);
  const box = dialog.querySelector("input[type=checkbox]");
  box.checked = true;
  box.dispatchEvent(new window.Event("change", { bubbles: true }));
  assert.equal(confirm.disabled, false);
  click(confirm);
  await settle();
  const call = ui.server.calls.find((entry) => entry.method === "POST" && entry.path === "/v1/admin/revocations");
  assert.deepEqual(call.body, { kind: "user", subject: "u-bob", reason: "Credentials exposed" });
  assert.match(ui.text(), /Revoked\. 2 open sessions were ended\./);
});

test("revocation errors for an unknown subject stay in the dialog", async () => {
  ui = await mount({
    ...signedIn(),
    "GET /v1/admin/revocations": json(200, { revocations: [], next: null }),
    "POST /v1/admin/revocations": json(404, { error: "unknown_subject" }),
  }, "#/revocations");
  click(byText(ui.root, "button", "New revocation"));
  const dialog = document.querySelector('[role="dialog"]');
  type(dialog.querySelector("#revoke-subject"), "u-nobody");
  type(dialog.querySelector("#revoke-reason"), "test");
  click(byText(dialog, "button", "Review effect…"));
  dialog.querySelector("input[type=checkbox]").checked = true;
  dialog.querySelector("input[type=checkbox]").dispatchEvent(new window.Event("change", { bubbles: true }));
  click(byText(dialog, "button", "Revoke now"));
  await settle();
  assert.match(dialog.textContent, /No such user, certificate or node exists/);
});

test("lifting a user revocation says it also deletes web sessions and API tokens before it deletes anything", async () => {
  ui = await mount({
    ...signedIn(),
    "GET /v1/admin/revocations": json(200, { revocations: [revocation()], next: null }),
    "DELETE /v1/admin/revocations/r-1": json(204, undefined),
  }, "#/revocations");
  click(byText(ui.root, "button", "Lift…"));
  const dialog = document.querySelector('[role="dialog"]');
  assert.match(dialog.textContent, /also deletes the user's web sessions and API tokens/);
  assert.equal(ui.server.count("DELETE", "/v1/admin/revocations/r-1"), 0);
  click(byText(dialog, "button", "Lift revocation"));
  await settle();
  assert.equal(ui.server.count("DELETE", "/v1/admin/revocations/r-1"), 1);
  assert.match(ui.text(), /The revocation was lifted/);
});

test("dialogs trap focus, close with Escape, return focus to the opener and make the page inert", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes/n-web-01": json(200, nodeDetail()), "GET /v1/admin/nodes/n-web-01/access": json(200, access()) }, "#/nodes/n-web-01");
  const opener = byText(ui.root, "button", "Remove…");
  opener.focus();
  click(opener);
  const dialog = document.querySelector('[role="dialog"]');
  assert.equal(dialog.getAttribute("aria-modal"), "true");
  assert.equal(ui.root.hasAttribute("inert"), true);
  const close = byText(dialog, "button", "Close");
  const cancel = byText(dialog, "button", "Cancel");
  assert.equal(document.activeElement, dialog.querySelector("input"));
  cancel.focus();
  const forward = press(cancel, "Tab");
  assert.equal(forward.defaultPrevented, true);
  assert.equal(document.activeElement, close);
  const backward = press(close, "Tab", { shiftKey: true });
  assert.equal(backward.defaultPrevented, true);
  assert.equal(document.activeElement, cancel);
  press(dialog, "Escape");
  assert.equal(document.querySelector('[role="dialog"]'), null);
  assert.equal(ui.root.hasAttribute("inert"), false);
  assert.equal(document.activeElement, opener);
});

test("live refresh runs on a timer of 15 seconds, never faster than 10, and makes no request while the tab is hidden", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/sessions": json(200, { sessions: [sessionRow()], next: null }) }, "#/sessions");
  mock.timers.enable({ apis: ["setTimeout"] });
  const reads = () => ui.server.count("GET", "/v1/admin/sessions");
  assert.equal(reads(), 1);
  const box = ui.root.querySelector("#sessions-auto");
  box.checked = true;
  box.dispatchEvent(new window.Event("change", { bubbles: true }));
  mock.timers.tick(14_999);
  await settle();
  assert.equal(reads(), 1);
  mock.timers.tick(1);
  await settle();
  assert.equal(reads(), 2);
  setHidden(true);
  mock.timers.tick(15_000);
  await settle();
  mock.timers.tick(15_000);
  await settle();
  assert.equal(reads(), 2);
  setHidden(false);
  mock.timers.tick(15_000);
  await settle();
  assert.equal(reads(), 3);
  click(byText(ui.root, "button", "Refresh"));
  await settle();
  assert.equal(reads(), 4);
});

test("leaving the sessions screen stops its refresh timer", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/sessions": json(200, { sessions: [], next: null }), "GET /v1/admin/audit": json(200, { events: [], next_cursor: null }) }, "#/sessions");
  mock.timers.enable({ apis: ["setTimeout"] });
  const box = ui.root.querySelector("#sessions-auto");
  box.checked = true;
  box.dispatchEvent(new window.Event("change", { bubbles: true }));
  window.location.hash = "#/audit";
  await settle();
  mock.timers.tick(60_000);
  await settle();
  assert.equal(ui.server.count("GET", "/v1/admin/sessions"), 1);
});

test("a node whose certificate is still pending renders a minimal row", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": json(200, { nodes: [node({ certificates: { state: "pending" }, connected_since: null, connected: false })], next: null, pending_enrolments: 0 }) }, "#/nodes");
  click(ui.root.querySelector('button[aria-label="List view"]'));
  assert.match(ui.text(), /Certificate pending/);
});

test("a failed refresh leaves Load more and Refresh usable again", async () => {
  const state = { fail: false };
  ui = await mount({
    ...signedIn(),
    "GET /v1/admin/sessions": () => (state.fail ? json(500, { error: "internal" }) : json(200, { sessions: [sessionRow()], next: "cursor-1" })),
  }, "#/sessions");
  state.fail = true;
  click(byText(ui.root, "button", "Refresh"));
  await settle();
  assert.match(ui.text(), /could not be completed/);
  assert.equal(byText(ui.root, "button", "Load more").disabled, false);
  click(byText(ui.root, "button", "Load more"));
  await settle();
  assert.match(ui.text(), /failed to complete/);
  assert.equal(byText(ui.root, "button", "Load more").disabled, false);
  state.fail = false;
  click(byText(ui.root, "button", "Refresh"));
  await settle();
  assert.equal(ui.root.querySelectorAll("tbody tr").length, 1);
  assert.doesNotMatch(ui.text(), /could not be completed/);
});

test("an open dialog is closed when the route changes, so it cannot act on a stale screen", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes/n-web-01": json(200, nodeDetail()), "GET /v1/admin/nodes/n-web-01/access": json(200, access()), "GET /v1/admin/audit": json(200, { events: [], next_cursor: null }) }, "#/nodes/n-web-01");
  click(byText(ui.root, "button", "Remove\u2026"));
  assert.ok(document.querySelector('[role="dialog"]'));
  window.history.replaceState(null, "", "#/audit");
  window.dispatchEvent(new window.Event("hashchange"));
  await settle();
  assert.equal(document.querySelector('[role="dialog"]'), null);
  assert.equal(ui.root.hasAttribute("inert"), false);
});

test("revoking from the node screen without sessions.read stays on the screen with a success note", async () => {
  ui = await mount({
    ...signedIn(["nodes.approve", "revocations.write"]),
    "GET /v1/admin/nodes/n-web-01": json(200, nodeDetail()),
    "POST /v1/admin/revocations": json(201, { revocation: revocation({ kind: "node", subject: "n-web-01" }), created: true, terminated_sessions: 2 }),
  }, "#/nodes/n-web-01");
  click(byText(ui.root, "button", "Revoke\u2026"));
  const dialog = document.querySelector('[role="dialog"]');
  type(dialog.querySelector("#revoke-reason"), "decommissioned");
  click(byText(dialog, "button", "Review effect\u2026"));
  assert.match(dialog.textContent, /Removes the node and ends its sessions/);
  assert.doesNotMatch(dialog.textContent, /refuses it until the revocation is lifted/);
  const box = dialog.querySelector("input[type=checkbox]");
  box.checked = true;
  box.dispatchEvent(new window.Event("change", { bubbles: true }));
  click(byText(dialog, "button", "Revoke now"));
  await settle();
  assert.equal(window.location.hash, "#/nodes/n-web-01");
  assert.match(ui.text(), /Revoked\. 2 open sessions were ended\./);
  assert.doesNotMatch(ui.text(), /HTTP 403/);
  assert.equal(ui.server.count("GET", "/v1/admin/nodes/n-web-01"), 2);
});

test("lifting a node revocation says the node stays removed and must enroll again", async () => {
  ui = await mount({
    ...signedIn(),
    "GET /v1/admin/revocations": json(200, { revocations: [revocation({ kind: "node", subject: "n-web-01" })], next: null }),
  }, "#/revocations");
  click(byText(ui.root, "button", "Lift\u2026"));
  const dialog = document.querySelector('[role="dialog"]');
  assert.match(dialog.textContent, /node stays removed/);
  assert.match(dialog.textContent, /enroll it again/);
});

test("a GET refused with 403 is not retried and does not re-read the session", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/audit": json(403, { error: "forbidden" }) }, "#/audit");
  assert.equal(ui.server.count("GET", "/v1/admin/audit"), 1);
  assert.equal(ui.server.count("GET", "/v1/web/session"), 1);
});
