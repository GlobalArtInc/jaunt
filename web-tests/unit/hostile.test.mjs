import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { HOSTILE, access, auditEvent, lookup, node, nodeDetail, revocation, sessionDetail, sessionRow } from "../fixtures.mjs";
import { byText, click, json, mount, settle, signedIn, submit, type } from "./support.mjs";
import { session as sessionFixture } from "../fixtures.mjs";

let ui = null;
afterEach(() => {
  if (ui) {
    ui.stop();
    ui = null;
  }
  delete globalThis.window?.__pwned;
});

const hostileLabels = { [HOSTILE.tag]: HOSTILE.quote, rtl: HOSTILE.rtl, [HOSTILE.control]: HOSTILE.link };

function assertInert(scope) {
  assert.equal(scope.querySelectorAll("img, script, iframe, object, embed, style, link, form[action]").length, 0, "no element may come from data");
  for (const drawing of scope.querySelectorAll("svg")) {
    assert.equal(drawing.getAttribute("class").startsWith("icon"), true, "only the static icons are drawings");
    for (const part of drawing.querySelectorAll("*")) {
      assert.match(part.localName, /^(path|circle|rect|ellipse)$/, "icons hold plain shapes only");
      for (const attribute of part.getAttributeNames()) {
        assert.doesNotMatch(attribute, /href|^on|style/i, attribute);
      }
    }
    for (const attribute of drawing.getAttributeNames()) {
      assert.doesNotMatch(attribute, /href/i);
    }
  }
  for (const element of scope.querySelectorAll("*")) {
    for (const attribute of element.attributes) {
      assert.doesNotMatch(attribute.name, /^on/i, attribute.name);
      assert.notEqual(attribute.name, "style");
    }
  }
  for (const link of scope.querySelectorAll("a[href]")) {
    assert.match(link.getAttribute("href"), /^(#\/[A-Za-z0-9\/_\-.~%:=&?+]*|\/v1\/web\/login\?return_to=[A-Za-z0-9%._~-]*)$/, link.getAttribute("href").slice(0, 80));
  }
  assert.equal(window.__pwned, undefined);
  const text = scope.textContent;
  assert.doesNotMatch(text, /[‪-‮⁦-⁩​-‏]/, "bidi and invisible controls are neutralised");
  assert.doesNotMatch(text, /[\u0000-\u0008\u000b-\u001f\u007f]/, "control characters are neutralised");
  const walker = document.createTreeWalker(scope, window.NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    assert.ok(walker.currentNode.data.length <= 2100, "very long values are cut");
  }
}

function assertShowsAsText(scope, ...values) {
  for (const value of values) {
    assert.ok(scope.textContent.includes(value), value.slice(0, 40));
  }
}

test("hostile node data on the list and the detail is shown as text and nothing else", async () => {
  const bad = { name: HOSTILE.tag, hostname: HOSTILE.quote, labels: hostileLabels, agent_version: HOSTILE.control, approved_by: HOSTILE.rtl, id: HOSTILE.link };
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": json(200, { nodes: [node(bad), node({ ...bad, name: HOSTILE.long, id: HOSTILE.quote })], next: null, pending_enrolments: 0 }) }, "#/nodes");
  assertInert(ui.root);
  assertShowsAsText(ui.root, HOSTILE.tag, HOSTILE.quote);
  ui.stop();
  ui = await mount(
    {
      ...signedIn(),
      "GET /v1/admin/nodes/hostile": json(200, nodeDetail({ ...bad, tls_spki_sha256: HOSTILE.tag, ssh_host_key_fingerprint: HOSTILE.quote })),
      "GET /v1/admin/nodes/hostile/access": json(200, { ...access(), policy_hash: HOSTILE.tag, roles: [{ role: HOSTILE.tag, users: [HOSTILE.quote], groups: [HOSTILE.rtl], logins: [HOSTILE.control], port_forwarding: true, record_input: true, admin: [HOSTILE.link] }] }),
    },
    "#/nodes/hostile",
  );
  assertInert(ui.root);
  assertShowsAsText(ui.root, HOSTILE.tag, HOSTILE.quote);
});

test("hostile session data on the list and the detail is shown as text and nothing else", async () => {
  const bad = { user_email: HOSTILE.tag, node_name: HOSTILE.quote, login: HOSTILE.rtl, end_reason: HOSTILE.control, state: "ended", ended_at: 1, client_addr: HOSTILE.tag, serial: HOSTILE.quote };
  ui = await mount(
    { ...signedIn(), "GET /v1/admin/sessions": json(200, { sessions: [sessionRow(bad), sessionRow({ ...bad, user_email: HOSTILE.long })], next: null }), "GET /v1/admin/sessions/hostile": json(200, sessionDetail(bad)) },
    "#/sessions",
  );
  assertInert(ui.root);
  assertShowsAsText(ui.root, HOSTILE.tag, HOSTILE.quote);
  window.history.replaceState(null, "", "#/sessions/hostile");
  window.dispatchEvent(new window.Event("hashchange"));
  await settle();
  assertInert(ui.root);
  assertShowsAsText(ui.root, HOSTILE.tag);
});

test("hostile revocation and audit data is shown as text and nothing else, including the drawer", async () => {
  ui = await mount(
    {
      ...signedIn(),
      "GET /v1/admin/revocations": json(200, { revocations: [revocation({ subject: HOSTILE.tag, reason: HOSTILE.quote, created_by: HOSTILE.rtl, kind: HOSTILE.control })], next: null }),
    },
    "#/revocations",
  );
  assertInert(ui.root);
  assertShowsAsText(ui.root, HOSTILE.tag, HOSTILE.quote);
  ui.stop();
  const event = auditEvent({ type: HOSTILE.tag, actor: HOSTILE.quote, node: HOSTILE.rtl, session_id: HOSTILE.control, fields: { [HOSTILE.tag]: HOSTILE.quote, other: HOSTILE.long, nested: { a: 1 } } });
  ui = await mount({ ...signedIn(), "GET /v1/admin/audit": json(200, { events: [event], next_cursor: null }) }, "#/audit");
  assertInert(ui.root);
  click(byText(ui.root, "button", "Details"));
  assertInert(document.body);
  assertShowsAsText(document.querySelector('[role="dialog"]'), HOSTILE.tag, HOSTILE.quote);
});

test("a hostile enrolment preview and the typed-name dialog show data as text", async () => {
  const bad = { name: HOSTILE.tag, hostname: HOSTILE.quote, labels: hostileLabels, agent_version: HOSTILE.rtl, peer_addr: HOSTILE.control, source_network: HOSTILE.link, tls_key_sha256: HOSTILE.tag, ssh_host_key_fingerprint: HOSTILE.quote };
  ui = await mount({ ...signedIn(), "POST /v1/admin/enrolments/lookup": json(200, lookup(bad)) }, "#/approve");
  type(ui.root.querySelector("input.code-input"), "K7QM-4TRD");
  submit(ui.root.querySelector("form"));
  await settle();
  assertInert(ui.root);
  assertShowsAsText(ui.root, HOSTILE.tag, HOSTILE.quote);
  const inputs = ui.root.querySelectorAll(".label-row input");
  assert.equal(inputs[0].value, HOSTILE.tag);
  ui.stop();
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes/n1": json(200, nodeDetail({ id: "n1", name: HOSTILE.tag })), "GET /v1/admin/nodes/n1/access": json(200, access()) }, "#/nodes/n1");
  click(byText(ui.root, "button", "Remove…"));
  assertInert(document.body);
  assertShowsAsText(document.querySelector('[role="dialog"]'), HOSTILE.tag);
});

test("the markup helper refuses event handler attributes, style attributes and unsafe links", async () => {
  const { installDom } = await import("./support.mjs");
  installDom();
  const { el, safeHref } = await import("../../crates/jaunt-web/assets/assets/js/dom.js");
  for (const name of ["onclick", "onerror", "style", "srcdoc", "formaction"]) {
    assert.throws(() => el("div", { [name]: "x" }), /refused/);
  }
  for (const href of [HOSTILE.link, "https://evil.example/", "//evil.example", "/v1/web/logout", "#nodes", "#/a b", "data:text/html,x"]) {
    assert.throws(() => safeHref(href), /unsafe/, href);
  }
  assert.equal(safeHref("#/nodes/a%20b"), "#/nodes/a%20b");
});

test("a hostile display name and hostile groups are shown as text in the header and on the not allowed page", async () => {
  ui = await mount({ ...signedIn(["audit.read"], { display_name: HOSTILE.tag }), "GET /v1/admin/audit": json(200, { events: [], next_cursor: null }) }, "#/audit");
  assertInert(ui.root);
  assertShowsAsText(ui.root.querySelector(".account-btn"), HOSTILE.tag);
  ui.stop();
  ui = await mount({ "GET /v1/web/session": json(200, sessionFixture([], { groups: [HOSTILE.tag, HOSTILE.quote, HOSTILE.rtl], display_name: HOSTILE.quote })) });
  assertInert(ui.root);
  assertShowsAsText(ui.root, HOSTILE.tag, HOSTILE.quote);
});

test("hostile labels in the Labels menu and a hostile display name in the account menu are text and nothing else", async () => {
  const bad = node({ name: HOSTILE.tag, labels: hostileLabels });
  ui = await mount({ ...signedIn(["nodes.approve"], { display_name: HOSTILE.tag + HOSTILE.rtl }), "GET /v1/admin/nodes": json(200, { nodes: [bad], next: "more", pending_enrolments: 0 }) }, "#/nodes");
  const labelsButton = Array.from(ui.root.querySelectorAll("button")).find((button) => button.textContent.trim() === "Labels");
  click(labelsButton);
  const menu = ui.root.querySelector(".menu");
  assert.ok(menu.querySelectorAll('[role="menuitemcheckbox"]').length >= 3);
  assertInert(ui.root);
  assertShowsAsText(menu, HOSTILE.tag);
  assert.match(menu.textContent, /loaded so far/);
  click(labelsButton);
  click(ui.root.querySelector(".account-btn"));
  const account = ui.root.querySelector(".menu");
  assertInert(ui.root);
  assert.ok(account.querySelector(".menu-heading").textContent.includes(HOSTILE.tag));
  assert.doesNotMatch(account.textContent, /[‪-‮⁦-⁩​-‏]/);
});

test("the removal note and the approval results show hostile names as text", async () => {
  ui = await mount({
    ...signedIn(),
    "GET /v1/admin/nodes/n1": json(200, nodeDetail({ id: "n1", name: HOSTILE.tag })),
    "GET /v1/admin/nodes/n1/access": json(200, access()),
    "DELETE /v1/admin/nodes/n1": json(200, { id: "n1", name: HOSTILE.tag, state: "removed", removed_at: 1, sessions_closed: 1 }),
    "GET /v1/admin/nodes": json(200, { nodes: [], next: null, pending_enrolments: 0 }),
  }, "#/nodes/n1");
  click(byText(ui.root, "button", "Remove\u2026"));
  const dialog = document.querySelector('[role="dialog"]');
  type(dialog.querySelector("input"), HOSTILE.tag);
  click(dialog.querySelector("footer button:last-child"));
  await settle();
  assertInert(ui.root);
  assertShowsAsText(ui.root.querySelector(".banner"), HOSTILE.tag);
  ui.stop();
  const bad = lookup({ name: HOSTILE.tag });
  ui = await mount({
    ...signedIn(),
    "POST /v1/admin/enrolments/lookup": json(200, bad),
    "POST /v1/admin/enrolments/e-1/approve": json(200, { enrolment_id: "e-1", node: { id: HOSTILE.link, name: HOSTILE.quote }, labels: {}, replaced: { id: "o", name: HOSTILE.tag } }),
  }, "#/approve");
  type(ui.root.querySelector("input.code-input"), "K7QM-4TRD");
  submit(ui.root.querySelector("form"));
  await settle();
  click(ui.root.querySelector(".card .actions .btn-primary"));
  await settle();
  assertInert(ui.root);
  assertShowsAsText(ui.root, HOSTILE.quote, HOSTILE.tag);
  ui.stop();
  ui = await mount({
    ...signedIn(),
    "POST /v1/admin/enrolments/lookup": json(200, bad),
    "POST /v1/admin/enrolments/e-1/reject": json(200, { enrolment_id: "e-1", name: HOSTILE.tag }),
  }, "#/approve");
  type(ui.root.querySelector("input.code-input"), "K7QM-4TRD");
  submit(ui.root.querySelector("form"));
  await settle();
  click(byText(ui.root, "button", "Reject request\u2026"));
  click(byText(document.querySelector('[role="dialog"]'), "button", "Reject request"));
  await settle();
  assertInert(ui.root);
  assertShowsAsText(ui.root.querySelector("h1"), HOSTILE.tag);
});
