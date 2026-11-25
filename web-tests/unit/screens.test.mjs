import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { NOW, access, auditEvent, node, nodeDetail, revocation, sessionDetail, sessionRow } from "../fixtures.mjs";
import { byText, click, json, mount, press, settle, signedIn } from "./support.mjs";

let ui = null;
afterEach(() => {
  if (ui) {
    ui.stop();
    ui = null;
  }
});

const nodesPage = (nodes, extra = {}) => json(200, { nodes, next: null, pending_enrolments: 0, ...extra });

test("the nodes screen renders rows, label chips, state markers, the pending banner and the nav count", async () => {
  ui = await mount(
    {
      ...signedIn(),
      "GET /v1/admin/nodes": nodesPage([node(), node({ id: "n2", name: "db-01", connected: false, revoked: true, labels: {} })], { pending_enrolments: 2 }),
    },
    "#/nodes",
  );
  const rows = ui.root.querySelectorAll("tbody tr");
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /web-01/);
  assert.deepEqual(Array.from(rows[0].querySelectorAll(".chip")).map((chip) => chip.textContent), ["env=prod", "team=web"]);
  assert.match(rows[0].textContent, /Online/);
  assert.match(rows[1].textContent, /Offline/);
  assert.match(rows[1].textContent, /Revoked/);
  assert.match(ui.root.querySelector(".banner").textContent, /2 enrolment requests are waiting/);
  assert.match(ui.root.querySelector(".mainnav").textContent, /2 pending/);
  assert.equal(document.title, "Nodes · Jaunt");
  assert.equal(ui.root.querySelector("a.btn-primary").getAttribute("href"), "#/approve");
});

test("the nodes screen sends its filters, appends the next page and shows the empty state", async () => {
  const pages = [];
  ui = await mount(
    {
      ...signedIn(),
      "GET /v1/admin/nodes": (request) => {
        pages.push(request.query.toString());
        return request.query.get("cursor") ? nodesPage([node({ id: "n2", name: "web-02" })]) : nodesPage([node()], { next: "cursor-1" });
      },
    },
    "#/nodes?q=web&label=env%3Aprod&label=team%3Aweb&state=removed",
  );
  assert.equal(pages[0], "state=removed&q=web&label=env%3Aprod&label=team%3Aweb&limit=50");
  click(byText(ui.root, "button", "Load more"));
  await settle();
  assert.equal(pages[1], "state=removed&q=web&label=env%3Aprod&label=team%3Aweb&limit=50&cursor=cursor-1");
  assert.equal(ui.root.querySelectorAll("tbody tr").length, 2);
  assert.equal(byText(ui.root, "button", "Load more").hidden, true);
});

test("an empty registry explains how to enrol a node and a filtered miss says so", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([]) }, "#/nodes");
  assert.match(ui.text(), /No nodes yet/);
  assert.match(ui.text(), /jaunt-agent enroll/);
  ui.stop();
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([]) }, "#/nodes?q=zzz");
  assert.match(ui.text(), /No nodes match these filters/);
});

test("an invalid filter code from the server becomes a message next to the filters", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": json(422, { error: "invalid_label" }) }, "#/nodes?label=bad");
  assert.match(ui.root.querySelector(".filters").textContent, /A label must look like key:value/);
});

test("the node detail shows facts, keys, session counts and who can reach the node", async () => {
  ui = await mount(
    {
      ...signedIn(),
      "GET /v1/admin/nodes/n-web-01": json(200, nodeDetail()),
      "GET /v1/admin/nodes/n-web-01/access": json(200, access()),
    },
    "#/nodes/n-web-01",
  );
  const text = ui.text();
  assert.match(text, /SHA256:q3Nf0ZyKc1v8/);
  assert.match(text, /SHA256:Vd8kP2rL0tQx/);
  assert.match(text, /2 open now/);
  assert.match(text, /7 in the last 24 hours/);
  assert.match(text, /prod-ops/);
  assert.match(text, /Policy 3f9c2e1a/);
  assert.ok(byText(ui.root, "button", "Remove…"));
  assert.ok(byText(ui.root, "button", "Revoke…"));
  assert.equal(document.title, "web-01 · Jaunt");
});

test("a missing node shows the not found page and a removed node offers no removal", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes/gone": json(404, { error: "not_found" }) }, "#/nodes/gone");
  assert.match(ui.text(), /HTTP 404/);
  ui.stop();
  ui = await mount(
    {
      ...signedIn(["nodes.approve"]),
      "GET /v1/admin/nodes/n-web-01": json(200, nodeDetail({ state: "removed", connected: false, removed_at: NOW - 60 })),
    },
    "#/nodes/n-web-01",
  );
  assert.equal(byText(ui.root, "button", "Remove…"), undefined);
  assert.match(ui.text(), /Removed/);
  assert.doesNotMatch(ui.text(), /Who can reach this node/);
});

test("the sessions screen marks live sessions and links to the detail with the recording note", async () => {
  ui = await mount(
    {
      ...signedIn(),
      "GET /v1/admin/sessions": json(200, { sessions: [sessionRow(), sessionRow({ id: "aaaa1111-0000-0000-0000-000000000000", state: "ended", ended_at: NOW - 10, end_reason: "closed", exit_status: 0 })], next: null }),
      "GET /v1/admin/sessions/5b1c0a42-aaaa-bbbb-cccc-111122223333": json(200, sessionDetail()),
    },
    "#/sessions",
  );
  const rows = ui.root.querySelectorAll("tbody tr");
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /Live/);
  assert.match(rows[1].textContent, /closed · exit 0/);
  assert.equal(rows[0].querySelector("a").getAttribute("href"), "#/sessions/5b1c0a42-aaaa-bbbb-cccc-111122223333");
  window.location.hash = "#/sessions/5b1c0a42-aaaa-bbbb-cccc-111122223333";
  await settle();
  assert.match(ui.text(), /203\.0\.113\.9:51022/);
  assert.match(ui.text(), /recordings\.read/);
  assert.match(ui.text(), /not part of this version/);
});

test("the revocations screen lists entries and offers lifting only with the write permission", async () => {
  const routes = { "GET /v1/admin/revocations": json(200, { revocations: [revocation()], next: null }) };
  ui = await mount({ ...signedIn(), ...routes }, "#/revocations");
  assert.match(ui.text(), /u-mallory/);
  assert.match(ui.text(), /Left the company/);
  assert.ok(byText(ui.root, "button", "Lift…"));
  assert.ok(byText(ui.root, "button", "New revocation"));
  ui.stop();
  ui = await mount({ ...signedIn(["sessions.read"]), ...routes }, "#/revocations");
  assert.equal(byText(ui.root, "button", "Lift…"), undefined);
  assert.equal(byText(ui.root, "button", "New revocation"), undefined);
});

test("the audit screen sends RFC 3339 range filters and the drawer shows typed fields only", async () => {
  const seen = [];
  ui = await mount(
    {
      ...signedIn(),
      "GET /v1/admin/audit": (request) => {
        seen.push(request.query.toString());
        return json(200, { events: [auditEvent()], next_cursor: null });
      },
    },
    "#/audit?type=admin.&from=2026-11-24T10%3A00&to=2026-11-24T11%3A30",
  );
  assert.equal(seen[0], "type=admin.&from=2026-11-24T10%3A00%3A00Z&to=2026-11-24T11%3A30%3A00Z&limit=50");
  const opener = byText(ui.root, "button", "Details");
  opener.focus();
  click(opener);
  const dialog = document.querySelector('[role="dialog"]');
  assert.match(dialog.textContent, /admin\.node\.approved/);
  assert.match(dialog.textContent, /labels_count/);
  assert.match(dialog.textContent, /replaced/);
  press(dialog, "Escape");
  assert.equal(document.querySelector('[role="dialog"]'), null);
  assert.equal(document.activeElement, opener);
});

test("a bad audit filter code is explained and the cursor is passed on load more", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/audit": json(400, { error: "invalid_range" }) }, "#/audit");
  assert.match(ui.root.querySelector(".filters").textContent, /start must be before the end/);
});

test("without a session the sign-in page shows one clear button that leaves for the login route", async () => {
  ui = await mount({ "GET /v1/web/session": json(401, { error: "unauthorized" }) });
  const link = ui.root.querySelector("a.btn-primary");
  assert.match(link.getAttribute("href"), /^\/v1\/web\/login\?return_to=/);
  assert.match(ui.text(), /Welcome back/);
  assert.equal(ui.root.querySelector(".mainnav"), null);
});

test("an unreachable server offers a retry instead of the sign-in button", async () => {
  ui = await mount({ "GET /v1/web/session": json(500, { error: "internal" }) });
  assert.match(ui.text(), /could not be reached/);
  assert.equal(byText(ui.root, "a", "Sign in"), undefined);
  assert.ok(byText(ui.root, "button", "Try again"));
});

test("a signed-in user without any admin permission gets the not allowed page and an empty nav", async () => {
  ui = await mount({ ...signedIn([]) });
  assert.match(ui.text(), /Not allowed/);
  assert.match(ui.text(), /none of your roles grants an administration permission/);
  assert.equal(ui.root.querySelectorAll(".mainnav a").length, 0);
});

test("navigation hides what the session cannot use and routes to it are refused without any request", async () => {
  ui = await mount({ ...signedIn(["sessions.read"]), "GET /v1/admin/sessions": json(200, { sessions: [], next: null }) }, "#/nodes");
  assert.deepEqual(Array.from(ui.root.querySelectorAll(".mainnav a")).map((link) => link.getAttribute("href")), ["#/sessions", "#/revocations"]);
  assert.match(ui.text(), /needs the permission nodes\.approve/);
  assert.equal(ui.server.count("GET", "/v1/admin/nodes"), 0);
  window.location.hash = "#/audit";
  await settle();
  assert.match(ui.text(), /needs the permission audit\.read/);
});

test("the server remains the authority: a 403 from the API renders the not allowed page", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/audit": json(403, { error: "forbidden" }) }, "#/audit");
  assert.match(ui.text(), /HTTP 403/);
  assert.match(ui.text(), /audit\.read/);
});

test("the start route goes to the first screen the session may open, unknown routes say not found", async () => {
  ui = await mount({ ...signedIn(["audit.read"]), "GET /v1/admin/audit": json(200, { events: [], next_cursor: null }) });
  assert.equal(window.location.hash, "#/audit");
  window.location.hash = "#/does-not-exist";
  await settle();
  assert.match(ui.text(), /HTTP 404/);
  assert.equal(document.title, "Not found · Jaunt");
});

test("signing out posts with the token and returns to the sign-in page", async () => {
  ui = await mount({ ...signedIn(), "GET /v1/admin/nodes": nodesPage([]), "POST /v1/web/logout": json(204, undefined) }, "#/nodes");
  click(byText(ui.root, "button", "Sign out"));
  await settle();
  const call = ui.server.calls.find((entry) => entry.path === "/v1/web/logout");
  assert.equal(call.headers["x-jaunt-csrf"], "csrf-token-one");
  assert.match(ui.text(), /You have signed out/);
});
