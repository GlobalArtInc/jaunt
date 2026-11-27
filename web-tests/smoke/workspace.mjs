import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { PANE, closeAllTabs, fail, failures, instrument, layout, quickOpen, until, waitConnected } from "./kit.mjs";
import { startStub } from "./stub.mjs";

const OUT = (process.env.SCREENSHOT_DIR || fileURLToPath(new URL("../screenshots-out/t2b/", import.meta.url))).replace(/\/?$/, "/");
const WIDTHS = [380, 1440];
const THEMES = ["light", "dark"];
const PERMISSIONS = ["nodes.approve", "sessions.read", "sessions.terminate", "audit.read"];
const RUN_LIMIT_MS = 15 * 60 * 1000;
const t = Math.floor(Date.now() / 1000);
const LOGINS = ["alice", "deploy", "backup", "monitor", "nginx", "release", "root"];
const TARGETS = [
  { node: "web-01", labels: { env: "prod", role: "web" }, connected: true, pinned: true, logins: LOGINS, hidden_logins: ["Alice.M"] },
  { node: "db-01", labels: { env: "prod", role: "db" }, connected: true, pinned: true, logins: ["postgres"], hidden_logins: [] },
  { node: "db-02", labels: { env: "staging", role: "db" }, connected: true, pinned: false, creates_accounts: true, logins: ["alice", "readonly"], hidden_logins: [] },
  { node: "web-02", labels: { env: "staging", role: "web" }, connected: true, pinned: false, logins: ["deploy"], hidden_logins: [] },
  { node: "build-01", labels: { env: "ci" }, connected: false, pinned: false, logins: ["alice"], hidden_logins: [] },
  { node: "edge-01", labels: { env: "prod", role: "edge" }, connected: true, pinned: false, logins: [], hidden_logins: [] },
];
const RECENT = [
  { node: "web-01", login: "alice", last_at: t - 7200 },
  { node: "db-02", login: "alice", last_at: t - 90000 },
  { node: "build-01", login: "alice", last_at: t - 3 * 86400 },
];

setTimeout(() => {
  console.error(`the run exceeded ${RUN_LIMIT_MS / 1000} s and was stopped`);
  for (const entry of failures) console.error(" - " + entry);
  process.exit(1);
}, RUN_LIMIT_MS).unref();

function nodeRecord(index, entry) {
  return {
    id: "n-" + index,
    name: entry.node,
    hostname: entry.node + ".example.com",
    labels: entry.labels,
    state: "active",
    revoked: false,
    connected: entry.connected,
    connected_since: entry.connected ? t - 3600 * (index + 1) : null,
    agent_version: "0.4.2",
    certificates: { state: "delivered", x509_expires_at: t + 5 * 86400, ssh_host_expires_at: t + 4 * 86400 },
    approved_by: "alice@example.com",
    created_at: t - 30 * 86400,
    removed_at: null,
    creates_accounts: entry.creates_accounts === true,
  };
}

function arrange(stub) {
  stub.setTargets(TARGETS.map((entry) => ({ ...entry })));
  stub.setNodes(TARGETS.map((entry, index) => nodeRecord(index + 1, entry)));
  stub.setRecent(RECENT);
  stub.terminal.plan = null;
  stub.terminal.nodeMs = 24;
  stub.terminal.recording = "full";
  stub.terminal.maxPerUser = 4;
  stub.terminal.openOverride = null;
  stub.terminal.denyNext = null;
}

async function snap(page, name, width, theme, full = true) {
  await page.screenshot({ path: `${OUT}${name}-${width}-${theme}.png`, fullPage: full });
}

async function signIn(page, stub) {
  await page.goto(stub.origin + "/");
  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });
}

const text = (page, selector) => page.locator(selector).first().textContent();

async function openSession(page, stub, node, login, narrow) {
  const before = stub.terminal.sessions.length;
  await quickOpen(page, node, login, narrow);
  await until(() => stub.terminal.sessions.length === before + 1, "the session of " + login + "@" + node, "workspace");
  return stub.terminal.sessions.at(-1);
}

async function activate(page, label, narrow) {
  if (!narrow) {
    await page.click(`.ttab-btn:has(.lbl:text-is("${label}"))`);
    return;
  }
  await page.click(".switcher-btn");
  await page.click(`.switcher .menu [role=menuitemradio]:has-text("${label}")`);
}

async function nodesScreen(page, stub, context, width, theme, narrow) {
  await page.goto(stub.origin + "/#/nodes");
  await page.waitForSelector(".node-card");
  await page.waitForSelector(".recent-row .recent-btn");
  await layout(page, context, "nodes", narrow);
  const headings = await page.locator(".results .section-head h2").allTextContents();
  if (headings.join() !== "Recent terminals,Pinned,All nodes") fail(context, "section headings " + JSON.stringify(headings));
  const recent = await page.locator(".recent-row .mono").allTextContents();
  if (recent.join() !== "alice@web-01,alice@db-02,alice@build-01") fail(context, "recent terminals " + JSON.stringify(recent));
  await page.click('.node-card:has(a.node-name:text-is("web-01")) button[aria-label="Connect to web-01"]');
  await page.waitForSelector(".menu .menu-search input");
  await snap(page, "1-connect", width, theme);
  await layout(page, context, "nodes-menu", narrow);
  const overflow = await page.evaluate(() => {
    const menu = document.querySelector(".menu").getBoundingClientRect();
    return Math.max(0, menu.right - document.documentElement.clientWidth, -menu.left);
  });
  if (overflow > 0.5) fail(context, `the Connect menu sticks out of the window by ${overflow}px`);
  await page.fill(".menu .menu-search input", "re");
  const filtered = await page.locator(".menu .menu-scroll [role=menuitem] .menu-label").allTextContents();
  if (filtered.join() !== "release") fail(context, "the login filter shows " + filtered.join());
  const focusKept = await page.evaluate(() => document.activeElement && document.activeElement.type === "search");
  if (!focusKept) fail(context, "the filter lost its focus while filtering");
  await page.keyboard.press("Escape");
  await page.waitForSelector(".menu", { state: "detached" });

  const before = stub.state.targets.filter((entry) => entry.pinned).length;
  await page.click('button[aria-label="Pin db-02"]');
  await page.waitForSelector('button[aria-label="Unpin db-02"]');
  if (stub.state.targets.filter((entry) => entry.pinned).length !== before + 1) fail(context, "the pin did not reach the server");
  const focused = await page.evaluate(() => document.activeElement && document.activeElement.getAttribute("aria-label"));
  if (focused !== "Unpin db-02") fail(context, "focus is on " + focused + " after pinning");
  await page.click('button[aria-label="Unpin db-02"]');
  await page.waitForSelector('button[aria-label="Pin db-02"]');
  if (stub.state.targets.filter((entry) => entry.pinned).length !== before) fail(context, "the unpin did not reach the server");

  await page.click(".recent-row .recent-btn");
  await page.waitForSelector(`${PANE} .term-host canvas`);
  await waitConnected(page);
  if ((await page.evaluate(() => location.hash)) !== "#/terminal") fail(context, "a recent button left the address at " + (await page.evaluate(() => location.hash)));
  await closeAllTabs(page, narrow);
}

async function tabsScreens(page, stub, context, width, theme, narrow) {
  await page.goto(stub.origin + "/#/terminal");
  await page.waitForSelector(".panel.quick");
  await layout(page, context, "quick-inline", narrow);
  const recent = await page.locator(".panel.quick section:first-of-type .quick-row .name").allTextContents();
  if (recent.join() !== "alice@web-01,alice@db-02,alice@build-01") fail(context, "inline recent pairs " + JSON.stringify(recent));
  const order = await page.locator(".panel.quick section:nth-of-type(2) .quick-row .name").allTextContents();
  if (order.join() !== "web-01,db-01,db-02,web-02,build-01,edge-01") fail(context, "node order in quick open " + JSON.stringify(order));

  const first = await openSession(page, stub, "web-01", "alice", narrow);
  await page.waitForSelector(`${PANE} .term-host canvas`);
  await waitConnected(page);
  await page.waitForSelector(".ws:not([hidden])");

  await page.click(narrow ? '.switcher .icon-btn[aria-label="New terminal"]' : '.tabbar button:has-text("New terminal")');
  await page.waitForSelector(".modal.quick");
  await page.click('.modal.quick .quick-row:has(.name:text-is("db-02")) button:has-text("Choose login")');
  await page.waitForSelector('.modal.quick input[name="quick-login"]');
  await layout(page, context, "quick-dialog", narrow);
  await snap(page, "2b-new-terminal", width, theme, false);
  await page.click('.modal.quick .quick-row:has(.name:text-is("db-02")) button:has-text("Hide logins")');
  const second = await openSession(page, stub, "db-01", "postgres", narrow);
  await waitConnected(page);
  const third = await openSession(page, stub, "web-02", "deploy", narrow);
  await waitConnected(page);
  third.sendText({ t: "error", code: "unavailable" });
  third.close(1011, "unavailable");
  await page.waitForSelector(`${PANE} .term-banner:has-text('The node became unavailable')`);

  await activate(page, "alice@web-01", narrow);
  await page.waitForFunction(() => document.querySelector(".term-pane:not([hidden]) .statusbar .mono")?.textContent === "web-01");
  const railCount = await text(page, ".rail-count").catch(() => null);
  if (railCount !== "3") fail(context, "the rail count is " + railCount);
  const shown = await page.locator(".term-pane").evaluateAll((panes) => panes.map((pane) => pane.hidden));
  if (shown.join() !== "false,true,true") fail(context, "pane visibility " + shown.join());

  const lat = await page
    .waitForFunction(() => !document.querySelector(".term-pane:not([hidden]) .lat")?.closest(".item").hidden, null, { timeout: 30000 })
    .then(() => true)
    .catch(() => false);
  if (!lat) fail(context, "the latency never appeared after a ping");
  else {
    const header = await text(page, `${PANE} .lat .mono`);
    if (header !== "24 ms" && !/^\d+ ms$/.test(header)) fail(context, "latency text " + header);
    const line = await text(page, `${PANE} .term-status`);
    if (!/server to node 24 ms/.test(line) && width > 640) fail(context, "the status line lacks the node leg: " + line);
    const band = await page.locator(`${PANE} .lat`).getAttribute("class");
    if (!/lat-good/.test(band)) fail(context, "latency band " + band);
  }
  const record = await text(page, `${PANE} .statusbar .badge[class*=b-rec]`).catch(() => null);
  if (!record || !/ecorded/.test(record)) fail(context, "the recording badge says " + record);
  await layout(page, context, "workspace", narrow);
  await snap(page, "2-terminal", width, theme);

  await page.click(narrow ? ".switcher-btn" : ".tabbar-end .btn-menu");
  await page.waitForSelector(".menu [role=menuitemradio]");
  const entries = await page.locator(".menu [role=menuitemradio] .menu-hint").allTextContents();
  if (entries.length !== 3 || !/^Ended: /.test(entries[2])) fail(context, "switcher hints " + JSON.stringify(entries));
  await layout(page, context, "switcher-menu", narrow);
  await snap(page, "2d-switcher", width, theme, false);
  await page.keyboard.press("Escape");

  if (!narrow) {
    await page.click(`${PANE} .term-host`);
    const inputBefore = first.input.length;
    await page.keyboard.press("Control+Alt+PageDown");
    const nowActive = await page.locator('[role=tab][aria-selected=true] .lbl').textContent();
    if (nowActive !== "postgres@db-01") fail(context, "Ctrl+Alt+PageDown selected " + nowActive);
    await page.keyboard.press("Control+Alt+PageUp");
    const back = await page.locator('[role=tab][aria-selected=true] .lbl').textContent();
    if (back !== "alice@web-01") fail(context, "Ctrl+Alt+PageUp selected " + back);
    await page.keyboard.press("Control+Alt+PageUp");
    const wrapped = await page.locator('[role=tab][aria-selected=true] .lbl').textContent();
    if (wrapped !== "deploy@web-02") fail(context, "the ring did not wrap: " + wrapped);
    await page.keyboard.press("Control+Alt+PageDown");
    if (first.input.length !== inputBefore || second.input.length !== 0) fail(context, "the switching keys reached a node");
    const focusInTerminal = await page.evaluate(() => document.activeElement && document.activeElement.closest(".term-host") !== null);
    if (!focusInTerminal) fail(context, "focus is not in the terminal after switching with the keyboard");
    await page.click(".ttab-btn");
    await page.focus('[role=tab][aria-selected=true]');
    await page.keyboard.press("ArrowRight");
    const arrowed = await page.locator('[role=tab][aria-selected=true] .lbl').textContent();
    if (arrowed !== "postgres@db-01") fail(context, "ArrowRight selected " + arrowed);
    await activate(page, "alice@web-01", narrow);
  }

  if (narrow) {
    await page.click(`${PANE} .term-tools .n-flex button`);
    await page.click('.menu [role=menuitem]:has-text("Close terminal")');
  } else {
    await page.click(".ttab.is-active button[aria-label^='Close ']");
  }
  await page.waitForSelector("[role=dialog] .effects");
  const effects = await page.locator("[role=dialog] .effects li").allTextContents();
  if (effects.join("|") !== "The session ends now and cannot be resumed.|What was on the screen is kept only in the recording.") fail(context, "close effects " + JSON.stringify(effects));
  await layout(page, context, "close-confirm", narrow);
  await snap(page, "2c-close-confirm", width, theme, false);
  await page.click("[role=dialog] button:has-text('Keep open')");
  if (first.closed !== null) fail(context, "Keep open still closed the session");
  await page.click(narrow ? ".switcher-btn" : ".tabbar-end .btn-menu");
  await page.click('.menu [role=menuitem]:has-text("Close ended terminals")');
  const left = await page.locator('[role=tab] .lbl').allTextContents().catch(() => []);
  if (!narrow && left.join() !== "alice@web-01,postgres@db-01") fail(context, "after Close ended terminals: " + left.join());
  if (narrow) {
    const count = await text(page, ".switcher-btn .count");
    if (count !== "1 of 2") fail(context, "the switcher count is " + count);
  }
  await closeAllTabs(page, narrow);
  const closedFirst = await until(() => first.closed !== null, "the close of the first session", context);
  if (closedFirst && first.closed !== 1000) fail(context, "closing a tab ended the socket with " + first.closed);
}

const STATES = [
  ["connecting", (stub) => (stub.terminal.plan = { hold: true }), async (page) => page.waitForSelector(`${PANE} .term-steps li[aria-current=step]:has-text('Reaching')`), /Connecting…/],
  ["account-creating", (stub) => (stub.terminal.plan = { account: { home: "/home/alice" } }), async (page) => page.waitForSelector(`${PANE} .term-banner:has-text('Creating your account')`), /Creating account…/],
  ["denied", (stub) => (stub.terminal.denyNext = { status: 403, body: { error: "denied", ref: "D-4C1E82A9" } }), async (page) => page.waitForSelector(`${PANE} .term-banner:has-text('Access denied')`), /Not opened/],
  ["limit", (stub) => (stub.terminal.denyNext = { status: 429, body: { error: "limit", open: 4, max: 4, ref: "D-0B77E310" } }), async (page) => page.waitForSelector(`${PANE} .term-banner:has-text('Too many terminals')`), /Not opened/],
  ["account-refused", (stub) => (stub.terminal.plan = { refuse: { code: "account_refused", ref: "H-9D0311FE" } }), async (page) => page.waitForSelector(`${PANE} .term-banner:has-text('Your account could not be created')`), /Not opened/],
  ["account-failed", (stub) => (stub.terminal.plan = { refuse: { code: "account_failed", ref: "H-51C07A42" } }), async (page) => page.waitForSelector(`${PANE} .term-banner:has-text('The node could not create your account')`), /Not opened/],
  ["no-account", (stub) => (stub.terminal.plan = { refuse: { code: "no_account", ref: "D-0B77E310" } }), async (page) => page.waitForSelector(`${PANE} .term-banner:has-text('There is no account')`), /Not opened/],
];

const ENDINGS = [
  ["unavailable", (record) => (record.sendText({ t: "error", code: "unavailable" }), record.close(1011, "unavailable")), "The node became unavailable", /Connection lost/],
  ["revoked", (record) => (record.sendText({ t: "error", code: "revoked" }), record.close(4001, "revoked")), "Access revoked", /Cut/],
  ["terminated", (record) => record.terminate(), "Ended by an administrator", /Ended/],
  ["idle-closed", (record) => (record.sendText({ t: "error", code: "timeout" }), record.close(4002, "idle")), "Closed for inactivity", /Session ended/],
  ["stalled", (record) => (record.sendText({ t: "error", code: "stalled" }), record.close(4003, "stalled")), "Closed: this page stopped taking output", /Session ended/],
  ["ended-normally", (record) => (record.sendText({ t: "exit", status: 0, signal: null }), record.close(1000, "exit")), "Session ended", /Session ended/],
];

async function stateScreens(page, stub, context, width, theme, narrow) {
  await page.goto(stub.origin + "/#/terminal");
  await page.waitForSelector(".panel.quick");
  for (const [name, arm, wait, state] of STATES) {
    arm(stub);
    const before = stub.terminal.sessions.length;
    await quickOpen(page, "web-02", "deploy", narrow);
    await wait(page).catch(() => fail(context, "state " + name + " never showed"));
    const words = await text(page, `${PANE} .statusbar [role=status]`);
    if (!state.test(words)) fail(context, `${name}: the state word is ${JSON.stringify(words)}`);
    await layout(page, context, "state-" + name, narrow);
    await snap(page, "3-states-" + name, width, theme);
    if (name === "connecting") {
      const steps = await page.locator(`${PANE} .term-steps li`).allTextContents();
      if (steps.length !== 3) fail(context, "connecting steps " + JSON.stringify(steps));
      stub.terminal.sessions.at(-1).release();
      await waitConnected(page);
      await snap(page, "3-states-connected", width, theme);
    } else if (name === "account-creating") {
      const steps = await page.locator(`${PANE} .term-steps li`).allTextContents();
      if (steps.length !== 4) fail(context, "account steps " + JSON.stringify(steps));
      const banners = await page.locator(`${PANE} .term-banner .banner`).count();
      if (banners !== 1) fail(context, "the account step shows " + banners + " banners");
      stub.terminal.sessions.at(-1).release();
      await waitConnected(page);
      await page.waitForSelector(`${PANE} .term-banner:has-text('Account created.')`);
      await snap(page, "3-states-account-created", width, theme);
    } else if (stub.terminal.sessions.length !== before + (name === "denied" || name === "limit" ? 0 : 1)) {
      fail(context, `${name}: ${stub.terminal.sessions.length - before} sessions were opened`);
    }
    if (name === "denied" || name === "limit") {
      const reference = await text(page, `${PANE} .term-banner .ref .mono`);
      if (!/^D-[0-9A-F]{8}$/.test(reference)) fail(context, `${name}: the reference is ${reference}`);
    }
    stub.terminal.plan = null;
    await closeAllTabs(page, narrow);
  }
  stub.terminal.maxPerUser = 4;

  for (const [name, end, title, state] of ENDINGS) {
    await quickOpen(page, "web-01", "deploy", narrow);
    await waitConnected(page);
    const record = stub.terminal.sessions.at(-1);
    end(record);
    await page.waitForSelector(`${PANE} .term-banner:has-text("${title}")`).catch(() => fail(context, "ending " + name + " never showed"));
    const words = await text(page, `${PANE} .statusbar [role=status]`);
    if (!state.test(words)) fail(context, `${name}: the state word is ${JSON.stringify(words)}`);
    await layout(page, context, "ending-" + name, narrow);
    await snap(page, "3-states-" + name, width, theme);
    await closeAllTabs(page, narrow);
  }

  await quickOpen(page, "web-01", "deploy", narrow);
  await waitConnected(page);
  const record = stub.terminal.sessions.at(-1);
  record.idle(112);
  await page.waitForSelector(`${PANE} .term-banner:has-text('This terminal closes in')`);
  const idleWords = await text(page, `${PANE} .statusbar [role=status]`);
  if (!/Idle/.test(idleWords)) fail(context, "idle state word " + idleWords);
  const title = await text(page, `${PANE} .term-banner .banner-title`);
  if (!/^This terminal closes in \d:\d\d\.$/.test(title)) fail(context, "idle title " + title);
  await layout(page, context, "state-idle", narrow);
  await snap(page, "3-states-idle", width, theme);
  const ticked = await page
    .waitForFunction((first) => document.querySelector(".term-pane:not([hidden]) .term-banner .banner-title")?.textContent !== first, title, { timeout: 5000 })
    .then(() => true)
    .catch(() => false);
  if (!ticked) fail(context, "the idle countdown does not tick");
  await page.click(`${PANE} .term-banner button:has-text('Keep open')`);
  await until(() => record.actives.length === 1, "the active frame", context);
  const gone = await page.locator(`${PANE} .term-banner .banner`).count();
  if (gone !== 0) fail(context, "Keep open left the banner");
  await closeAllTabs(page, narrow);
}

async function sessionsScreens(page, stub, context, width, theme, narrow) {
  await page.goto(stub.origin + "/#/sessions");
  await page.waitForSelector("tbody tr");
  await page.waitForFunction(() => document.querySelector("table.data tbody tr .cell-origin")?.textContent.length > 0);
  await layout(page, context, "sessions", narrow);
  await snap(page, "7-sessions", width, theme);
  const overflowing = await page.evaluate(() => {
    const wrap = document.querySelector(".table-wrap");
    return wrap.scrollWidth - wrap.clientWidth;
  });
  if (!narrow && overflowing > 1) fail(context, `the sessions table scrolls by ${overflowing}px at ${width}px`);
  await page.click("button:has-text('Origin: Any')");
  await page.click('[role=menuitemradio]:has-text("ssh")');
  await page.waitForFunction(() => location.hash === "#/sessions?origin=ssh");
  await page.waitForFunction(() => {
    const cells = Array.from(document.querySelectorAll("td.cell-origin"));
    return cells.length > 0 && cells.every((cell) => cell.textContent === "ssh");
  }, null, { timeout: 5000 }).catch(() => undefined);
  const origins = await page.locator("td.cell-origin").allTextContents();
  if (origins.length === 0 || origins.some((entry) => entry !== "ssh")) fail(context, "the ssh filter shows " + JSON.stringify(origins));
  await page.goto(stub.origin + "/#/sessions");
  await page.waitForSelector("tbody tr");
  const button = page.locator("table.data button:has-text('Terminate…')").first();
  await button.click();
  await page.waitForSelector("[role=dialog] .effects");
  const cancelFocused = await page.evaluate(() => document.activeElement && document.activeElement.textContent === "Cancel");
  if (!cancelFocused) fail(context, "Cancel does not have the first focus in the terminate dialog");
  await page.fill("[role=dialog] input[type=text]", "Long-running query is locking the table.");
  await layout(page, context, "terminate-dialog", narrow);
  await snap(page, "7b-terminate-confirm", width, theme, false);
  const before = stub.state.terminations.length;
  await page.click("[role=dialog] button:has-text('Terminate session')");
  await until(() => stub.state.terminations.length === before + 1, "the terminate request", context);
  await page.waitForSelector("[role=dialog]", { state: "detached" });
  const last = stub.state.terminations.at(-1);
  if (last.reason !== "Long-running query is locking the table.") fail(context, "the reason that reached the server is " + JSON.stringify(last.reason));
  const live = await page.locator("table.data button:has-text('Terminate…')").count();
  if (live !== 1) fail(context, "after a terminate " + live + " live sessions have the button");
}

async function runContext(browser, stub, width, theme) {
  const context = `workspace-${theme}-${width}`;
  const narrow = width <= 640;
  arrange(stub);
  const browserContext = await browser.newContext({ viewport: { width, height: width < 600 ? 800 : 900 }, colorScheme: theme, deviceScaleFactor: 1, reducedMotion: "reduce" });
  await browserContext.grantPermissions(["clipboard-read", "clipboard-write"], { origin: stub.origin });
  const { page, problems } = await instrument(browserContext, stub.origin);
  await signIn(page, stub);
  await nodesScreen(page, stub, context, width, theme, narrow);
  await tabsScreens(page, stub, context, width, theme, narrow);
  await stateScreens(page, stub, context, width, theme, narrow);
  await sessionsScreens(page, stub, context, width, theme, narrow);
  const violations = await page.evaluate(() => window.__csp);
  if (violations.length > 0) fail(context, "CSP violations: " + violations.join("; "));
  if (stub.terminal.violations.length > 0) fail(context, "the stub saw messages outside the contract: " + stub.terminal.violations.join("; "));
  if (stub.terminal.handshakeFailures.length > 0) fail(context, "handshake refused: " + stub.terminal.handshakeFailures.join(", "));
  for (const problem of problems) fail(context, problem);
  await browserContext.close();
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const browser = await chromium.launch();
  try {
    for (const theme of THEMES) {
      for (const width of WIDTHS) {
        const stub = await startStub({ permissions: PERMISSIONS });
        try {
          await runContext(browser, stub, width, theme);
        } finally {
          await stub.close();
        }
      }
    }
  } finally {
    await browser.close();
  }
  console.log(`screenshots: ${OUT}`);
  if (failures.length > 0) {
    console.error(`${failures.length} failure(s):`);
    for (const entry of failures) console.error(" - " + entry);
    process.exitCode = 1;
  } else {
    console.log("workspace: Nodes page with pins and recent terminals, quick open, tabs, switching keys, close rules, header, steps, states, idle, Sessions origin and terminate passed");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
