import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const ORIGIN = "https://jaunt.e2e.test";
const IDP_PRIME =
  "https://idp.e2e.test/authorize?response_type=code&client_id=jaunt-e2e&code_challenge=e2e-test-only-challenge&code_challenge_method=S256" +
  "&redirect_uri=https%3A%2F%2Fjaunt.e2e.test%2Fv1%2Flogin%2Fcallback&state=e2e-prime&login_hint=";
const WIDTHS = [380, 1440];
const OUT = process.env.E2E_SCREENSHOTS || fileURLToPath(new URL("../../target/e2e/screenshots/", import.meta.url));
const WAIT_MS = 45000;
const IDLE_WAIT_MS = 150000;
const DENIAL_REFERENCE = /^D-[0-9A-F]{8}$/;
const LOGIN = "deploy";
const FIRST_NODE = "node-a";
const SECOND_NODE = "node-b";
const SERVER_LIMIT = 4;

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set; run this through \`just e2e-web\``);
  }
  return value;
}

const WEB_PORT = required("E2E_WEB_PORT");
const IDP_PORT = required("E2E_IDP_PORT");
const OPERATOR = required("E2E_WS_OPERATOR");
const IDLE_USER = required("E2E_WS_IDLE_USER");
const RESULT_FILE = required("E2E_WS_OUT");
const failures = [];
const results = [];

function fail(context, message) {
  failures.push(`${context}: ${message}`);
}

async function guard(context, name, action) {
  try {
    return await action();
  } catch (error) {
    fail(context, `${name}: ${String(error.message || error).split("\n")[0]}`);
    return null;
  }
}

async function shot(page, context, name, { fullPage = true } = {}) {
  await page.waitForTimeout(150);
  await page.screenshot({ path: `${OUT}${context}-${name}.png`, fullPage });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (overflow > 0) {
    fail(`${context} ${name}`, `the page overflows horizontally by ${overflow}px`);
  }
}

function watch(page, problems) {
  page.on("console", (message) => {
    if (message.type() === "error" && !/Failed to load resource/.test(message.text())) {
      problems.push(`console: ${message.text()}`);
    }
  });
  page.on("response", (response) => {
    if (response.status() >= 400 && ![401, 429].includes(response.status())) {
      problems.push(`HTTP ${response.status()} for ${response.url()}`);
    }
  });
  page.on("pageerror", (error) => problems.push(`pageerror: ${error.message}`));
}

function track(page) {
  const log = { sockets: [], frames: [] };
  page.on("websocket", (socket) => {
    const index = log.sockets.length;
    log.sockets.push(socket.url());
    for (const [event, direction] of [["framereceived", "in"], ["framesent", "out"]]) {
      socket.on(event, (frame) => {
        if (typeof frame.payload === "string") {
          log.frames.push({ socket: index, direction, payload: frame.payload });
        }
      });
    }
  });
  return log;
}

function framesOf(log, direction, socket) {
  const found = [];
  for (const entry of log.frames) {
    if (entry.direction !== direction || (socket !== undefined && entry.socket !== socket)) {
      continue;
    }
    try {
      found.push({ socket: entry.socket, frame: JSON.parse(entry.payload) });
    } catch {
      continue;
    }
  }
  return found;
}

function readyOf(log, socket) {
  const entry = framesOf(log, "in", socket).find(({ frame }) => frame.t === "ready");
  return entry ? entry.frame : null;
}

async function instrument(browserContext) {
  await browserContext.addInitScript(() => {
    window.__csp = [];
    window.__terminals = [];
    window.__steps = [];
    document.addEventListener("securitypolicyviolation", (event) => window.__csp.push(`${event.violatedDirective} ${event.blockedURI}`));
    new MutationObserver(() => {
      for (const item of document.querySelectorAll(".term-steps li")) {
        const text = item.textContent.replace(/\s+/g, " ").trim().replace(/^(✓|\d+)\s*/, "").replace(/, done$/, "");
        if (text !== "" && !window.__steps.includes(text)) {
          window.__steps.push(text);
        }
      }
    }).observe(document, { childList: true, subtree: true, characterData: true });
    let constructor;
    Object.defineProperty(window, "Terminal", {
      configurable: true,
      get: () => constructor,
      set(value) {
        constructor = new Proxy(value, {
          construct(target, args, newTarget) {
            const created = Reflect.construct(target, args, newTarget);
            window.__terminals.push(created);
            return created;
          },
        });
      },
    });
  });
}

async function signIn(browser, hint, width) {
  const browserContext = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width, height: width < 600 ? 800 : 900 },
    deviceScaleFactor: 1,
  });
  await instrument(browserContext);
  const priming = await browserContext.newPage();
  await priming.goto(IDP_PRIME + encodeURIComponent(hint));
  await priming.close();
  const page = await browserContext.newPage();
  const problems = [];
  watch(page, problems);
  const log = track(page);
  await page.goto(`${ORIGIN}/`);
  await page.waitForSelector("a.btn-primary");
  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });
  return { browserContext, page, problems, log };
}

async function finish(context, session) {
  for (const violation of await session.page.evaluate(() => window.__csp)) {
    session.problems.push(`CSP violation: ${violation}`);
  }
  for (const problem of session.problems) {
    fail(context, problem);
  }
  await session.browserContext.close();
}

async function visibleTerminalText(page) {
  return page.evaluate(() => {
    const shown = window.__terminals.filter((terminal) => terminal.element && terminal.element.isConnected && !terminal.element.closest("[hidden]"));
    const terminal = shown[shown.length - 1];
    if (!terminal) {
      return "";
    }
    const buffer = terminal.buffer.active;
    const lines = [];
    for (let row = 0; row < buffer.length; row += 1) {
      const line = buffer.getLine(row);
      lines.push(line ? line.translateToString(true) : "");
    }
    return lines.join("\n");
  });
}

async function shows(page, pattern, timeout = WAIT_MS) {
  const deadline = Date.now() + timeout;
  let text = "";
  while (Date.now() < deadline) {
    text = await visibleTerminalText(page);
    if (pattern.test(text)) {
      return text;
    }
    await page.waitForTimeout(100);
  }
  throw new Error(`${pattern} did not appear in the terminal: ${JSON.stringify(text.slice(-200))}`);
}

async function paintedPixels(page) {
  return page.evaluate(() => {
    let count = 0;
    for (const canvas of document.querySelectorAll(".term-pane:not([hidden]) .term-host canvas")) {
      const context = canvas.getContext("2d");
      if (!context || canvas.width === 0 || canvas.height === 0) {
        continue;
      }
      const data = context.getImageData(0, 0, canvas.width, canvas.height).data;
      for (let index = 3; index < data.length; index += 4) {
        if (data[index] !== 0 && data[index - 3] + data[index - 2] + data[index - 1] > 300) {
          count += 1;
        }
      }
    }
    return count;
  });
}

async function expectPainted(page, context, what) {
  const deadline = Date.now() + 5000;
  let pixels = 0;
  while (Date.now() < deadline) {
    pixels = await paintedPixels(page);
    if (pixels >= 200) {
      return;
    }
    await page.waitForTimeout(100);
  }
  fail(context, `DEFECT the terminal canvas is blank ${what} (${pixels} light pixels) although the buffer holds the text`);
}

async function typeLine(page, line) {
  await page.keyboard.type(line);
  await page.keyboard.press("Enter");
}

function pane(page) {
  return page.locator(".term-pane:not([hidden])");
}

async function waitConnected(page) {
  await page.waitForFunction(
    () => /Connected/.test(document.querySelector(".term-pane:not([hidden]) .sess-head .item-state")?.textContent || ""),
    null,
    { timeout: WAIT_MS },
  );
}

async function tabState(page) {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll('.ttabs [role="tab"]')).map((tab) => ({
      label: tab.querySelector(".lbl")?.textContent || "",
      selected: tab.getAttribute("aria-selected") === "true",
      words: tab.querySelector(".visually-hidden")?.textContent || "",
    })),
  );
}

async function pickAndOpen(root, node, login) {
  await root.locator(`.quick-row:has(.name:text-is("${node}")) button:has-text("Choose login")`).click();
  await root.locator(`.quick-row.is-open label.pick-login:has(input[value="${login}"])`).click();
  await root.locator(`.btn-primary:has-text("Open terminal as ${login} on ${node}")`).click();
}

async function openInline(page, node, login) {
  await page.goto(`${ORIGIN}/#/terminal`);
  await page.waitForSelector(".panel.quick");
  await pickAndOpen(page.locator(".panel.quick"), node, login);
  await page.waitForSelector(".term-pane:not([hidden]) .term-host canvas", { timeout: WAIT_MS });
}

function newTerminalButton(page) {
  return page.locator('.tabbar button:has-text("New terminal"), .switcher .icon-btn[aria-label="New terminal"]').locator("visible=true").first();
}

async function openAnother(page, node, login, shotName) {
  await newTerminalButton(page).click();
  const dialog = page.locator("[role=dialog].quick");
  await dialog.waitFor();
  if (shotName) {
    await page.waitForSelector("[role=dialog].quick .quick-row .name");
    await shot(page, shotName.context, shotName.name);
  }
  await pickAndOpen(dialog, node, login);
  await page.waitForSelector("[role=dialog].quick", { state: "detached" });
}

async function closeActive(page, { confirm }) {
  const narrow = (await page.viewportSize()).width < 640;
  if (narrow) {
    await pane(page).locator("button:has-text('More')").locator("visible=true").first().click();
    await page.locator('[role=menuitem]:has-text("Close terminal")').click();
  } else {
    await page.locator('.ttab.is-active button[data-close]').click();
  }
  if (confirm) {
    await page.locator("[role=dialog] .btn:has-text('Close terminal')").click();
    await page.waitForSelector("[role=dialog]", { state: "detached" });
  }
}

async function apiGet(page, path) {
  return page.evaluate(async (target) => {
    const response = await fetch(target, { credentials: "same-origin", headers: { Accept: "application/json" } });
    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    return { status: response.status, body };
  }, path);
}

function isInteger(value) {
  return Number.isInteger(value);
}

async function contract(page, context) {
  const targets = await apiGet(page, "/v1/web/terminal/targets");
  const wellFormed = (entry) =>
    typeof entry.node === "string" &&
    entry.labels && typeof entry.labels === "object" &&
    typeof entry.connected === "boolean" &&
    typeof entry.creates_accounts === "boolean" &&
    Array.isArray(entry.logins) &&
    Array.isArray(entry.hidden_logins) &&
    typeof entry.pinned === "boolean";
  if (targets.status !== 200 || !Array.isArray(targets.body) || targets.body.length < 2 || !targets.body.every(wellFormed)) {
    fail(context, `CONTRACT targets: ${targets.status} ${JSON.stringify(targets.body).slice(0, 300)}`);
  }
  const limits = await apiGet(page, "/v1/web/terminal/limits");
  if (limits.status !== 200 || limits.body.max_per_user !== SERVER_LIMIT || !isInteger(limits.body.idle_timeout_secs)) {
    fail(context, `CONTRACT limits: ${limits.status} ${JSON.stringify(limits.body)}`);
  }
  const recent = await apiGet(page, "/v1/web/terminal/recent");
  if (recent.status !== 200 || !Array.isArray(recent.body) || !recent.body.every((pair) => typeof pair.node === "string" && typeof pair.login === "string" && isInteger(pair.last_at))) {
    fail(context, `CONTRACT recent: ${recent.status} ${JSON.stringify(recent.body).slice(0, 300)}`);
  }
}

async function pinFlow(page, context) {
  await page.goto(`${ORIGIN}/#/nodes`);
  await page.waitForSelector(".node-name");
  const pin = page.locator(`button.pin-btn[data-pin="${SECOND_NODE}"]`);
  if ((await pin.getAttribute("aria-pressed")) === "true") {
    await pin.click();
    await page.waitForSelector(`button.pin-btn[data-pin="${SECOND_NODE}"][aria-pressed="false"]`);
  }
  await pin.click();
  await page.waitForSelector(`button.pin-btn[data-pin="${SECOND_NODE}"][aria-pressed="true"]`);
  await page.reload();
  await page.waitForSelector(".node-name");
  const names = await page.locator("main .node-name").allTextContents();
  if (names[0] !== SECOND_NODE) {
    fail(context, `after the reload the first node is ${JSON.stringify(names[0])}, expected the pinned ${SECOND_NODE}: ${JSON.stringify(names)}`);
  }
  if ((await page.locator("h2:has-text('Pinned')").count()) === 0) {
    fail(context, "the Nodes page has no Pinned section after the reload");
  }
  await shot(page, context, "nodes-pinned");
  await page.locator(`button[aria-label="Connect to ${FIRST_NODE}"]`).click();
  const menu = page.locator("[role=menu]");
  await menu.waitFor();
  if ((await menu.locator(`[role=menuitem]:has-text("${LOGIN}")`).count()) === 0) {
    fail(context, `the Connect menu of ${FIRST_NODE} has no ${LOGIN} item`);
  }
  await shot(page, context, "nodes-connect-menu");
  await page.keyboard.press("Escape");
}

async function unpin(page) {
  await page.goto(`${ORIGIN}/#/nodes`);
  await page.waitForSelector(".node-name");
  await page.locator(`button.pin-btn[data-pin="${SECOND_NODE}"]`).click();
  await page.waitForSelector(`button.pin-btn[data-pin="${SECOND_NODE}"][aria-pressed="false"]`);
  await page.reload();
  await page.waitForSelector(".node-name");
  if ((await page.locator("h2:has-text('Pinned')").count()) !== 0) {
    throw new Error("the Pinned section is still there after the unpin and a reload");
  }
}

async function quickOpenOrder(page, context) {
  await page.goto(`${ORIGIN}/#/terminal`);
  await page.waitForSelector(".panel.quick .quick-row .name");
  const names = await page.locator(".panel.quick h3:has-text('Nodes') + ul .name").allTextContents();
  if (names[0] !== SECOND_NODE) {
    fail(context, `quick open lists ${JSON.stringify(names)}, the pinned ${SECOND_NODE} must come first`);
  }
  await shot(page, context, "quick-open");
}

async function readyHeader(session, context, socket, node, expectedRecording, expectedStages) {
  const { page, log } = session;
  const ready = readyOf(log, socket);
  if (!ready || typeof ready.session_id !== "string") {
    fail(context, `no ready frame with a session id on socket ${socket}`);
    return null;
  }
  const incoming = framesOf(log, "in", socket).map(({ frame }) => (frame.t === "progress" ? `progress:${frame.stage}` : frame.t));
  const expectedOrder = [...expectedStages.map((stage) => `progress:${stage}`), "ready"];
  const order = incoming.filter((name) => name === "ready" || name.startsWith("progress:"));
  if (JSON.stringify(order) !== JSON.stringify(expectedOrder)) {
    fail(context, `CONTRACT frame order before the shell: ${JSON.stringify(order)}, expected ${JSON.stringify(expectedOrder)}`);
  }
  if (ready.account_created !== false) {
    fail(context, `ready.account_created is ${JSON.stringify(ready.account_created)} for an existing account`);
  }
  if (ready.recording !== expectedRecording) {
    fail(context, `CONTRACT ready.recording is ${JSON.stringify(ready.recording)}, expected ${JSON.stringify(expectedRecording)}`);
  }
  const steps = await page.evaluate(() => window.__steps);
  for (const wanted of [`Reaching ${node}`, "Starting the shell"]) {
    if (!steps.includes(wanted)) {
      fail(context, `the connection steps shown were ${JSON.stringify(steps)}, no "${wanted}"`);
    }
  }
  results.push({ kind: "steps", session: ready.session_id, steps });
  await page.waitForFunction(
    () => /^\d+ ms$/.test(document.querySelector(".term-pane:not([hidden]) .sess-head .lat .mono")?.textContent || ""),
    null,
    { timeout: WAIT_MS },
  ).catch(() => fail(context, "the latency number did not appear in the header after the first pong"));
  const header = await pane(page).locator(".sess-head").innerText();
  const shortId = ready.session_id.slice(0, 8);
  if (!header.includes(shortId)) {
    fail(context, `the header does not show the session id ${shortId}: ${JSON.stringify(header)}`);
  }
  const recordingText = { full: /This session is recorded|Recorded/, output: /Output is recorded, input is not|Output only/, off: /Not recorded/ }[expectedRecording];
  if (!recordingText.test(header)) {
    fail(context, `the header does not show the recording state ${expectedRecording}: ${JSON.stringify(header)}`);
  }
  return ready.session_id;
}

async function openingAndSwitching(session, context, width, found) {
  const { page, log } = session;
  await openInline(page, FIRST_NODE, LOGIN);
  await waitConnected(page);
  const first = await readyHeader(session, context, 0, FIRST_NODE, "output", ["node", "shell"]);
  await shot(page, context, "workspace-one-tab", { fullPage: false });
  await openAnother(page, SECOND_NODE, LOGIN, { context, name: "quick-open-dialog" });
  await waitConnected(page);
  const second = await readyHeader(session, context, 1, SECOND_NODE, "output", ["node", "shell"]);
  const tabs = await tabState(page);
  if (tabs.length !== 2 || tabs[0].label !== `${LOGIN}@${FIRST_NODE}` || tabs[1].label !== `${LOGIN}@${SECOND_NODE}` || !tabs[1].selected) {
    fail(context, `the tabs after the second open are ${JSON.stringify(tabs)}`);
  }
  await page.locator(".term-pane:not([hidden]) .term-host").click();
  await typeLine(page, "echo second-$((6*7))");
  await shows(page, /^second-42$/m);
  await page.keyboard.press("Control+Alt+PageUp");
  await page.waitForFunction(() => document.querySelector('.ttabs [role="tab"]')?.getAttribute("aria-selected") === "true", null, { timeout: 5000 })
    .catch(() => fail(context, "Ctrl+Alt+PageUp did not select the first tab"));
  await typeLine(page, "echo first-$((6*7))");
  const firstText = await shows(page, /^first-42$/m);
  if (/second-42/.test(firstText)) {
    fail(context, "the first terminal shows what was typed into the second");
  }
  await expectPainted(page, context, "after Ctrl+Alt+PageUp showed the first tab again");
  await page.keyboard.press("Control+Alt+PageDown");
  await page.waitForFunction(() => document.querySelectorAll('.ttabs [role="tab"]')[1]?.getAttribute("aria-selected") === "true", null, { timeout: 5000 })
    .catch(() => fail(context, "Ctrl+Alt+PageDown did not select the second tab"));
  await expectPainted(page, context, "after Ctrl+Alt+PageDown showed the second tab again");
  const secondText = await visibleTerminalText(page);
  if (!/^second-42$/m.test(secondText) || /first-42/.test(secondText)) {
    fail(context, `the second terminal shows ${JSON.stringify(secondText.slice(-160))}`);
  }
  await shot(page, context, "workspace-two-tabs", { fullPage: false });
  found.push({ kind: "first", session: first }, { kind: "second", session: second });
  return { first, second, width, log };
}

async function closeWithConfirmation(session, context, id) {
  const { page } = session;
  const before = (await tabState(page)).length;
  await page.locator('[role="tab"][aria-selected="false"]').first().evaluate((tab) => tab.click());
  const label = (await tabState(page)).find((tab) => tab.selected).label;
  const narrow = (await page.viewportSize()).width < 640;
  if (narrow) {
    await pane(page).locator("button:has-text('More')").locator("visible=true").first().click();
    await page.locator('[role=menuitem]:has-text("Close terminal")').click();
  } else {
    await page.locator('.ttab.is-active button[data-close]').click();
  }
  const dialog = page.locator("[role=dialog]");
  await dialog.waitFor();
  const title = await dialog.locator("h2, .modal-title, header").first().innerText();
  if (!title.includes(`Close ${label}?`)) {
    fail(context, `the close question is ${JSON.stringify(title)}`);
  }
  await shot(page, context, "close-confirm");
  await dialog.locator(".btn:has-text('Keep open')").click();
  await dialog.waitFor({ state: "detached" });
  if ((await tabState(page)).length !== before) {
    fail(context, "Keep open closed the tab");
  }
  await closeActive(page, { confirm: true });
  const after = await tabState(page);
  if (after.length !== before - 1 || after.some((tab) => tab.label === label)) {
    fail(context, `after the close the tabs are ${JSON.stringify(after)}`);
  }
  results.push({ kind: "closed_by_user", session: id });
}

async function recentFlow(session, context, expected) {
  const { page } = session;
  await page.goto(`${ORIGIN}/#/sessions`);
  await page.waitForSelector("tbody tr");
  const refreshed = page.waitForResponse((response) => response.url().includes("/v1/web/terminal/recent"));
  await page.goto(`${ORIGIN}/#/terminal`);
  await refreshed;
  await page.goto(`${ORIGIN}/#/nodes`);
  await page.waitForSelector(".node-name");
  const recent = await page.locator("button.recent-btn .mono").allTextContents();
  for (const pair of expected) {
    if (!recent.includes(pair)) {
      fail(context, `the recent terminals ${JSON.stringify(recent)} lack ${pair}`);
    }
  }
  await shot(page, context, "nodes-recent");
  await page.locator(`button.recent-btn:has(.mono:text-is("${LOGIN}@${FIRST_NODE}"))`).click();
  await page.waitForSelector(".term-pane:not([hidden]) .term-host canvas", { timeout: WAIT_MS });
  await waitConnected(page);
  const tabs = await tabState(page);
  if (!tabs.some((tab) => tab.label === `${LOGIN}@${FIRST_NODE}` && tab.selected)) {
    fail(context, `a recent terminal did not open a selected tab: ${JSON.stringify(tabs)}`);
  }
}

async function fillToLimit(session, context) {
  const { page } = session;
  while ((await tabState(page)).length < SERVER_LIMIT) {
    const count = (await tabState(page)).length;
    await openAnother(page, count % 2 === 0 ? FIRST_NODE : SECOND_NODE, LOGIN);
    await waitConnected(page);
  }
  const countText = await page.locator(".tabbar-end [role=status], .switcher .count").locator("visible=true").first().innerText();
  if (!new RegExp(`\\b${SERVER_LIMIT}\\b`).test(countText)) {
    fail(context, `the tab count shows ${JSON.stringify(countText)} at the limit`);
  }
  if (!(await newTerminalButton(page).isDisabled())) {
    fail(context, "New terminal is enabled at the limit");
  }
}

async function limitRefusal(browser, width, context) {
  const second = await signIn(browser, OPERATOR, width);
  const { page, log } = second;
  await openInline(page, FIRST_NODE, LOGIN).catch(() => undefined);
  const banner = page.locator(".term-pane:not([hidden]) .term-banner");
  await banner.waitFor({ timeout: WAIT_MS });
  const text = await banner.innerText();
  const expected = new RegExp(`You have ${SERVER_LIMIT} terminals open, and ${SERVER_LIMIT} is the most allowed at once`);
  if (!/Too many terminals/.test(text) || !expected.test(text)) {
    fail(context, `the limit refusal reads ${JSON.stringify(text)}`);
  }
  const shown = await banner.locator(".ref .mono").textContent().catch(() => null);
  if (!DENIAL_REFERENCE.test(shown || "")) {
    fail(context, `the limit refusal shows the reference ${JSON.stringify(shown)}, expected D-XXXXXXXX`);
  } else {
    results.push({ kind: "limit", ref: shown });
  }
  const raw = await page.evaluate(async (node) => {
    const session = await (await fetch("/v1/web/session", { credentials: "same-origin" })).json();
    const response = await fetch("/v1/web/terminal/ticket", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Jaunt-Csrf": session.csrf_token },
      body: JSON.stringify({ node, login: "deploy" }),
    });
    return { status: response.status, body: await response.json() };
  }, FIRST_NODE);
  if (raw.status !== 429 || raw.body.error !== "limit" || raw.body.open !== SERVER_LIMIT || raw.body.max !== SERVER_LIMIT || !DENIAL_REFERENCE.test(raw.body.ref || "")) {
    fail(context, `CONTRACT the ticket refusal at the limit is ${raw.status} ${JSON.stringify(raw.body)}`);
  } else {
    results.push({ kind: "limit_raw", ref: raw.body.ref });
  }
  if (framesOf(log, "in").length !== 0) {
    fail(context, "a socket was opened after the ticket was refused");
  }
  await shot(page, context, "refusal-limit");
  await finish(`${context} second sign-in`, second);
}

async function sessionsFlow(session, context, victim) {
  const { page } = session;
  await page.goto(`${ORIGIN}/#/sessions`);
  await page.waitForSelector("tbody tr");
  const rowFor = (id) => page.locator(`tbody tr:has(a.name:text-is("${id.slice(0, 8)}"))`);
  const originOf = async (id) => (await rowFor(id).locator(".chip").first().innerText()).trim();
  if ((await originOf(victim)) !== "Web terminal") {
    fail(context, `the origin of the terminal session is ${JSON.stringify(await originOf(victim))}`);
  }
  await shot(page, context, "sessions");
  for (const [choice, expected] of [["Web terminal", "Web terminal"], ["ssh", "ssh"]]) {
    await page.locator("button.btn-menu:has-text('Origin:')").click();
    await page.locator(`[role=menuitemradio]:has-text("${choice}")`).click();
    await page.waitForFunction((value) => location.hash.includes(`origin=${value}`), choice === "ssh" ? "ssh" : "web", { timeout: 10000 });
    await page
      .waitForFunction(
        (wanted) => {
          const chips = Array.from(document.querySelectorAll("tbody .chip")).map((chip) => chip.textContent.trim());
          return chips.length > 0 && chips.every((chip) => chip === wanted);
        },
        expected,
        { timeout: 10000 },
      )
      .catch(async () => {
        const shown = (await page.locator("tbody .chip").allTextContents()).map((chip) => chip.trim());
        fail(context, `the origin filter "${choice}" shows ${JSON.stringify(shown)}`);
      });
  }
  await page.goto(`${ORIGIN}/#/sessions?origin=web`);
  await page.waitForSelector("tbody tr");
  await rowFor(victim).locator("button:has-text('Terminate')").click();
  const dialog = page.locator("[role=dialog]");
  await dialog.waitFor();
  const text = await dialog.innerText();
  if (!text.includes(`Terminate session ${victim.slice(0, 8)}?`) || !/Web terminal/.test(text) || !/within 5 seconds/.test(text)) {
    fail(context, `the terminate question reads ${JSON.stringify(text.slice(0, 300))}`);
  }
  await dialog.locator("input[type=text]").fill("end-to-end terminate");
  await shot(page, context, "terminate-confirm");
  await dialog.locator(".btn:has-text('Terminate session')").click();
  await dialog.waitFor({ state: "detached" });
  results.push({ kind: "terminated", session: victim, reason: "end-to-end terminate" });
}

async function terminatedTab(session, context, socket) {
  const { page, log } = session;
  await page.goto(`${ORIGIN}/#/terminal`);
  await page.waitForFunction(
    () => Array.from(document.querySelectorAll('.ttabs [role="tab"]')).some((tab) => /Ended/.test(tab.textContent)),
    null,
    { timeout: WAIT_MS },
  ).catch(() => fail(context, "no tab shows the ended state after Terminate"));
  const frame = framesOf(log, "in", socket).find(({ frame: item }) => item.t === "error");
  if (!frame || frame.frame.code !== "terminated") {
    fail(context, `CONTRACT the terminated session got the frame ${JSON.stringify(frame && frame.frame)}`);
  }
  const ended = page.locator(".ttabs [role=tab]:has(.visually-hidden)").filter({ hasText: /Ended/ }).first();
  await ended.evaluate((tab) => tab.click());
  const banner = await pane(page).locator(".term-banner").innerText();
  if (!/Ended by an administrator/.test(banner)) {
    fail(context, `the terminated tab says ${JSON.stringify(banner)}`);
  }
  const stateText = await pane(page).locator(".sess-head .item-state").innerText();
  if (!/Ended/.test(stateText)) {
    fail(context, `the state of the terminated tab is ${JSON.stringify(stateText)}`);
  }
  await shot(page, context, "terminated-tab");
}

async function closeAll(session, context) {
  const { page } = session;
  for (let guardCount = 0; guardCount < SERVER_LIMIT + 2; guardCount += 1) {
    const tabs = await tabState(page);
    if (tabs.length === 0) {
      break;
    }
    const live = tabs.find((tab) => tab.selected) || tabs[0];
    const confirm = !/Ended|Not opened/.test(live.words);
    await closeActive(page, { confirm });
    results.push({ kind: confirm ? "closed_by_user_final" : "closed_ended", label: live.label });
  }
  await page.waitForSelector(".panel.quick", { timeout: WAIT_MS }).catch(() => fail(context, "quick open did not come back after the last tab was closed"));
}

async function watchIdle(browser, width, context) {
  const session = await signIn(browser, IDLE_USER, width);
  const { page, log } = session;
  await openInline(page, FIRST_NODE, LOGIN);
  await waitConnected(page);
  const ready = readyOf(log, 0);
  const opened = Date.now();
  const done = (async () => {
    let seen = null;
    await page.waitForSelector(".term-pane:not([hidden]) .term-banner .banner-title:has-text('This terminal closes in')", { timeout: IDLE_WAIT_MS })
      .then(() => {
        seen = Date.now() - opened;
      })
      .catch(() => fail(context, `no idle warning within ${IDLE_WAIT_MS / 1000} s`));
    if (seen !== null) {
      await shot(page, context, "idle-warning");
      const frame = framesOf(log, "in", 0).find(({ frame: item }) => item.t === "idle");
      if (!frame || !(frame.frame.seconds_left > 0 && frame.frame.seconds_left <= 120)) {
        fail(context, `CONTRACT the idle frame is ${JSON.stringify(frame && frame.frame)}`);
      }
      await page.locator(".term-pane:not([hidden]) .term-banner .btn:has-text('Keep open')").click();
      await page.waitForFunction(() => !/closes in/.test(document.querySelector(".term-pane:not([hidden]) .term-banner")?.textContent || ""), null, { timeout: 10000 })
        .catch(() => fail(context, "the idle warning stayed after Keep open"));
      const sent = framesOf(log, "out", 0).filter(({ frame: item }) => item.t === "active");
      if (sent.length !== 1) {
        fail(context, `Keep open sent ${sent.length} active frames`);
      }
      await page.waitForTimeout(500);
      const state = await pane(page).locator(".sess-head .item-state").innerText();
      if (!/Connected/.test(state)) {
        fail(context, `after Keep open the state is ${JSON.stringify(state)}`);
      }
    }
    const pongs = framesOf(log, "in", 0).filter(({ frame: item }) => item.t === "pong");
    if (!pongs.some(({ frame: item }) => Number.isInteger(item.node_ms) || typeof item.node_ms === "number")) {
      fail(context, `CONTRACT no pong carried node_ms in ${pongs.length} pongs`);
    }
    if (ready) {
      results.push({ kind: "idle", session: ready.session_id, warned_after_ms: seen });
    }
    await closeAll(session, context);
    await finish(`${context} idle user`, session);
  })();
  return { done };
}

async function width(browser, size) {
  const context = `ws-${size}`;
  const idle = await watchIdle(browser, size, `${context}-idle`);
  const session = await signIn(browser, OPERATOR, size);
  const found = [];
  const { page } = session;
  await guard(context, "contract", () => contract(page, context));
  await guard(context, "pin", () => pinFlow(page, context));
  await guard(context, "quick open order", () => quickOpenOrder(page, context));
  const opened = await guard(context, "open and switch", () => openingAndSwitching(session, context, size, found));
  if (opened) {
    await guard(context, "close with confirmation", () => closeWithConfirmation(session, context, opened.first));
    await guard(context, "recent", () => recentFlow(session, context, [`${LOGIN}@${FIRST_NODE}`, `${LOGIN}@${SECOND_NODE}`]));
  }
  await guard(context, "fill to the limit", () => fillToLimit(session, context));
  await guard(context, "limit refusal", () => limitRefusal(browser, size, context));
  const readies = framesOf(session.log, "in").filter(({ frame }) => frame.t === "ready");
  const victim = readies.length > 0 ? readies[readies.length - 1] : null;
  if (victim) {
    await guard(context, "sessions", () => sessionsFlow(session, context, victim.frame.session_id));
    await guard(context, "terminated tab", () => terminatedTab(session, context, victim.socket));
  } else {
    fail(context, "no session to terminate");
  }
  await guard(context, "close everything", () => closeAll(session, context));
  await guard(context, "unpin", () => unpin(page));
  await idle.done;
  await finish(context, session);
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const browser = await chromium.launch({
    args: [`--host-resolver-rules=MAP jaunt.e2e.test 127.0.0.1:${WEB_PORT}, MAP idp.e2e.test 127.0.0.1:${IDP_PORT}`],
  });
  try {
    for (const size of WIDTHS) {
      await width(browser, size);
    }
  } finally {
    await browser.close();
    await writeFile(RESULT_FILE, JSON.stringify({ results }));
  }
  console.log(`workspace results recorded: ${results.length}`);
  if (failures.length > 0) {
    console.error(`${failures.length} failure(s):`);
    for (const entry of failures) {
      console.error(` - ${entry}`);
    }
    process.exitCode = 1;
  } else {
    console.log("the terminal workspace browser run passed");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
