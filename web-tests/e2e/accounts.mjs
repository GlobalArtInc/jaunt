import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const ORIGIN = "https://jaunt.e2e.test";
const IDP_PRIME =
  "https://idp.e2e.test/authorize?response_type=code&client_id=jaunt-e2e&code_challenge=e2e-test-only-challenge&code_challenge_method=S256" +
  "&redirect_uri=https%3A%2F%2Fjaunt.e2e.test%2Fv1%2Flogin%2Fcallback&state=e2e-prime&login_hint=";
const WIDTHS = [380, 1440];
const OUT = process.env.E2E_SCREENSHOTS || fileURLToPath(new URL("../../target/e2e/screenshots/", import.meta.url));
const CREATING_NODE = "node-a";
const PLAIN_NODE = "node-b";
const WAIT_MS = 45000;
const REFERENCE = /^H-[0-9A-F]{8}$/;
const TERMINAL_WORDS = ["Creating your account", "Account created", "could not be created", "There is no account"];

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set; run this through \`just e2e-web\``);
  }
  return value;
}

const WEB_PORT = required("E2E_WEB_PORT");
const IDP_PORT = required("E2E_IDP_PORT");
const USER = required("E2E_ACCOUNT_USER");
const ADMIN = required("E2E_ACCOUNT_ADMIN");
const RESULT_FILE = required("E2E_ACCOUNTS_OUT");
const LOGINS = JSON.parse(required("E2E_ACCOUNT_LOGINS"));
const failures = [];
const results = [];

function fail(context, message) {
  failures.push(`${context}: ${message}`);
}

async function shot(page, context, name) {
  await page.waitForTimeout(100);
  await page.screenshot({ path: `${OUT}${context}-${name}.png`, fullPage: true });
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

async function instrument(browserContext) {
  await browserContext.addInitScript(() => {
    window.__csp = [];
    window.__terminals = [];
    document.addEventListener("securitypolicyviolation", (event) => window.__csp.push(`${event.violatedDirective} ${event.blockedURI}`));
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

async function terminalText(page) {
  return page.evaluate(() => {
    const terminal = window.__terminals[window.__terminals.length - 1];
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

async function terminalShows(page, context, what, pattern) {
  const deadline = Date.now() + WAIT_MS;
  let text = "";
  while (Date.now() < deadline) {
    text = await terminalText(page);
    const found = text.match(pattern);
    if (found) {
      return found;
    }
    await page.waitForTimeout(100);
  }
  fail(context, `${what} did not appear in the terminal: ${JSON.stringify(text.slice(-300))}`);
  return null;
}

async function typeLine(page, line) {
  await page.keyboard.type(line);
  await page.keyboard.press("Enter");
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
  const frames = [];
  page.on("websocket", (socket) => {
    socket.on("framereceived", (frame) => {
      if (typeof frame.payload === "string") {
        frames.push(frame.payload);
      }
    });
  });
  await page.goto(`${ORIGIN}/`);
  await page.waitForSelector("a.btn-primary");
  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });
  return { browserContext, page, problems, frames };
}

async function nodeMarkers(browser, width) {
  const context = `accounts-nodes-${width}`;
  const { browserContext, page, problems } = await signIn(browser, ADMIN, width);
  await page.goto(`${ORIGIN}/#/nodes`);
  await page.waitForSelector(".node-card");
  await page.waitForFunction(
    (name) => [...document.querySelectorAll(".node-card")].some((card) => card.textContent.includes(name) && card.querySelector(".badge.b-acct")),
    CREATING_NODE,
    { timeout: WAIT_MS },
  ).catch(() => fail(context, `the ${CREATING_NODE} card has no Creates accounts marker`));
  const marked = await page.locator(".node-card:has(.badge.b-acct) .node-name").allTextContents();
  if (marked.join(",") !== CREATING_NODE) {
    fail(context, `the cards with the marker are ${JSON.stringify(marked)}`);
  }
  const badge = await page.locator(".node-card .badge.b-acct").first().textContent();
  if (!/Creates accounts/.test(badge || "")) {
    fail(context, `the marker says ${JSON.stringify(badge)}`);
  }
  await shot(page, context, "nodes");
  for (const problem of problems) {
    fail(context, problem);
  }
  await browserContext.close();
}

async function openTerminal(page, node, login) {
  await page.goto(`${ORIGIN}/#/terminal?node=${node}&login=${login}`);
  await page.waitForSelector('input[name="terminal-node"]');
  await page.waitForSelector(`input[name="terminal-login"][value="${login}"]`);
  await page.click("button:has-text('Open terminal')");
}

async function sessionOf(page) {
  return page.evaluate(() => {
    for (const paragraph of document.querySelectorAll("p")) {
      const id = paragraph.querySelector(".mono");
      if (id && /^Session: /.test(paragraph.textContent)) {
        return id.textContent.trim();
      }
    }
    return null;
  });
}

function errorFrame(frames, from) {
  for (const payload of frames.slice(from)) {
    try {
      const parsed = JSON.parse(payload);
      if (parsed.t === "error") {
        return parsed;
      }
    } catch {
      continue;
    }
  }
  return null;
}

async function picker(page, context) {
  await page.goto(`${ORIGIN}/#/terminal`);
  await page.waitForSelector('input[name="terminal-node"]');
  const marked = await page.locator("label.pick-card .badge.b-acct").evaluateAll((nodes) => nodes.map((node) => node.closest("label").querySelector("input").value));
  if (marked.join(",") !== CREATING_NODE) {
    fail(context, `the Creates accounts marker on the picker is on ${JSON.stringify(marked)}`);
  }
  await page.click(`label.pick-card:has(input[value="${CREATING_NODE}"])`);
  await page.waitForSelector("p.muted.small:has-text('creates your account at your first login')", { timeout: WAIT_MS })
    .catch(() => fail(context, "the picker does not explain the first login"));
  await shot(page, context, "picker");
}

async function createdLogin(session, width, login) {
  const { page, frames } = session;
  const context = `accounts-created-${width}`;
  const before = frames.length;
  await openTerminal(page, CREATING_NODE, login);
  await page.waitForSelector(`.term-banner:has-text('Creating your account ${login} on ${CREATING_NODE}')`, { timeout: WAIT_MS })
    .catch(() => fail(context, "no creating banner"));
  const state = await page.textContent(".statusbar [role=status]").catch(() => "");
  if (!/Creating account/.test(state || "")) {
    fail(context, `the status says ${JSON.stringify(state)} while the account is created`);
  }
  await shot(page, context, "creating");
  await page.waitForSelector(".term-banner:has-text('Account created.')", { timeout: WAIT_MS }).catch(() => fail(context, "no created banner"));
  await page.waitForFunction(() => /Connected/.test(document.querySelector(".statusbar [role=status]")?.textContent || ""), null, { timeout: WAIT_MS });
  const banner = await page.locator(".term-banner").first().textContent();
  if (!(banner || "").includes(`/home/${login}`)) {
    fail(context, `the created banner lacks the home directory: ${JSON.stringify(banner)}`);
  }
  const ready = frames.slice(before).map((payload) => {
    try {
      return JSON.parse(payload);
    } catch {
      return {};
    }
  }).find((frame) => frame.t === "ready");
  if (!ready || ready.account_created !== true || ready.home !== `/home/${login}`) {
    fail(context, `the ready frame is ${JSON.stringify(ready)}`);
  }
  const beforeTyping = await terminalText(page);
  for (const word of TERMINAL_WORDS) {
    if (beforeTyping.includes(word)) {
      fail(context, `the console wrote ${JSON.stringify(word)} into the terminal area`);
    }
  }
  await shot(page, context, "created");
  await page.click(".term-banner button:has-text('Dismiss')");
  if ((await page.locator(".term-banner").first().textContent()) !== "") {
    fail(context, "the created banner was not dismissed");
  }
  await page.click(".term-host");
  await typeLine(page, "echo whoami-$(id -un)");
  await terminalShows(page, context, `whoami-${login}`, new RegExp(`^whoami-${login}$`, "m"));
  await typeLine(page, "echo uid-$(id -u)");
  const uid = await terminalShows(page, context, "the uid", /^uid-(\d+)$/m);
  await typeLine(page, "exit");
  await page.waitForSelector(".term-banner:has-text('Session ended')", { timeout: WAIT_MS });
  const after = await terminalText(page);
  for (const word of TERMINAL_WORDS) {
    if (after.includes(word)) {
      fail(context, `the console wrote ${JSON.stringify(word)} into the terminal area at the end`);
    }
  }
  results.push({ width, kind: "created", node: CREATING_NODE, login, session: await sessionOf(page), uid: uid ? Number(uid[1]) : null });
}

async function refusedLogin(session, width, node, login, code, title) {
  const { page, frames } = session;
  const context = `accounts-${code}-${width}`;
  const before = frames.length;
  await openTerminal(page, node, login);
  await page.waitForSelector(`.term-banner:has-text('${title}')`, { timeout: WAIT_MS }).catch(() => fail(context, `no banner "${title}" for ${login}`));
  const frame = errorFrame(frames, before);
  if (!frame || frame.code !== code) {
    fail(context, `the error frame is ${JSON.stringify(frame)}`);
  }
  const shown = await page.locator(".term-banner .ref .mono").textContent().catch(() => null);
  if (!REFERENCE.test(shown || "") || !frame || shown !== frame.ref) {
    fail(context, `the banner shows ${JSON.stringify(shown)} while the error frame carries ${JSON.stringify(frame && frame.ref)}`);
  }
  const text = await terminalText(page);
  for (const word of TERMINAL_WORDS) {
    if (text.includes(word)) {
      fail(context, `the console wrote ${JSON.stringify(word)} into the terminal area`);
    }
  }
  await shot(page, context, "refused");
  results.push({ width, kind: code, node, login, ref: frame ? frame.ref : null, banner_ref: shown, session: await sessionOf(page) });
}

async function terminals(browser, width) {
  const context = `accounts-terminal-${width}`;
  const session = await signIn(browser, USER, width);
  await picker(session.page, context);
  await createdLogin(session, width, LOGINS.created[width]);
  await refusedLogin(session, width, CREATING_NODE, LOGINS.reserved, "account_refused", "Your account could not be created.");
  await refusedLogin(session, width, CREATING_NODE, LOGINS.group, "account_refused", "Your account could not be created.");
  await refusedLogin(session, width, PLAIN_NODE, LOGINS.off, "no_account", `There is no account ${LOGINS.off} on ${PLAIN_NODE}.`);
  for (const violation of await session.page.evaluate(() => window.__csp)) {
    session.problems.push(`CSP violation: ${violation}`);
  }
  for (const problem of session.problems) {
    fail(context, problem);
  }
  await session.browserContext.close();
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const browser = await chromium.launch({
    args: [`--host-resolver-rules=MAP jaunt.e2e.test 127.0.0.1:${WEB_PORT}, MAP idp.e2e.test 127.0.0.1:${IDP_PORT}`],
  });
  try {
    for (const width of WIDTHS) {
      await nodeMarkers(browser, width);
      await terminals(browser, width);
    }
  } finally {
    await browser.close();
    await writeFile(RESULT_FILE, JSON.stringify({ results }));
  }
  console.log(`account steps recorded: ${results.length}`);
  if (failures.length > 0) {
    console.error(`${failures.length} failure(s):`);
    for (const entry of failures) {
      console.error(` - ${entry}`);
    }
    process.exitCode = 1;
  } else {
    console.log("the account creation browser run passed");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
