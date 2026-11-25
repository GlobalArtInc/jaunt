import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const ORIGIN = "https://jaunt.e2e.test";
const IDP_PRIME =
  "https://idp.e2e.test/authorize?response_type=code&client_id=jaunt-e2e&code_challenge=e2e-test-only-challenge&code_challenge_method=S256" +
  "&redirect_uri=https%3A%2F%2Fjaunt.e2e.test%2Fv1%2Flogin%2Fcallback&state=e2e-prime&login_hint=admin";
const WIDTHS = [380, 1440];
const OUT = process.env.E2E_SCREENSHOTS || fileURLToPath(new URL("../../target/e2e/screenshots/", import.meta.url));

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set; run this through \`just e2e-web\``);
  }
  return value;
}

const WEB_PORT = required("E2E_WEB_PORT");
const IDP_PORT = required("E2E_IDP_PORT");
const PENDING = required("E2E_PENDING").split(",").map((pair) => pair.split(":"));
const REVOKE = required("E2E_REVOKE_USERS").split(",");
const TERMINAL_USER = required("E2E_TERMINAL_USER");
const TERMINAL_OUT = required("E2E_TERMINAL_OUT");
const TERMINAL_WAIT_MS = 30000;
const failures = [];
const seen = [];
const terminals = [];

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
  seen.push(`${context} ${name}`);
}

async function signIn(page, context) {
  await page.goto(`${ORIGIN}/`);
  await page.waitForSelector("a.btn-primary");
  await shot(page, context, "signin");
  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });
  if (!page.url().endsWith("#/nodes")) {
    fail(context, `sign-in did not land on the nodes screen: ${page.url()}`);
  }
}

async function listNodes(page, context) {
  await page.waitForSelector(".node-card");
  const text = await page.innerText(".node-grid");
  for (const name of ["node-a", "node-b"]) {
    if (!text.includes(name)) {
      fail(context, `the node list does not show ${name}: ${text.slice(0, 200)}`);
    }
  }
  await shot(page, context, "nodes");
}

async function approvePending(page, context, code, name) {
  await page.goto(`${ORIGIN}/#/approve`);
  await page.waitForSelector("input.code-input");
  await page.fill("input.code-input", code);
  await page.click("button:has-text('Continue')");
  await page.waitForSelector("text=Is this the server you expect?");
  await shot(page, context, "approve-check");
  await page.click(`button:has-text('Approve ${name}')`);
  await page.waitForSelector("text=is approved");
  await shot(page, context, "approve-done");
}

async function sessionsShow(page, context, expectState) {
  await page.goto(`${ORIGIN}/#/sessions`);
  await page.waitForSelector("tbody tr");
  const text = await page.innerText("tbody");
  if (!text.includes("node-a") || !text.includes("deploy")) {
    fail(context, `the session list does not show the session on node-a: ${text.slice(0, 200)}`);
  }
  if (expectState && !new RegExp(`\\b${expectState}\\b`, "i").test(text)) {
    fail(context, `no ${expectState} session in the list: ${text.slice(0, 300)}`);
  }
  await shot(page, context, `sessions-${expectState || "list"}`);
}

async function revoke(page, context, subject) {
  await page.goto(`${ORIGIN}/#/revocations`);
  await page.waitForSelector("button:has-text('New revocation')");
  await page.click("button:has-text('New revocation')");
  await page.waitForSelector("[role=dialog]");
  await page.fill("#revoke-subject", subject);
  await page.fill("#revoke-reason", "revoked from the end-to-end browser run");
  await shot(page, context, "revoke-form");
  await page.click("[role=dialog] button:has-text('Review effect')");
  await page.waitForSelector("#revoke-understand");
  await page.check("#revoke-understand");
  await shot(page, context, "revoke-review");
  await page.click("[role=dialog] button:has-text('Revoke now')");
  await page.waitForSelector(`tbody >> text=${subject}`);
  const text = await page.innerText("tbody");
  if (!text.includes(subject)) {
    fail(context, `the revocation of ${subject} is not listed: ${text.slice(0, 300)}`);
  }
  await shot(page, context, "revocations");
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
  const deadline = Date.now() + TERMINAL_WAIT_MS;
  let text = "";
  while (Date.now() < deadline) {
    text = await terminalText(page);
    const found = text.match(pattern);
    if (found) {
      return found;
    }
    await page.waitForTimeout(100);
  }
  fail(context, `${what} did not appear in the terminal within ${TERMINAL_WAIT_MS / 1000} s: ${JSON.stringify(text.slice(-300))}`);
  return null;
}

async function typeLine(page, line) {
  await page.keyboard.type(line);
  await page.keyboard.press("Enter");
}

async function terminalSize(page) {
  return page.evaluate(() => {
    const terminal = window.__terminals[window.__terminals.length - 1];
    return terminal ? `${terminal.rows}x${terminal.cols}` : "";
  });
}

async function webTerminal(browser, width) {
  const context = `terminal-${width}`;
  const height = width < 600 ? 800 : 900;
  const browserContext = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height }, deviceScaleFactor: 1 });
  await instrument(browserContext);
  const priming = await browserContext.newPage();
  await priming.goto(IDP_PRIME.replace("login_hint=admin", `login_hint=${encodeURIComponent(TERMINAL_USER)}`));
  await priming.close();
  const page = await browserContext.newPage();
  const problems = [];
  watch(page, problems);
  await page.goto(`${ORIGIN}/`);
  await page.waitForSelector("a.btn-primary");
  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });
  await page.goto(`${ORIGIN}/#/terminal`);
  await page.waitForSelector('input[name="terminal-node"]');
  await page.click('label.pick-card:has(input[value="node-a"])');
  await page.click('label.pick-login:has(input[value="deploy"])');
  await shot(page, context, "terminal-picker");
  await page.click("button:has-text('Open terminal')");
  await page.waitForSelector(".term-host canvas");
  await page.waitForFunction(() => /Connected/.test(document.querySelector(".statusbar [role=status]")?.textContent || ""), null, { timeout: TERMINAL_WAIT_MS });
  await page.click(".term-host");
  await typeLine(page, "echo hello-$((6*7))");
  await terminalShows(page, context, "hello-42", /^hello-42$/m);
  await typeLine(page, "seq 1 200000 | tail -n 1");
  await terminalShows(page, context, "200000", /^200000$/m);
  await shot(page, context, "terminal-session");
  await typeLine(page, "echo size-before-$(stty size | tr ' ' x)");
  const before = await terminalShows(page, context, "the size before the resize", /^size-before-(\d+x\d+)$/m);
  const shown = await terminalSize(page);
  if (before && before[1] !== shown) {
    fail(context, `the shell sees ${before[1]} while the page shows ${shown}`);
  }
  await page.setViewportSize(width < 600 ? { width, height: height - 240 } : { width: width - 360, height: height - 200 });
  const resizeDeadline = Date.now() + TERMINAL_WAIT_MS;
  while ((await terminalSize(page)) === shown && Date.now() < resizeDeadline) {
    await page.waitForTimeout(100);
  }
  const resized = await terminalSize(page);
  if (resized === shown) {
    fail(context, `the terminal kept ${shown} after the window was resized`);
  }
  await typeLine(page, "echo size-after-$(stty size | tr ' ' x)");
  const after = await terminalShows(page, context, "the size after the resize", /^size-after-(\d+x\d+)$/m);
  if (after && after[1] !== resized) {
    fail(context, `after the resize the shell sees ${after[1]} while the page shows ${resized}`);
  }
  await typeLine(page, "exit");
  await page.waitForSelector(".term-banner:has-text('Session ended')", { timeout: TERMINAL_WAIT_MS });
  const ended = await page.textContent(".term-banner");
  if (!/exited with status 0/.test(ended)) {
    fail(context, `the ended banner says: ${ended.slice(0, 160)}`);
  }
  const session = await page.evaluate(() => {
    for (const paragraph of document.querySelectorAll("p")) {
      const id = paragraph.querySelector(".mono");
      if (id && /^Session: /.test(paragraph.textContent)) {
        return id.textContent.trim();
      }
    }
    return null;
  });
  if (!session) {
    fail(context, "the ended screen does not name the session");
  } else {
    terminals.push({ width, session });
  }
  await shot(page, context, "terminal-ended");
  for (const violation of await page.evaluate(() => window.__csp)) {
    problems.push(`CSP violation: ${violation}`);
  }
  for (const problem of problems) {
    fail(context, problem);
  }
  await browserContext.close();
}

async function run(browser, width, index) {
  const context = `real-${width}`;
  const browserContext = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width, height: width < 600 ? 800 : 900 },
    deviceScaleFactor: 1,
  });
  const priming = await browserContext.newPage();
  await priming.goto(IDP_PRIME);
  await priming.close();
  const page = await browserContext.newPage();
  const problems = [];
  watch(page, problems);
  await signIn(page, context);
  await listNodes(page, context);
  const [code, name] = PENDING[index];
  await approvePending(page, context, code, name);
  await sessionsShow(page, context, index === 0 ? "live" : null);
  await revoke(page, context, REVOKE[index]);
  if (index === 0) {
    await sessionsShow(page, context, "ended");
  }
  for (const problem of problems) {
    fail(context, problem);
  }
  await browserContext.close();
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const browser = await chromium.launch({
    args: [`--host-resolver-rules=MAP jaunt.e2e.test 127.0.0.1:${WEB_PORT}, MAP idp.e2e.test 127.0.0.1:${IDP_PORT}`],
  });
  try {
    for (const [index, width] of WIDTHS.entries()) {
      await webTerminal(browser, width);
      await run(browser, width, index);
    }
  } finally {
    await browser.close();
    await writeFile(TERMINAL_OUT, JSON.stringify({ sessions: terminals }));
  }
  console.log(`screens captured: ${seen.length}`);
  console.log(`screenshots: ${OUT}`);
  if (failures.length > 0) {
    console.error(`${failures.length} failure(s):`);
    for (const entry of failures) {
      console.error(` - ${entry}`);
    }
    process.exitCode = 1;
  } else {
    console.log("the real-stack browser run passed");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
