import { mkdir } from "node:fs/promises";
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
const failures = [];
const seen = [];

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
  page.on("console", (message) => {
    if (message.type() === "error" && !/status of (401|429)/.test(message.text())) {
      problems.push(`console: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => problems.push(`pageerror: ${error.message}`));
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
      await run(browser, width, index);
    }
  } finally {
    await browser.close();
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
