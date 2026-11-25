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
const SESSION = required("E2E_RECORDED_SESSION");
const TYPED = required("E2E_TYPED_TEXT");
const failures = [];
const seen = [];

function fail(context, message) {
  failures.push(`${context}: ${message}`);
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
      return null;
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

async function painted(page) {
  return page.evaluate(() => {
    let count = 0;
    for (const canvas of document.querySelectorAll(".player-screen canvas")) {
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

async function run(browser, width) {
  const context = `recording-${width}`;
  const browserContext = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width, height: width < 600 ? 800 : 900 },
    deviceScaleFactor: 1,
  });
  await instrument(browserContext);
  const priming = await browserContext.newPage();
  await priming.goto(IDP_PRIME);
  await priming.close();
  const page = await browserContext.newPage();
  const problems = [];
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
  await page.goto(`${ORIGIN}/`);
  await page.waitForSelector("a.btn-primary");
  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });
  await page.goto(`${ORIGIN}/#/sessions/${SESSION}`);
  await page.waitForSelector("button:has-text('Watch recording')");
  await page.screenshot({ path: `${OUT}${context}-session-detail.png`, fullPage: true });
  seen.push(`${context} session-detail`);
  await page.click("button:has-text('Watch recording')");
  await page.waitForSelector(".player-screen canvas");
  await page.locator(".player-screen").scrollIntoViewIfNeeded();
  await page.click("button:text-is('Play')");
  await page.waitForFunction(() => /Finished/.test(document.querySelector(".player .visually-hidden[role=status]")?.textContent || ""), null, { timeout: 60000 });
  const text = await terminalText(page);
  if (text === null) {
    fail(context, "no Terminal instance was captured: xterm is not exposed as a global `Terminal` (the capture must be updated if the console bundles it as a module), so the screen text cannot be read");
  } else if (!text.includes(TYPED)) {
    fail(context, `the typed text ${TYPED} is not on the terminal screen: ${JSON.stringify(text.slice(-300))}`);
  }
  await page.locator(".player-screen").scrollIntoViewIfNeeded();
  await page.waitForTimeout(800);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (overflow > 0) {
    fail(context, `the page overflows horizontally by ${overflow}px after the player finished`);
  }
  const pixels = await painted(page);
  if (pixels < 500) {
    fail(context, `the terminal canvas has no painted text (${pixels} light pixels)`);
  }
  await page.screenshot({ path: `${OUT}${context}-player.png`, fullPage: true });
  seen.push(`${context} player`);
  const violations = await page.evaluate(() => window.__csp);
  for (const violation of violations) {
    fail(context, `CSP violation: ${violation}`);
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
    for (const width of WIDTHS) {
      await run(browser, width);
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
    console.log("the recorded session played in the real console");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
