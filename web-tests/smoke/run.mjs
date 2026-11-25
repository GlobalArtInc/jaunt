import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { startStub } from "./stub.mjs";

const OUT = fileURLToPath(new URL("../screenshots-out/", import.meta.url));
const ALL = ["nodes.approve", "sessions.read", "recordings.read", "revocations.write", "audit.read"];
const WIDTHS = [380, 1440];
const THEMES = ["light", "dark"];

const TEXT_PAIRS = [
  ["--text", "--bg"], ["--text", "--surface"], ["--text", "--surface-2"], ["--text-muted", "--bg"], ["--text-muted", "--surface"], ["--text-muted", "--surface-2"],
  ["--accent", "--bg"], ["--accent", "--surface"], ["--accent", "--accent-weak"], ["--on-accent", "--accent"], ["--text", "--accent-weak"],
  ["--ok", "--ok-weak"], ["--warn", "--warn-weak"], ["--danger", "--danger-weak"], ["--ok", "--bg"], ["--warn", "--bg"], ["--danger", "--bg"], ["--danger", "--surface"],
  ["--text", "--warn-weak"], ["--text", "--danger-weak"], ["--text", "--ok-weak"], ["--on-danger", "--danger-fill"],
];
const NON_TEXT_PAIRS = [["--border-strong", "--bg"], ["--border-strong", "--surface"], ["--focus", "--bg"], ["--focus", "--surface"]];

let touchChecked = 0;
const failures = [];
const report = [];

function fail(context, message) {
  failures.push(context + ": " + message);
}

function luminance(hex) {
  const value = hex.trim().replace("#", "");
  const channels = [0, 2, 4].map((offset) => parseInt(value.slice(offset, offset + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function ratio(first, second) {
  const [high, low] = [luminance(first), luminance(second)].sort((a, b) => b - a);
  return (high + 0.05) / (low + 0.05);
}

async function tokenContrast(page, context) {
  const tokens = await page.evaluate(() => {
    const style = getComputedStyle(document.documentElement);
    return Object.fromEntries(Array.from(new Set(["--text", "--bg", "--surface", "--surface-2", "--text-muted", "--accent", "--accent-weak", "--on-accent", "--ok", "--ok-weak", "--warn", "--warn-weak", "--danger", "--danger-weak", "--danger-fill", "--on-danger", "--border-strong", "--focus"])).map((name) => [name, style.getPropertyValue(name)]));
  });
  for (const [foreground, background] of TEXT_PAIRS) {
    const value = ratio(tokens[foreground], tokens[background]);
    if (value < 4.5) fail(context, `${foreground} on ${background} is ${value.toFixed(2)}`);
  }
  for (const [foreground, background] of NON_TEXT_PAIRS) {
    const value = ratio(tokens[foreground], tokens[background]);
    if (value < 3) fail(context, `${foreground} on ${background} is ${value.toFixed(2)}`);
  }
}

async function layoutChecks(page, context) {
  const result = await page.evaluate(() => {
    const secondary = ".small, .muted, .badge, .chip, th, dt, label, legend, .field-hint, .sub, .crumbs, .nav-count, .who, .server, .num, .steps, .code, caption, .step-list li, .nav-group";
    const small = [];
    const lowContrast = [];
    const parse = (value) => {
      const match = /rgba?\(([^)]+)\)/.exec(value);
      if (!match) return null;
      const parts = match[1].split(/[ ,\/]+/).filter(Boolean).map(Number);
      return { rgb: parts.slice(0, 3), alpha: parts.length > 3 ? parts[3] : 1 };
    };
    const lum = (rgb) => {
      const [r, g, b] = rgb.map((c) => c / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const backgroundOf = (element) => {
      for (let node = element; node; node = node.parentElement) {
        const color = parse(getComputedStyle(node).backgroundColor);
        if (color && color.alpha === 1) return color.rgb;
      }
      return [255, 255, 255];
    };
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const seen = new Set();
    while (walker.nextNode()) {
      const text = walker.currentNode;
      const element = text.parentElement;
      if (!element || seen.has(element) || text.data.trim() === "" || element.closest("[hidden]") || element.closest(".visually-hidden") || element.closest("[inert]") && !element.closest(".scrim")) continue;
      const style = getComputedStyle(element);
      if (style.display === "none" || style.visibility === "hidden") continue;
      const rect = element.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) continue;
      seen.add(element);
      const size = parseFloat(style.fontSize);
      const minimum = element.closest(secondary) || element.closest("pre") ? 13 : 14;
      if (size < minimum) small.push(`${element.tagName.toLowerCase()}.${element.className} ${size}px < ${minimum}px "${text.data.trim().slice(0, 30)}"`);
      const foreground = parse(style.color);
      if (!foreground) continue;
      const back = backgroundOf(element);
      const high = Math.max(lum(foreground.rgb), lum(back));
      const low = Math.min(lum(foreground.rgb), lum(back));
      const contrast = (high + 0.05) / (low + 0.05);
      const needed = element.closest("[disabled]") ? 3 : 4.5;
      if (contrast < needed) lowContrast.push(`${element.tagName.toLowerCase()}.${element.className} ${contrast.toFixed(2)} "${text.data.trim().slice(0, 30)}"`);
    }
    const controls = Array.from(document.querySelectorAll("input:not([type=hidden]):not([type=checkbox]):not([type=radio]), select, textarea, button")).filter((control) => control.getBoundingClientRect().width > 0 && !control.closest("[inert]"));
    const smallControls = controls.filter((control) => parseFloat(getComputedStyle(control).fontSize) < 14).map((control) => control.tagName.toLowerCase() + "." + control.className);
    const touch = [];
    let checked = 0;
    if (window.innerWidth <= 520) {
      const targets = document.querySelectorAll("button, a.btn, select, textarea, input:not([type=hidden]):not([type=checkbox]):not([type=radio]), .mainnav a, table.data a, .crumbs a, a.chip");
      for (const target of targets) {
        const rect = target.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0 || rect.bottom <= 0 || rect.top < -50 || target.closest(".visually-hidden") || target.classList.contains("skip")) continue;
        if (target.closest("[inert]") && !target.closest(".scrim")) continue;
        checked += 1;
        if (rect.height < 43.5) touch.push(target.tagName.toLowerCase() + "." + target.className + " " + rect.height.toFixed(1) + "px");
      }
    }
    return {
      touch: touch.slice(0, 8),
      touchChecked: checked,
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      small: small.slice(0, 8),
      lowContrast: lowContrast.slice(0, 8),
      smallControls,
    };
  });
  if (result.overflow > 0) fail(context, `document overflows horizontally by ${result.overflow}px`);
  for (const entry of result.small) fail(context, "text below the minimum size: " + entry);
  for (const entry of result.lowContrast) fail(context, "rendered text contrast below 4.5: " + entry);
  touchChecked += result.touchChecked;
  for (const entry of result.touch) fail(context, "touch target below 44px: " + entry);
  for (const entry of result.smallControls) fail(context, "control font below 14px: " + entry);
}

async function focusRing(page, context) {
  await page.evaluate(() => document.activeElement && document.activeElement.blur && document.activeElement.blur());
  let checked = 0;
  for (let step = 0; step < 4; step += 1) {
    await page.keyboard.press("Tab");
    const ring = await page.evaluate(() => {
      const active = document.activeElement;
      if (!active || active === document.body) return null;
      const style = getComputedStyle(active);
      return { style: style.outlineStyle, width: parseFloat(style.outlineWidth), color: style.outlineColor, tag: active.tagName.toLowerCase(), text: (active.textContent || "").trim().slice(0, 20) };
    });
    if (!ring) continue;
    checked += 1;
    if (ring.style === "none" || ring.width < 2 || /rgba\(0, 0, 0, 0\)/.test(ring.color)) fail(context, `no visible focus ring on ${ring.tag} "${ring.text}": ${JSON.stringify(ring)}`);
  }
  if (checked === 0) fail(context, "nothing took keyboard focus");
}

async function shot(page, name, context, checks = {}) {
  await page.waitForTimeout(50);
  await page.screenshot({ path: `${OUT}${context}-${name}.png`, fullPage: true });
  await layoutChecks(page, `${context} ${name}`);
  if (checks.focus !== false) await focusRing(page, `${context} ${name}`);
  report.push(`${context} ${name}`);
}

async function runMatrix(browser, stub, width, theme) {
  const context = `${theme}-${width}`;
  const browserContext = await browser.newContext({ viewport: { width, height: width < 600 ? 800 : 900 }, colorScheme: theme, deviceScaleFactor: 1 });
  const page = await browserContext.newPage();
  const problems = [];
  page.on("console", (message) => {
    if (message.type() === "error" && !/status of (401|429)/.test(message.text())) problems.push("console: " + message.text());
  });
  page.on("pageerror", (error) => problems.push("pageerror: " + error.message));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      console.error("csp violation " + event.violatedDirective + " " + event.blockedURI);
    });
  });

  await page.goto(stub.origin + "/");
  await page.waitForSelector("a.btn-primary");
  await tokenContrast(page, context);
  await shot(page, "signin", context);

  await page.click("a.btn-primary");
  await page.waitForSelector(".mainnav a");
  await page.waitForSelector("tbody tr");
  if (!page.url().endsWith("#/nodes")) fail(context, "sign-in did not land on the nodes screen: " + page.url());
  await shot(page, "nodes", context);

  await page.goto(stub.origin + "/#/nodes/n-1");
  await page.waitForSelector(".kv");
  await page.waitForSelector(".access-table, section[aria-label='Who can reach this node'] table");
  await shot(page, "node", context);

  await page.click("button:has-text('Remove…')");
  await page.waitForSelector("[role=dialog]");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  const trapped = await page.evaluate(() => document.querySelector("[role=dialog]").contains(document.activeElement));
  if (!trapped) fail(context, "focus left the open dialog");
  await shot(page, "remove-dialog", context, { focus: false });
  await page.fill("[role=dialog] input[type=text]", "web-01");
  const enabled = await page.isEnabled("[role=dialog] button:has-text('Remove web-01')");
  if (!enabled) fail(context, "typed node name did not enable the confirm button");
  await page.keyboard.press("Escape");
  const closed = await page.evaluate(() => document.querySelector("[role=dialog]") === null);
  if (!closed) fail(context, "Escape did not close the dialog");

  const code = await stub.enrol("web-" + context, { env: "prod", team: "web" });
  await page.goto(stub.origin + "/#/approve");
  await page.waitForSelector("input.code-input");
  await shot(page, "approve-code", context);
  await page.fill("input.code-input", code);
  await page.click("button:has-text('Continue')");
  await page.waitForSelector("text=Is this the server you expect?");
  await shot(page, "approve-check", context);
  await page.click(`button:has-text('Approve web-${context}')`);
  await page.waitForSelector("text=is approved");
  await shot(page, "approve-done", context);

  await page.goto(stub.origin + "/#/sessions");
  await page.waitForSelector("tbody tr");
  await shot(page, "sessions", context);
  await page.goto(stub.origin + "/#/sessions/5b1c0a41-aaaa-bbbb-cccc-111122223333");
  await page.waitForSelector(".kv");
  await shot(page, "session", context);

  await page.goto(stub.origin + "/#/revocations");
  await page.waitForSelector("tbody tr");
  await shot(page, "revocations", context);
  await page.click("button:has-text('New revocation')");
  await page.waitForSelector("[role=dialog]");
  await shot(page, "revoke-dialog", context, { focus: false });
  await page.keyboard.press("Escape");

  await page.goto(stub.origin + "/#/audit");
  await page.waitForSelector("tbody tr");
  await shot(page, "audit", context);
  await page.click("tbody tr button:has-text('Details')");
  await page.waitForSelector("[role=dialog]");
  await shot(page, "audit-drawer", context, { focus: false });
  await page.keyboard.press("Escape");

  const original = stub.state.nodes;
  stub.setNodes([]);
  await page.goto(stub.origin + "/#/nodes");
  await page.waitForSelector("text=No nodes yet");
  await shot(page, "nodes-empty", context);
  stub.setNodes(original);

  stub.limitLookups(true);
  await page.goto(stub.origin + "/#/approve");
  await page.waitForSelector("input.code-input");
  await page.fill("input.code-input", "ZZZZ-ZZZZ");
  await page.click("button:has-text('Continue')");
  await page.waitForSelector("text=Try again in");
  await shot(page, "approve-rate-limited", context);
  stub.limitLookups(false);

  await page.goto(stub.origin + "/#/sessions");
  await page.waitForSelector("tbody tr");
  stub.expireSessions();
  await page.click("button:has-text('Refresh')");
  await page.waitForSelector("[role=dialog]:has-text('Session expired')");
  await shot(page, "session-expired", context, { focus: false });

  const pwned = await page.evaluate(() => window.__pwned);
  if (pwned !== undefined) fail(context, "hostile fixture executed script");
  for (const problem of problems) fail(context, problem);
  await browserContext.close();
}

async function runForbidden(browser, width, theme) {
  const context = `${theme}-${width}`;
  const stub = await startStub({ permissions: ["sessions.read"] });
  const browserContext = await browser.newContext({ viewport: { width, height: width < 600 ? 800 : 900 }, colorScheme: theme, deviceScaleFactor: 1 });
  const page = await browserContext.newPage();
  await page.goto(stub.origin + "/");
  await page.click("a.btn-primary");
  await page.waitForSelector(".mainnav a");
  await page.goto(stub.origin + "/#/nodes");
  await page.waitForSelector("text=Not allowed");
  const links = await page.$$eval(".mainnav a", (nodes) => nodes.map((node) => node.getAttribute("href")));
  if (links.join() !== "#/sessions,#/revocations") fail(context, "navigation shows " + links.join());
  await shot(page, "forbidden", context);
  await browserContext.close();
  await stub.close();
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const stub = await startStub({ permissions: ALL });
  const browser = await chromium.launch();
  try {
    for (const theme of THEMES) {
      for (const width of WIDTHS) {
        await runMatrix(browser, stub, width, theme);
        await runForbidden(browser, width, theme);
      }
    }
  } finally {
    await browser.close();
    await stub.close();
  }
  console.log(`screens checked: ${report.length}, touch targets measured: ${touchChecked}`);
  console.log(`screenshots: ${OUT}`);
  if (failures.length > 0) {
    console.error(`${failures.length} failure(s):`);
    for (const entry of failures) console.error(" - " + entry);
    process.exitCode = 1;
  } else {
    console.log("all layout, font size, contrast, focus and dialog checks passed");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
