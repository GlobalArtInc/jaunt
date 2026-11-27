import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { startStub } from "./stub.mjs";

const OUT = (process.env.SCREENSHOT_DIR || fileURLToPath(new URL("../screenshots-out/after/", import.meta.url))).replace(/\/?$/, "/");
const ALL = ["nodes.approve", "sessions.read", "sessions.terminate", "recordings.read", "revocations.write", "audit.read"];
const WIDTHS = process.env.SMOKE_WIDTHS ? process.env.SMOKE_WIDTHS.split(",").map(Number) : [380, 900, 1440];
const THEMES = process.env.SMOKE_THEMES ? process.env.SMOKE_THEMES.split(",") : ["light", "dark"];

const TEXT_PAIRS = [
  ["--text", "--bg"], ["--text", "--canvas"], ["--text", "--surface"], ["--text", "--surface-2"], ["--text", "--surface-3"], ["--text", "--hover"],
  ["--text-muted", "--bg"], ["--text-muted", "--canvas"], ["--text-muted", "--surface"], ["--text-muted", "--surface-2"], ["--text-muted", "--surface-3"], ["--text-muted", "--hover"],
  ["--accent", "--bg"], ["--accent", "--canvas"], ["--accent", "--surface"], ["--accent", "--accent-weak"], ["--on-accent", "--accent"], ["--text", "--accent-weak"], ["--text-muted", "--accent-weak"],
  ["--info", "--info-weak"], ["--text", "--info-weak"], ["--ok", "--ok-weak"], ["--warn", "--warn-weak"], ["--danger", "--danger-weak"], ["--ok", "--bg"], ["--warn", "--bg"], ["--danger", "--bg"], ["--danger", "--canvas"], ["--danger", "--surface"],
  ["--text", "--warn-weak"], ["--text", "--danger-weak"], ["--text", "--ok-weak"], ["--on-danger", "--danger-fill"],
];
const NON_TEXT_PAIRS = [["--border-strong", "--bg"], ["--border-strong", "--canvas"], ["--border-strong", "--surface"], ["--border-strong", "--surface-3"], ["--focus", "--bg"], ["--focus", "--canvas"], ["--focus", "--surface"], ["--focus", "--accent-weak"]];
const TOKENS = Array.from(new Set([...TEXT_PAIRS, ...NON_TEXT_PAIRS].flat()));

let touchChecked = 0;
const failures = [];
const report = [];
const RUN_LIMIT_MS = Number(process.env.SMOKE_RUN_LIMIT_MS || 15 * 60 * 1000);

setTimeout(() => {
  console.error(`the run exceeded ${RUN_LIMIT_MS / 1000} s and was stopped`);
  for (const entry of failures) console.error(" - " + entry);
  process.exit(1);
}, RUN_LIMIT_MS).unref();

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
  const tokens = await page.evaluate((names) => {
    const style = getComputedStyle(document.documentElement);
    return Object.fromEntries(names.map((name) => [name, style.getPropertyValue(name)]));
  }, TOKENS);
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
    const secondary = ".small, .muted, .badge, .chip, th, dt, label, legend, .field-hint, .sub, .crumbs, .nav-count, .num, .steps, .code, caption, .step-list li, .rail-label, .menu-hint, .menu-heading, .bell-count, .avatar, .subnav-foot, .link-btn, .node-type, .node-warning, .node-meta, .sort-note, .node-host";
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
      const targets = document.querySelectorAll("button, a.btn, select, textarea, input:not([type=hidden]):not([type=checkbox]):not([type=radio]), .rail a, .subnav a, .tab, .icon-btn, .menu-item, table.data a, .crumbs a, a.chip, .node-name, .switch-field");
      for (const target of targets) {
        const rect = target.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0 || rect.bottom <= 0 || rect.top < -50 || target.closest(".visually-hidden") || target.classList.contains("skip")) continue;
        if (target.closest("[inert]") && !target.closest(".scrim")) continue;
        if (getComputedStyle(target).visibility === "hidden" || target.closest("[hidden]")) continue;
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


const FOCUS_KINDS = ["hamburger", "rail-item", "subnav-item", "btn-connect", "tab", "search-input", "switch-input", "icon-btn", "account-btn", "node-name", "link-btn", "menu-item", "brand"];

async function activeRing(page) {
  return page.evaluate((kinds) => {
    const active = document.activeElement;
    if (!active || active === document.body) return null;
    const classes = (active.getAttribute("class") || "").split(/\s+/);
    const kind = kinds.find((name) => classes.includes(name)) || active.localName;
    const target = classes.includes("switch-input") ? active.nextElementSibling : active;
    const style = getComputedStyle(target);
    return {
      kind,
      index: Array.from(document.querySelectorAll("*")).indexOf(active),
      style: style.outlineStyle,
      width: parseFloat(style.outlineWidth),
      color: style.outlineColor,
      text: (active.textContent || active.getAttribute("aria-label") || "").trim().slice(0, 24),
    };
  }, FOCUS_KINDS);
}

function ringProblem(ring) {
  return ring.style === "none" || ring.width < 2 || /rgba\(0, 0, 0, 0\)/.test(ring.color);
}

async function walkTabOrder(page, context, required) {
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.focus(".skip");
  const seen = new Set();
  const kinds = new Set();
  for (let step = 0; step < 160; step += 1) {
    await page.keyboard.press("Tab");
    const ring = await activeRing(page);
    if (!ring || seen.has(ring.index)) break;
    seen.add(ring.index);
    kinds.add(ring.kind);
    if (ringProblem(ring)) fail(context, `no visible focus ring on ${ring.kind} "${ring.text}": ${ring.style} ${ring.width}px ${ring.color}`);
  }
  for (const kind of required) {
    if (!kinds.has(kind)) fail(context, `the tab order never reached a ${kind}`);
  }
  report.push(`${context} tab order ${seen.size} stops`);
}

async function walkMenu(page, context) {
  await page.focus(".btn-connect");
  await page.keyboard.press("Enter");
  await page.waitForSelector(".menu");
  let items = 0;
  for (let step = 0; step < 4; step += 1) {
    const ring = await activeRing(page);
    if (ring && ring.kind === "menu-item") {
      items += 1;
      if (ringProblem(ring)) fail(context, `no visible focus ring on a menu item "${ring.text}": ${ring.style} ${ring.width}px ${ring.color}`);
    }
    await page.keyboard.press("ArrowDown");
  }
  if (items < 2) fail(context, "the menu walk reached fewer than two items");
  await page.keyboard.press("Escape");
}

async function switchTarget(page, context, width) {
  const box = await page.evaluate(() => {
    const field = document.querySelector(".switch-field");
    const rect = field ? field.getBoundingClientRect() : null;
    return rect ? { width: rect.width, height: rect.height } : null;
  });
  if (!box) return fail(context, "the Advanced switch is missing");
  if (width <= 520 && box.height < 43.5) fail(context, `the Advanced switch is ${box.height.toFixed(1)}px tall`);
  if (width <= 520 && box.width < 43.5) fail(context, `the Advanced switch is ${box.width.toFixed(1)}px wide`);
}

async function shot(page, name, context, checks = {}) {
  await page.waitForTimeout(50);
  await page.screenshot({ path: `${OUT}${context}-${name}.png`, fullPage: checks.fullPage !== false });
  await layoutChecks(page, `${context} ${name}`);
  if (checks.focus !== false) await focusRing(page, `${context} ${name}`);
  report.push(`${context} ${name}`);
}


async function navigationChecks(page, context, width) {
  const drawer = width <= 900;
  const state = await page.evaluate(() => {
    const visible = (node) => node && node.getClientRects().length > 0 && getComputedStyle(node).visibility !== "hidden";
    const rail = document.querySelector(".rail");
    const subnav = document.querySelector(".subnav");
    return {
      hamburger: visible(document.querySelector(".hamburger")),
      rail: visible(rail),
      railWidth: rail ? rail.getBoundingClientRect().width : 0,
      subnav: visible(subnav),
      subnavWidth: subnav ? subnav.getBoundingClientRect().width : 0,
      bell: visible(document.querySelector(".bell")),
      account: visible(document.querySelector(".account-btn")),
      mainLeft: document.querySelector("main").getBoundingClientRect().left,
    };
  });
  if (!state.bell || !state.account) fail(context, "the bell or the account menu is not visible");
  if (drawer) {
    if (!state.hamburger) fail(context, "no hamburger in the drawer layout");
    if (state.rail || state.subnav) fail(context, "the navigation is visible while the drawer is closed");
    await page.click(".hamburger");
    await page.waitForSelector(".drawer-open .sidebar");
    const inside = await page.evaluate(() => document.querySelector("#sidebar").contains(document.activeElement));
    if (!inside) fail(context, "focus did not move into the open drawer");
    await shot(page, "drawer", context, { focus: false, fullPage: false });
    for (let step = 0; step < 14; step += 1) await page.keyboard.press("Tab");
    const trapped = await page.evaluate(() => document.querySelector("#sidebar").contains(document.activeElement));
    if (!trapped) fail(context, "focus left the open drawer");
    await page.keyboard.press("Escape");
    const returned = await page.evaluate(() => document.activeElement === document.querySelector(".hamburger"));
    if (!returned) fail(context, "focus did not return to the hamburger");
    const closed = await page.evaluate(() => document.querySelector(".sidebar").getClientRects().length === 0);
    if (!closed) fail(context, "the drawer did not close on Escape");
  } else {
    if (state.hamburger) fail(context, "the hamburger shows on a wide screen");
    if (!state.rail || !state.subnav) fail(context, "the rail and the secondary panel are not both visible");
    if (Math.abs(state.railWidth - 84) > 1 || Math.abs(state.subnavWidth - 220) > 1) fail(context, `rail ${state.railWidth}px and panel ${state.subnavWidth}px, expected 84 and 220`);
  }
}

const ICON_TYPES = { "/assets/brand/favicon.svg": "image/svg+xml", "/assets/brand/favicon.ico": "image/x-icon", "/assets/brand/apple-touch-icon.png": "image/png", "/favicon.ico": "image/x-icon" };

async function iconChecks(page, context) {
  const declared = await page.$$eval('link[rel~="icon"], link[rel="apple-touch-icon"]', (links) => links.map((link) => link.getAttribute("href")));
  if (declared.join() !== "/assets/brand/favicon.ico,/assets/brand/favicon.svg,/assets/brand/apple-touch-icon.png") fail(context, "the page declares icons " + declared.join());
  const themeColors = await page.$$eval('meta[name="theme-color"]', (metas) => metas.map((meta) => meta.getAttribute("media") + " " + meta.getAttribute("content")));
  if (themeColors.length !== 2) fail(context, "theme-color metas: " + themeColors.join());
  for (const [path, type] of Object.entries(ICON_TYPES)) {
    const result = await page.evaluate(async (href) => {
      const reply = await fetch(href);
      const bytes = (await reply.arrayBuffer()).byteLength;
      const loaded = await new Promise((resolve) => {
        const image = new Image();
        image.onload = () => resolve(true);
        image.onerror = () => resolve(false);
        image.src = href;
      });
      return { status: reply.status, type: reply.headers.get("content-type"), bytes, loaded };
    }, path);
    if (result.status !== 200 || result.type !== type || result.bytes === 0) fail(context, `${path} answered ${result.status} ${result.type} ${result.bytes} bytes`);
    if (!result.loaded) fail(context, `${path} does not load as an image`);
    if (process.env.SMOKE_VERBOSE_ICONS) console.log(`${context} ${path} ${result.status} ${result.type} ${result.bytes} bytes loaded=${result.loaded}`);
  }
}

async function runMatrix(browser, stub, width, theme) {
  const context = `${theme}-${width}`;
  const browserContext = await browser.newContext({ viewport: { width, height: width < 600 ? 800 : 900 }, colorScheme: theme, deviceScaleFactor: 1 });
  const page = await browserContext.newPage();
  const problems = [];
  page.on("console", (message) => {
    const optional = /\/v1\/(web\/terminal\/(targets|recent|limits)|client-config)$/.test(message.location().url || "") && /status of 404/.test(message.text());
    if (message.type() === "error" && !optional && !/status of (401|429)/.test(message.text())) problems.push("console: " + message.text());
  });
  page.on("pageerror", (error) => problems.push("pageerror: " + error.message));
  if (process.env.SMOKE_VERBOSE_ICONS) page.on("response", (reply) => /brand|favicon/.test(reply.url()) && console.log(`${context} network ${reply.status()} ${reply.url()} ${reply.headers()["content-type"]}`));
  await page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      console.error("csp violation " + event.violatedDirective + " " + event.blockedURI);
    });
  });

  await page.goto(stub.origin + "/");
  await page.waitForSelector("a.btn-primary");
  await tokenContrast(page, context);
  await iconChecks(page, context);
  await shot(page, "signin", context);

  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });
  await page.waitForSelector(".node-card");
  if (!page.url().endsWith("#/nodes")) fail(context, "sign-in did not land on the nodes screen: " + page.url());
  await shot(page, "nodes", context);
  await navigationChecks(page, context, width);
  await switchTarget(page, context, width);
  const wide = width > 900;
  await walkTabOrder(page, context + " nodes", ["search-input", "switch-input", "tab", "btn-connect", "node-name", "icon-btn", "account-btn", ...(wide ? ["rail-item", "subnav-item"] : ["hamburger"])]);
  await walkMenu(page, context + " connect menu");

  await page.click("button[aria-label='List view']");
  await page.waitForSelector(".node-row");
  await shot(page, "nodes-list", context);
  await page.click("button[aria-label='Grid view']");
  await page.waitForSelector(".node-card");

  await page.click(".node-card .link-btn");
  await page.click(".node-card button[aria-label^='Connect to']");
  await page.waitForSelector(".menu");
  await shot(page, "nodes-connect-menu", context, { focus: false, fullPage: false });
  await page.keyboard.press("Escape");
  stub.setTargets([{ node: "web-01", labels: {}, connected: true, logins: ["deploy", "root"] }]);
  await page.goto(stub.origin + "/#/nodes?sort=recent");
  await page.reload();
  await page.waitForSelector(".node-card");
  await page.waitForTimeout(150);
  await page.click(".node-card:has(a.node-name:text-is('web-01')) button[aria-label^='Connect to']");
  await page.waitForSelector(".menu [role=menuitem]:has-text('deploy')");
  await shot(page, "nodes-connect-targets", context, { focus: false, fullPage: false });
  await page.keyboard.press("Escape");
  stub.setTargets(null);

  await page.goto(stub.origin + "/#/nodes?q=web");
  await page.waitForSelector(".node-card");
  await page.click(".switch-field");
  await page.waitForSelector(".advanced:not([hidden])");
  await shot(page, "nodes-advanced", context);
  await page.goto(stub.origin + "/#/nodes?tab=pending");
  await page.waitForSelector(".empty");
  await shot(page, "nodes-pending", context);
  await page.goto(stub.origin + "/#/terminal");
  await page.waitForSelector(".empty");
  await shot(page, "terminal", context);
  await page.click(".account-btn");
  await page.waitForSelector(".menu");
  await shot(page, "account-menu", context, { focus: false, fullPage: false });
  await page.keyboard.press("Escape");
  await page.goto(stub.origin + "/#/nodes");
  await page.waitForSelector(".node-card");

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
  await page.waitForSelector(".rail a", { state: "attached" });
  await page.goto(stub.origin + "/#/nodes");
  await page.waitForSelector("text=Not allowed");
  const links = await page.$$eval(".rail a", (nodes) => nodes.map((node) => node.getAttribute("href")));
  if (links.join() !== "#/sessions,#/terminal,#/revocations") fail(context, "navigation shows " + links.join());
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
