import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { hostileCast, incompleteCast, richCast } from "./casts.mjs";
import { startStub } from "./stub.mjs";

const OUT = fileURLToPath(new URL("../screenshots-out/", import.meta.url));
const ALL = ["nodes.approve", "sessions.read", "recordings.read", "revocations.write", "audit.read"];
const WIDTHS = [380, 1440];
const THEMES = ["light", "dark"];
const LIMIT = 64 * 1024 * 1024;
const IDS = {
  rich: "5b1c0a41-aaaa-bbbb-cccc-111122223333",
  hostile: "5b1c0a42-aaaa-bbbb-cccc-111122223333",
  large: "5b1c0a43-aaaa-bbbb-cccc-111122223333",
  incomplete: "5b1c0a44-aaaa-bbbb-cccc-111122223333",
  exec: "5b1c0a45-aaaa-bbbb-cccc-111122223333",
};

const failures = [];
const notes = [];

function fail(context, message) {
  failures.push(context + ": " + message);
}

function manifest(overrides) {
  const now = Math.floor(Date.now() / 1000);
  return { state: "complete", kind: "shell", chunks: 4, raw_bytes: 2048, incomplete: false, salvaged: false, input_recorded: false, dropped_chunks: 0, has_cast: true, started_at: now - 900, ended_at: now - 600, command: null, playback_limit_bytes: LIMIT, ...overrides };
}

function seed(stub) {
  const rich = richCast();
  const hostile = hostileCast();
  stub.setRecording(IDS.rich, manifest({ raw_bytes: rich.length, input_recorded: true }), rich);
  stub.setRecording(IDS.hostile, manifest({ raw_bytes: hostile.length, input_recorded: true }), hostile);
  stub.setRecording(IDS.large, manifest({ raw_bytes: LIMIT + 1 }), Buffer.from("unused"));
  stub.setRecording(IDS.incomplete, manifest({ state: "incomplete", incomplete: true, salvaged: true, raw_bytes: 200 }), incompleteCast());
  stub.setRecording(IDS.exec, manifest({ kind: "exec", has_cast: false, command: "systemctl restart nginx", raw_bytes: 0, chunks: 0 }), null);
}

async function instrument(browserContext, origin, context) {
  await browserContext.addInitScript(() => {
    window.__csp = [];
    window.__clipboard = 0;
    window.__opened = 0;
    window.__resizeListeners = 0;
    const addListener = window.addEventListener.bind(window);
    window.addEventListener = (type, ...rest) => {
      if (type === "resize") window.__resizeListeners += 1;
      return addListener(type, ...rest);
    };
    window.__long = [];
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) window.__long.push(entry.duration);
    }).observe({ type: "longtask", buffered: true });
    document.addEventListener("securitypolicyviolation", (event) => window.__csp.push(event.violatedDirective + " " + event.blockedURI));
    if (navigator.clipboard && navigator.clipboard.writeText) {
      const original = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = (...args) => {
        window.__clipboard += 1;
        return original(...args);
      };
    }
    const execCommand = document.execCommand.bind(document);
    document.execCommand = (name, ...rest) => {
      if (String(name).toLowerCase() === "copy" || String(name).toLowerCase() === "cut") {
        window.__clipboard += 1;
      }
      return execCommand(name, ...rest);
    };
    const open = window.open.bind(window);
    window.open = (...args) => {
      window.__opened += 1;
      return open(...args);
    };
  });
  const page = await browserContext.newPage();
  const problems = [];
  const requests = [];
  page.on("console", (message) => {
    if ((message.type() === "error" || message.type() === "warning") && !/status of 401/.test(message.text())) {
      problems.push("console " + message.type() + ": " + message.text().slice(0, 200));
    }
  });
  page.on("pageerror", (error) => problems.push("page error: " + String(error && error.stack || error).replace(/\s+/g, " ").slice(0, 600)));
  page.on("dialog", async (dialog) => {
    problems.push("dialog: " + dialog.message().slice(0, 80));
    await dialog.dismiss();
  });
  page.on("request", (request) => requests.push(request.url()));
  page.on("requestfailed", (request) => problems.push("request failed: " + request.url()));
  page.on("response", (response) => {
    if (response.status() >= 400 && !/\/v1\/web\/session$/.test(response.url())) {
      problems.push("http " + response.status() + ": " + response.url().replace(origin, ""));
    }
  });
  return { page, problems, requests };
}

async function shot(page, name, context) {
  await page.screenshot({ path: `${OUT}recording-${name}-${context}.png`, fullPage: true });
}

function luminance(rgb) {
  const [r, g, b] = rgb.map((value) => value / 255).map((value) => (value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

async function layout(page, context, label) {
  const result = await page.evaluate(() => {
    const parse = (value) => {
      const match = /rgba?\(([^)]+)\)/.exec(value);
      if (!match) return null;
      const parts = match[1].split(/[ ,\/]+/).filter(Boolean).map(Number);
      return { rgb: parts.slice(0, 3), alpha: parts.length > 3 ? parts[3] : 1 };
    };
    const backgroundOf = (element) => {
      for (let node = element; node; node = node.parentElement) {
        const color = parse(getComputedStyle(node).backgroundColor);
        if (color && color.alpha === 1) return color.rgb;
      }
      return [255, 255, 255];
    };
    const small = [];
    const lowContrast = [];
    const panel = document.querySelector(".recording");
    const walker = document.createTreeWalker(panel || document.body, NodeFilter.SHOW_TEXT);
    const lum = (rgb) => {
      const [r, g, b] = rgb.map((value) => value / 255).map((value) => (value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4));
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    while (walker.nextNode()) {
      const text = walker.currentNode;
      const parent = text.parentElement;
      if (!parent || text.data.trim() === "" || parent.closest(".player-screen, .visually-hidden")) continue;
      const style = getComputedStyle(parent);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.fontSize) < 13) small.push(text.data.trim().slice(0, 30) + " " + style.fontSize);
      const foreground = parse(style.color);
      if (foreground) {
        const [high, low] = [lum(foreground.rgb), lum(backgroundOf(parent))].sort((a, b) => b - a);
        const ratio = (high + 0.05) / (low + 0.05);
        if (ratio < 4.5) lowContrast.push(text.data.trim().slice(0, 30) + " " + ratio.toFixed(2));
      }
    }
    const screen = document.querySelector(".player-screen");
    const box = screen ? screen.getBoundingClientRect() : null;
    return {
      overflow: document.documentElement.scrollWidth - window.innerWidth,
      small,
      lowContrast,
      screenRight: box ? Math.round(box.right) : null,
      screenWidth: box ? Math.round(box.width) : null,
      screenScrolls: screen ? screen.scrollWidth > screen.clientWidth : null,
      width: window.innerWidth,
    };
  });
  if (result.overflow > 0) fail(context, `${label}: the page scrolls horizontally by ${result.overflow}px`);
  for (const entry of result.small) fail(context, `${label}: text under 13px: ${entry}`);
  for (const entry of result.lowContrast) fail(context, `${label}: contrast under 4.5: ${entry}`);
  if (result.screenRight !== null && result.screenRight > result.width) fail(context, `${label}: the screen sticks out of the viewport`);
  return result;
}

async function drawn(page) {
  return page.evaluate(() => {
    let painted = 0;
    for (const canvas of document.querySelectorAll(".player-screen canvas")) {
      const context = canvas.getContext("2d");
      if (!context || canvas.width === 0 || canvas.height === 0) continue;
      const data = context.getImageData(0, 0, canvas.width, canvas.height).data;
      for (let index = 3; index < data.length; index += 4) {
        if (data[index] !== 0) painted += 1;
      }
    }
    return painted;
  });
}

async function playToEnd(page, context) {
  await page.selectOption("#player-speed", "8");
  await page.click("button:has-text('Play')");
  await page.waitForFunction(() => /Finished/.test(document.querySelector(".player .visually-hidden[role=status]")?.textContent || ""), null, { timeout: 30000 });
  return page.textContent(".player-time");
}

async function runContext(browser, stub, width, theme) {
  const context = `${theme}-${width}`;
  const browserContext = await browser.newContext({ viewport: { width, height: width < 600 ? 900 : 1000 }, colorScheme: theme, deviceScaleFactor: 1 });
  const { page, problems, requests } = await instrument(browserContext, stub.origin, context);
  await page.goto(stub.origin + "/");
  await page.click("a.btn-primary");
  await page.waitForSelector(".mainnav a");

  stub.state.recordingRequests.length = 0;
  await page.goto(stub.origin + "/#/sessions/" + IDS.rich);
  await page.waitForSelector("button:has-text('Watch recording')");
  await shot(page, "panel", context);
  await layout(page, context, "panel");
  if (stub.state.recordingRequests.some((entry) => !entry.path.endsWith("/manifest"))) fail(context, "the cast was requested before Watch was pressed");

  await page.click("button:has-text('Watch recording')");
  await page.waitForSelector(".player-screen canvas");
  const streamRequests = stub.state.recordingRequests.filter((entry) => !entry.path.endsWith("/manifest"));
  if (streamRequests.length !== 1) fail(context, `expected one cast request, saw ${streamRequests.length}`);
  await shot(page, "loaded", context);
  const listenersAfterFirst = await page.evaluate(() => window.__resizeListeners);
  const initial = await layout(page, context, "loaded");
  notes.push(`${context}: screen ${initial.screenWidth}px wide of ${initial.width}px, scrolls inside: ${initial.screenScrolls}`);

  await page.keyboard.press("Tab");
  await page.focus(".player-screen");
  const before = await page.textContent(".player-time");
  await page.keyboard.press("Space");
  await page.waitForFunction((value) => document.querySelector(".player-time").textContent !== value, before, { timeout: 5000 });
  await page.keyboard.press("Space");
  const frozen = await page.textContent(".player-time");
  await page.waitForTimeout(400);
  if ((await page.textContent(".player-time")) !== frozen) fail(context, "Space did not pause the playback");

  await page.focus("#player-seek");
  const ring = await page.evaluate(() => {
    const style = getComputedStyle(document.querySelector("#player-seek"));
    return { style: style.outlineStyle, width: parseFloat(style.outlineWidth) };
  });
  await page.keyboard.press("End");
  const atEnd = await page.textContent(".player-time");
  const [elapsed, total] = atEnd.split(" / ");
  if (elapsed !== total) fail(context, `End did not reach the end: ${atEnd}`);
  await page.keyboard.press("Home");
  if (!(await page.textContent(".player-time")).startsWith("0:00 /")) fail(context, "Home did not return to the start");
  await page.keyboard.press("ArrowRight");
  if (!(await page.textContent(".player-time")).startsWith("0:05 /")) fail(context, "ArrowRight did not move five seconds");
  await page.waitForTimeout(300);
  await shot(page, "seeked", context);
  if (ring.style === "none" || ring.width < 2) fail(context, `the seek bar shows no focus ring (${ring.style} ${ring.width})`);

  await page.keyboard.press("Home");
  const finishedAt = await playToEnd(page, context);
  await page.waitForTimeout(300);
  const painted = await drawn(page);
  if (painted < 500) fail(context, `the terminal canvas looks empty (${painted} painted pixels)`);
  await shot(page, "played", context);
  await layout(page, context, "played");
  notes.push(`${context}: played to ${finishedAt}, ${painted} painted pixels`);

  await page.check("#player-input");
  await page.waitForTimeout(300);
  await shot(page, "input-on", context);
  await page.uncheck("#player-input");
  await page.uncheck("#player-compress");
  const longTotal = (await page.textContent(".player-time")).split(" / ")[1];
  await page.check("#player-compress");
  const shortTotal = (await page.textContent(".player-time")).split(" / ")[1];
  if (longTotal === shortTotal) fail(context, "idle compression did not change the total time");
  notes.push(`${context}: total ${longTotal} without and ${shortTotal} with idle compression`);

  const download = await page.getAttribute("a:has-text('Download .cast')", "href");
  if (download !== `/v1/admin/sessions/${IDS.rich}/recording?download=1`) fail(context, "unexpected download link " + download);

  await page.goto(stub.origin + "/#/sessions/" + IDS.hostile);
  await page.waitForSelector("button:has-text('Watch recording')");
  const scriptsBefore = await page.evaluate(() => document.querySelectorAll("script").length);
  await page.evaluate(() => {
    window.__titleBefore = document.title;
  });
  const clipboardBefore = await page.evaluate(() => window.__clipboard);
  const requestsBefore = requests.length;
  await page.click("button:has-text('Watch recording')");
  await page.waitForSelector(".player-screen canvas");
  await page.check("#player-input");
  await playToEnd(page, context);
  await page.waitForTimeout(500);
  await shot(page, "hostile", context);
  await layout(page, context, "hostile");
  const hostileState = await page.evaluate(() => ({
    title: document.title === window.__titleBefore,
    clipboard: window.__clipboard,
    opened: window.__opened,
    pwned: window.__pwned,
    longest: Math.max(0, ...window.__long),
    resizeListeners: window.__resizeListeners,
    foreign: document.querySelectorAll(".recording img, .recording iframe, .recording object, .recording embed, .recording svg, .recording style, .recording script, .player-screen a").length,
    scripts: document.querySelectorAll("script").length,
    skipped: document.querySelector(".recording [role=status]:not(.visually-hidden)")?.textContent || "",
    hash: location.hash,
    width: window.innerWidth,
  }));
  if (!hostileState.title) fail(context, "a hostile cast changed the page title");
  if (hostileState.clipboard !== clipboardBefore) fail(context, "a hostile cast wrote to the clipboard");
  if (hostileState.resizeListeners > listenersAfterFirst) fail(context, `opening a second player added ${hostileState.resizeListeners - listenersAfterFirst} resize listeners`);
  notes.push(`${context}: resize listeners after the first player ${listenersAfterFirst}, after the second ${hostileState.resizeListeners}`);
  if (hostileState.longest >= 500) fail(context, `a hostile cast kept the main thread busy for ${Math.round(hostileState.longest)} ms`);
  notes.push(`${context}: longest main-thread task while playing the hostile cast ${Math.round(hostileState.longest)} ms`);
  if (hostileState.opened !== 0) fail(context, "a hostile cast opened a window");
  if (hostileState.pwned !== undefined) fail(context, "a hostile cast ran script");
  if (hostileState.foreign !== 0) fail(context, "a hostile cast created elements");
  if (hostileState.scripts !== scriptsBefore) fail(context, "a hostile cast added a script");
  if (hostileState.hash !== "#/sessions/" + IDS.hostile) fail(context, "a hostile cast navigated");
  if (!/skipped/.test(hostileState.skipped)) fail(context, "the damaged lines were not reported: " + hostileState.skipped);
  const foreignRequests = requests.slice(requestsBefore).filter((url) => !url.startsWith(stub.origin + "/v1/admin/sessions/") && !url.startsWith(stub.origin + "/v1/web/session") && !url.startsWith(stub.origin + "/assets/"));
  if (foreignRequests.length > 0) fail(context, "unexpected requests: " + foreignRequests.join(", "));

  await page.goto(stub.origin + "/#/sessions/" + IDS.large);
  await page.waitForSelector("text=larger than the 64 MiB");
  await shot(page, "large", context);
  await layout(page, context, "large");
  if (stub.state.recordingRequests.some((entry) => entry.session === IDS.large && !entry.path.endsWith("/manifest"))) fail(context, "the oversized cast was requested");

  await page.goto(stub.origin + "/#/sessions/" + IDS.incomplete);
  await page.waitForSelector("text=Some parts are missing");
  await shot(page, "incomplete", context);
  await layout(page, context, "incomplete");

  await page.goto(stub.origin + "/#/sessions/" + IDS.exec);
  await page.waitForSelector("text=metadata only");
  await shot(page, "metadata", context);
  await layout(page, context, "metadata");

  const violations = await page.evaluate(() => window.__csp);
  if (violations.length > 0) fail(context, "CSP violations: " + violations.join("; "));
  const outside = requests.filter((url) => !url.startsWith(stub.origin + "/"));
  if (outside.length > 0) fail(context, "requests outside the console: " + outside.join(", "));
  const fromLibrary = requests.filter((url) => url.includes("/assets/vendor/")).map((url) => url.replace(stub.origin, ""));
  notes.push(`${context}: vendored files fetched: ${[...new Set(fromLibrary)].join(", ")}`);
  for (const problem of problems) fail(context, problem);
  await browserContext.close();
}

async function runReader(browser, width) {
  const context = `reader-${width}`;
  const stub = await startStub({ permissions: ["sessions.read"] });
  seed(stub);
  const browserContext = await browser.newContext({ viewport: { width, height: 900 }, deviceScaleFactor: 1 });
  const { page, problems, requests } = await instrument(browserContext, stub.origin, context);
  await page.goto(stub.origin + "/");
  await page.click("a.btn-primary");
  await page.waitForSelector(".mainnav a");
  await page.goto(stub.origin + "/#/sessions/" + IDS.rich);
  await page.waitForSelector("text=not its content");
  await shot(page, "no-permission", context);
  await layout(page, context, "no-permission");
  await page.waitForTimeout(500);
  if (stub.state.recordingRequests.length > 0 || requests.some((url) => /\/v1\/admin\/sessions\/[^/]+\/recording/.test(url))) fail(context, "a recording request was made without the permission: " + requests.filter((url) => /\/v1\/admin\/sessions\/[^/]+\/recording/.test(url)).join(", ") + " " + JSON.stringify(stub.state.recordingRequests));
  for (const problem of problems) fail(context, problem);
  await browserContext.close();
  await stub.close();
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const stub = await startStub({ permissions: ALL });
  seed(stub);
  const browser = await chromium.launch();
  try {
    for (const theme of THEMES) {
      for (const width of WIDTHS) {
        await runContext(browser, stub, width, theme);
      }
    }
    for (const width of WIDTHS) {
      await runReader(browser, width);
    }
  } finally {
    await browser.close();
    await stub.close();
  }
  for (const note of notes) console.log(note);
  console.log(`screenshots: ${OUT}`);
  if (failures.length > 0) {
    console.error(`${failures.length} failure(s):`);
    for (const entry of failures) console.error(" - " + entry);
    process.exitCode = 1;
  } else {
    console.log("recording player: layout, CSP, hostile cast, permission and request checks passed");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
