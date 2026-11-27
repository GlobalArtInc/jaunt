import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { PANE, clickTool, closeAllTabs, fail, failures, instrument, layout, quickOpen, until, waitConnected } from "./kit.mjs";
import { startStub } from "./stub.mjs";

const OUT = fileURLToPath(new URL("../screenshots-out/", import.meta.url));
const WIDTHS = [380, 1440];
const THEMES = ["light", "dark"];
const FLEET = [
  { node: "web-01", labels: { env: "prod", team: "web" }, connected: true, pinned: false, logins: ["deploy", "alice"], hidden_logins: [] },
  { node: "web-02", labels: { env: "prod" }, connected: true, pinned: false, creates_accounts: true, logins: ["deploy"], hidden_logins: [] },
  { node: "db-replica-02", labels: { env: "prod", team: "data" }, connected: false, pinned: false, logins: ["deploy"], hidden_logins: [] },
];
const ALLOWED_REPLY = /^(\u001b\[\?1;2c|\u001b\[>0;276;0c|\u001b\[0n|\u001b\[\d+;\d+R|\u001b\[\?\d+;\d+R)+$/;
const notes = [];
const RUN_LIMIT_MS = 15 * 60 * 1000;

function fatal(message) {
  console.error(message);
  for (const entry of failures) console.error(" - " + entry);
  process.exit(1);
}

setTimeout(() => fatal(`the run exceeded ${RUN_LIMIT_MS / 1000} s and was stopped`), RUN_LIMIT_MS).unref();

async function shot(page, name, context) {
  await page.screenshot({ path: `${OUT}terminal-${name}-${context}.png`, fullPage: true });
}

const screenText = (page) =>
  page.evaluate(() => {
    const terminal = window.__terms && window.__terms.at(-1);
    if (!terminal) return "";
    const buffer = terminal.buffer.active;
    const lines = [];
    for (let index = 0; index < buffer.length; index += 1) {
      const line = buffer.getLine(index);
      lines.push(line ? line.translateToString(true) : "");
    }
    return lines.join("\n");
  });

async function waitForText(page, text, context, timeout = 8000) {
  try {
    await page.waitForFunction(
      (needle) => {
        const terminal = window.__terms && window.__terms.at(-1);
        if (!terminal) return false;
        const buffer = terminal.buffer.active;
        for (let index = 0; index < buffer.length; index += 1) {
          const line = buffer.getLine(index);
          if (line && line.translateToString(true).includes(needle)) return true;
        }
        return false;
      },
      text,
      { timeout },
    );
  } catch {
    fail(context, `the terminal never showed "${text}"; it shows: ${JSON.stringify((await screenText(page)).slice(-300))}`);
  }
}

async function painted(page) {
  return page.evaluate(() => {
    let count = 0;
    for (const canvas of document.querySelectorAll(".term-host canvas")) {
      const context = canvas.getContext("2d");
      if (!context || canvas.width === 0 || canvas.height === 0) continue;
      const data = context.getImageData(0, 0, canvas.width, canvas.height).data;
      for (let index = 3; index < data.length; index += 4) if (data[index] !== 0) count += 1;
    }
    return count;
  });
}

async function trackTerminals(page) {
  await page.evaluate(async () => {
    const { terminalHooks } = await import("/assets/js/terminal/hooks.js");
    if (!terminalHooks.__wrapped) {
      terminalHooks.__wrapped = true;
      const original = terminalHooks.createTerminal;
      terminalHooks.createTerminal = (options) => {
        const created = original(options);
        window.__terms = [...(window.__terms || []), created];
        return created;
      };
    }
  });
}

async function openSession(page, stub, context, node, login, narrow = false) {
  await page.goto(stub.origin + "/#/terminal");
  await page.waitForSelector(".panel.quick, .ws:not([hidden])");
  await trackTerminals(page);
  await quickOpen(page, node, login, narrow);
  await page.waitForSelector(".term-pane:not([hidden]) .term-host canvas");
  await waitConnected(page);
}

async function pickAndOpen(page, node, narrow = false) {
  await page.waitForSelector(".panel.quick, .ws:not([hidden])");
  await quickOpen(page, node, node === "web-02" ? "deploy" : null, narrow);
  await page.waitForSelector(".term-pane:not([hidden]) .term-host canvas");
  await waitConnected(page);
}

async function endViaExit(page, context, name) {
  await page.keyboard.type("exit");
  await page.keyboard.press("Enter");
  await page.waitForSelector(`${PANE} .term-banner:has-text('Session ended')`, { timeout: 6000 }).catch(() => fail(context, `${name}: no ended banner`));
}

async function navigationChecks(page, stub, context, width) {
  const narrow = width <= 520;
  await page.goto(stub.origin + "/#/nodes");
  await page.waitForSelector(".node-card");
  await page.goto(stub.origin + "/#/terminal");
  const exits = [
    ["Close terminal in the banner", async () => page.click(`${PANE} .term-banner button:has-text('Close terminal')`)],
    [
      "tab close button",
      async () => {
        if (narrow) {
          await page.click(`${PANE} .term-banner button:has-text('Close terminal')`);
        } else {
          await page.click(".ttab.is-active button[aria-label^='Close ']");
        }
      },
    ],
  ];
  for (const [name, close] of exits) {
    await pickAndOpen(page, "web-02", narrow);
    await endViaExit(page, context, name);
    if ((await page.evaluate(() => location.hash)) !== "#/terminal") fail(context, `${name}: the address is not #/terminal`);
    await close();
    const back = await page.waitForSelector(".panel.quick", { timeout: 4000 }).catch(() => null);
    if (!back) {
      fail(context, `${name}: quick open did not come back`);
      await page.goto(stub.origin + "/#/nodes");
      await page.goto(stub.origin + "/#/terminal");
      continue;
    }
    if ((await page.locator(".term-pane").count()) !== 0) fail(context, `${name}: the session screen is still there`);
  }
}

const LONG_FLEET = [
  { node: "n".repeat(40), labels: { ["k".repeat(40)]: "v".repeat(40) }, connected: true, logins: ["deploy"] },
  { node: "m".repeat(50), labels: { ["k".repeat(50)]: "v".repeat(50), env: "p".repeat(50) }, connected: true, logins: ["deploy"] },
  { node: "x".repeat(200), labels: { ["K".repeat(100)]: "V".repeat(2000) }, connected: true, logins: ["deploy"] },
];

async function runLongNames(browser, stub, width, theme) {
  const context = `long-${theme}-${width}`;
  const browserContext = await browser.newContext({ viewport: { width, height: width < 600 ? 800 : 900 }, colorScheme: theme, deviceScaleFactor: 1, reducedMotion: "reduce" });
  const { page, problems } = await instrument(browserContext, stub.origin);
  stub.setTargets(LONG_FLEET.map((entry) => ({ ...entry, pinned: false, hidden_logins: [] })));
  await page.goto(stub.origin + "/");
  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });
  await page.goto(stub.origin + "/#/terminal");
  await page.waitForSelector(".panel.quick");
  await shot(page, "picker-long", context);
  await layout(page, context, "picker-long", width <= 520);
  for (const entry of LONG_FLEET) {
    await page.click(`.quick-row:has(.name:text-is("${entry.node}")) button:has-text("Choose login")`);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    if (overflow > 0) fail(context, `${entry.node.length}-character node: quick open scrolls horizontally by ${overflow}px`);
  }
  await pickAndOpen(page, "x".repeat(200), width <= 520);
  await shot(page, "session-long", context);
  await layout(page, context, "session-long", width <= 520);
  stub.setTargets(FLEET);
  for (const problem of problems) fail(context, problem);
  await browserContext.close();
}

async function runContext(browser, stub, width, theme) {
  const context = `${theme}-${width}`;
  const narrow = width <= 520;
  const browserContext = await browser.newContext({ viewport: { width, height: width < 600 ? 800 : 900 }, colorScheme: theme, deviceScaleFactor: 1, reducedMotion: "reduce" });
  await browserContext.grantPermissions(["clipboard-read", "clipboard-write"], { origin: stub.origin });
  const { page, problems, requests } = await instrument(browserContext, stub.origin);
  const sockets = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  stub.terminal.sessions.length = 0;
  await page.goto(stub.origin + "/");
  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });

  await page.goto(stub.origin + "/#/terminal");
  await page.waitForSelector(".panel.quick");
  await shot(page, "picker", context);
  await layout(page, context, "picker", narrow);
  if ((await page.locator('.quick-row:has(.name:text-is("db-replica-02")) button').count()) !== 0) fail(context, "an offline node can be opened");

  await page.click('.quick-row:has(.name:text-is("web-01")) button:has-text("Choose login")');
  await page.waitForSelector('input[name="quick-login"]');
  await shot(page, "picker-login", context);
  await layout(page, context, "picker-login", narrow);
  await page.keyboard.press("Tab");
  await page.click('.quick-row:has(.name:text-is("web-01")) button:has-text("Hide logins")');

  await openSession(page, stub, context, "web-01", "deploy", narrow);
  const session = stub.terminal.sessions.at(-1);
  await waitForText(page, "deploy@web-01", context);
  await shot(page, "session", context);
  const initial = await layout(page, context, "session", narrow);
  notes.push(`${context}: terminal frame ${initial.frameHeight}px high, cols x rows in the address: ${session.query.cols}x${session.query.rows}`);
  const realCols = await page.evaluate(() => window.__terms.at(-1).cols);
  if (realCols !== session.query.cols) fail(context, `the address said ${session.query.cols} columns but the terminal has ${realCols}`);
  const fontSize = await page.evaluate(() => window.__terms.at(-1).options.fontSize);
  if (fontSize < 14) fail(context, "terminal font under 14px: " + fontSize);

  const sockInfo = await page.evaluate(() => window.__sockets);
  if (sockInfo.length !== 1) fail(context, `expected one WebSocket, saw ${sockInfo.length}`);
  const info = sockInfo[0];
  if (info.url.includes(info.protocols[1].slice("jaunt-ticket.".length))) fail(context, "the ticket is in the WebSocket address");
  if (info.protocols[0] !== "jaunt-terminal.v1" || !/^jaunt-ticket\.[A-Za-z0-9_-]{43}$/.test(info.protocols[1]) || info.protocols.length !== 2) fail(context, "unexpected subprotocols " + JSON.stringify(info.protocols));
  if (!info.url.startsWith("ws://127.0.0.1:")) fail(context, "unexpected socket address " + info.url);
  if (stub.terminal.handshakeFailures.length > 0) fail(context, "handshake refused: " + stub.terminal.handshakeFailures.join(", "));

  await page.keyboard.type("echo hello");
  await page.keyboard.press("Enter");
  await waitForText(page, "hello", context);
  const typed = session.input.flat();
  if (String.fromCharCode(...typed) !== "echo hello\r") fail(context, "the node received " + JSON.stringify(String.fromCharCode(...typed)));
  const pixels = await painted(page);
  if (pixels < 500) fail(context, `the terminal canvas looks empty (${pixels} painted pixels)`);
  await shot(page, "hello", context);
  notes.push(`${context}: typed echo hello, the terminal shows it, ${pixels} painted pixels`);

  await page.waitForFunction(() => document.querySelector(".term-elapsed").textContent !== "00:00", null, { timeout: 6000 }).catch(() => fail(context, "the elapsed time did not advance"));

  const sizeBefore = await page.evaluate(() => [window.__terms.at(-1).cols, window.__terms.at(-1).rows]);
  const resizesBefore = session.resizes.length;
  await page.setViewportSize({ width: width === 380 ? 340 : 1100, height: 640 });
  await until(() => session.resizes.length > resizesBefore, "a resize frame", context);
  await page.waitForTimeout(400);
  const sizeAfter = await page.evaluate(() => [window.__terms.at(-1).cols, window.__terms.at(-1).rows]);
  const last = session.resizes.at(-1);
  if (!last || last[0] !== sizeAfter[0] || last[1] !== sizeAfter[1]) fail(context, `the last resize frame ${JSON.stringify(last)} differs from the terminal ${JSON.stringify(sizeAfter)}`);
  if (sizeAfter[0] === sizeBefore[0] && sizeAfter[1] === sizeBefore[1]) fail(context, "the terminal size did not change with the window");
  if (session.resizes.length - resizesBefore > 3) fail(context, `a single window change produced ${session.resizes.length - resizesBefore} resize frames`);
  notes.push(`${context}: window change ${sizeBefore.join("x")} -> ${sizeAfter.join("x")}, resize frames sent: ${session.resizes.length - resizesBefore}`);
  await shot(page, "resized", context);
  await layout(page, context, "resized", width === 380 ? true : false);
  await page.setViewportSize({ width, height: width < 600 ? 800 : 900 });
  await page.waitForTimeout(400);

  const keyBarShown = await page.isVisible(".keybar");
  if (narrow && !keyBarShown) fail(context, "the key bar is not shown on a narrow screen");
  if (!narrow && keyBarShown) fail(context, "the key bar is shown on a wide screen without being asked");
  if (!keyBarShown) await page.click("button[data-action=keys]");
  await page.waitForSelector(".keybar button");
  const inputBefore = session.input.length;
  await page.click('.key-btn[data-key="esc"]');
  await page.click('.key-btn[data-key="up"]');
  await page.click('.key-btn[data-key="ctrl"]');
  await page.keyboard.type("c");
  await page.click('.key-btn[data-key="pgdn"]');
  await page.click('.key-btn[data-key="pipe"]');
  await until(() => session.input.length >= inputBefore + 5, "the key bar bytes", context);
  const keyBytes = session.input.slice(inputBefore).map((bytes) => String.fromCharCode(...bytes));
  const expected = ["\u001b", "\u001b[A", "\u0003", "\u001b[6~", "|"];
  if (JSON.stringify(keyBytes) !== JSON.stringify(expected)) fail(context, "key bar bytes " + JSON.stringify(keyBytes));
  await shot(page, "keybar", context);
  await layout(page, context, "keybar", narrow);
  if (!narrow) await page.click("button[data-action=keys]");

  await page.click(".term-host");
  await page.keyboard.press("Control+Alt+Escape");
  const left = await page.evaluate(() => document.activeElement && document.activeElement.className);
  if (!String(left).startsWith("statusbar")) fail(context, "Ctrl+Alt+Esc did not move focus out of the terminal: " + left);
  await page.keyboard.press("Tab");
  const ring = await page.evaluate(() => {
    const style = getComputedStyle(document.activeElement);
    return { tag: document.activeElement.textContent.trim(), style: style.outlineStyle, width: parseFloat(style.outlineWidth) };
  });
  if (ring.style === "none" || ring.width < 2) fail(context, `no focus ring on ${ring.tag}`);
  await page.click(".term-host");
  await page.keyboard.press("Control+c");

  await page.keyboard.type("bracketed");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(300);
  const pasteFrom = session.input.length;
  await page.evaluate(() => {
    const data = new DataTransfer();
    data.setData("text/plain", "a\u001b[201~b\u009b");
    document.querySelector(".term-host textarea").dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }));
  });
  await until(() => session.input.length > pasteFrom, "the pasted bytes", context);
  const pasted = session.input.slice(pasteFrom).map((bytes) => String.fromCharCode(...bytes)).join("");
  if (pasted !== "\u001b[200~a[201~b\u001b[201~") fail(context, "the paste reached the node as " + JSON.stringify(pasted));
  await page.keyboard.press("Control+c");

  await page.evaluate(() => window.__terms.at(-1).selectAll());
  await clickTool(page, "Copy selection", narrow);
  await page.waitForFunction(() => /Selection copied/.test(document.querySelector(".term-note")?.textContent || ""), null, { timeout: 4000 }).catch(() => fail(context, "the Copy selection button did not copy"));
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  if (!copied.includes("echo hello")) fail(context, "the copied text was " + JSON.stringify(copied.slice(0, 80)));
  await page.evaluate(() => navigator.clipboard.writeText("from-the-button"));
  const buttonPasteFrom = session.input.length;
  await page.click("button:has-text('Paste')");
  await until(() => session.input.slice(buttonPasteFrom).map((bytes) => String.fromCharCode(...bytes)).join("").includes("[200~from-the-button"), "the Paste button bytes", context);
  await page.click(".term-host");
  const frameRing = await page.evaluate(() => {
    const style = getComputedStyle(document.querySelector(".term-frame"));
    return { style: style.outlineStyle, width: parseFloat(style.outlineWidth), color: style.outlineColor };
  });
  if (frameRing.style === "none" || frameRing.width < 2) fail(context, "no focus ring around the terminal while it has focus: " + JSON.stringify(frameRing));
  await page.keyboard.press("Control+c");

  const titleBefore = await page.title();
  const clipboardBefore = await page.evaluate(() => window.__clipboard);
  const requestsBefore = requests.length;
  const scriptsBefore = await page.evaluate(() => document.querySelectorAll("script").length);
  const hostileFrom = session.input.length;
  await page.keyboard.type("hostile");
  await page.keyboard.press("Enter");
  await waitForText(page, "end of hostile output", context, 20000);
  await page.waitForTimeout(500);
  await shot(page, "hostile", context);
  await layout(page, context, "hostile", narrow);
  const hostile = await page.evaluate(() => ({
    clipboard: window.__clipboard,
    opened: window.__opened,
    pwned: window.__pwned,
    longest: Math.max(0, ...window.__long),
    foreign: document.querySelectorAll("main img, main iframe, main object, main embed, main svg:not(.icon), main style, main script, .term-host a").length,
    scripts: document.querySelectorAll("script").length,
    hash: location.hash,
  }));
  if ((await page.title()) !== titleBefore) fail(context, "hostile output changed the page title");
  if (hostile.clipboard !== clipboardBefore) fail(context, "hostile output touched the clipboard");
  if (hostile.opened !== 0) fail(context, "hostile output opened a window");
  if (hostile.pwned !== undefined) fail(context, "hostile output ran script");
  if (hostile.foreign !== 0) fail(context, "hostile output created elements");
  if (hostile.scripts !== scriptsBefore) fail(context, "hostile output added a script");
  if (hostile.hash !== "#/terminal?node=web-01&login=deploy" && hostile.hash !== "#/terminal") fail(context, "hostile output navigated to " + hostile.hash);
  if (hostile.longest >= 500) fail(context, `hostile output kept the main thread busy for ${Math.round(hostile.longest)} ms`);
  notes.push(`${context}: longest main-thread task during the hostile stream ${Math.round(hostile.longest)} ms`);
  const foreign = requests.slice(requestsBefore).filter((url) => !url.startsWith(stub.origin + "/"));
  if (foreign.length > 0) fail(context, "hostile output caused requests: " + foreign.join(", "));
  const fromHostile = session.input.slice(hostileFrom).map((bytes) => String.fromCharCode(...bytes)).join("");
  if (fromHostile.replace("hostile\r", "") !== "") fail(context, "hostile output made the page send " + JSON.stringify(fromHostile));

  const beforeQueries = session.input.length;
  await page.keyboard.type("queries");
  await page.keyboard.press("Enter");
  await waitForText(page, "end of queries", context);
  await page.waitForTimeout(500);
  const replies = session.input.slice(beforeQueries).map((bytes) => String.fromCharCode(...bytes)).join("").replace("queries\r", "");
  if (!ALLOWED_REPLY.test(replies)) fail(context, "unexpected reply to terminal queries: " + JSON.stringify(replies));
  const replyCount = (replies.match(/\u001b/g) || []).length;
  if (replyCount > 16) fail(context, `${replyCount} replies to queries, over the budget`);
  if (replyCount === 0) fail(context, "no reply at all to the allowed queries");
  if (/\]52|\]10|\]11|\$y|\$r|\[8;|\[4;|\[3;|\[2;/.test(replies.replace(/\u001b\[\d+;\d+R/g, ""))) fail(context, "a blocked reply was sent: " + JSON.stringify(replies));
  notes.push(`${context}: replies to the query stream: ${JSON.stringify(replies)}`);
  await shot(page, "queries", context);

  for (const command of ["flood4k", "flood86k", "bypassnul", "bypassdel", "bypass8bit", "bypasssplit", "delflood", "marks3"]) {
    await page.evaluate(() => {
      window.__drift = 0;
      window.__long.length = 0;
    });
    const started = Date.now();
    await page.keyboard.type(command);
    await page.keyboard.press("Enter");
    await waitForText(page, "end of " + command, context, 30000);
    const rendered = await Promise.race([page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve(true))))), new Promise((resolve) => setTimeout(() => resolve(false), 5000))]);
    if (!rendered) {
      fail(context, `${command}: the page stopped drawing`);
      fatal(`${context}: ${command} hung the page`);
    }
    if (command === "marks3") {
      const shown = await screenText(page);
      const six = "e" + String.fromCodePoint(...Array.from({ length: 6 }, (_, offset) => 0x300 + offset));
      if (!shown.includes(six)) fail(context, "marks3: the first six marks are not on the screen");
      if (shown.includes(six + String.fromCodePoint(0x306))) fail(context, "marks3: more than six marks reached the screen");
    }
    const flood = await page.evaluate(() => ({ task: Math.max(0, ...window.__long), drift: window.__drift }));
    if (flood.task >= 500) fail(context, `${command} blocked the main thread for ${Math.round(flood.task)} ms`);
    if (flood.drift >= 500) fail(context, `${command} stopped the timers for ${Math.round(flood.drift)} ms`);
    if (Date.now() - started > 5000) fail(context, `${command} took ${Date.now() - started} ms end to end`);
    notes.push(`${context}: ${command} took ${Date.now() - started} ms end to end, longest task ${Math.round(flood.task)} ms, longest timer delay ${Math.round(flood.drift)} ms`);
  }

  await clickTool(page, "Disconnect", narrow);
  const dialog = await page.waitForSelector("[role=dialog]", { timeout: 2000 }).catch(() => null);
  if (!dialog) fail(context, "no confirmation after typing");
  else {
    await shot(page, "confirm", context);
    await page.click("[role=dialog] button:has-text('Keep working')");
  }

  const floodReplyFrom = session.input.length;
  await page.keyboard.type("queryflood");
  await page.keyboard.press("Enter");
  await waitForText(page, "end of queryflood", context, 30000);
  await page.waitForTimeout(300);
  const floodReplies = session.input.slice(floodReplyFrom).map((bytes) => String.fromCharCode(...bytes)).join("").replace("queryflood\r", "");
  const floodCount = (floodReplies.match(/\u001b/g) || []).length;
  if (floodCount > 32) fail(context, `${floodCount} replies to a flood of position queries`);
  await page.keyboard.type("exit");
  await page.keyboard.press("Enter");
  await page.waitForSelector(".term-banner:has-text('Session ended')", { timeout: 6000 }).catch(() => fail(context, "no ended banner after exit"));
  const endedText = await page.textContent(".term-banner");
  if (!/exited with status 0/.test(endedText)) fail(context, "the ended banner says: " + endedText.slice(0, 120));
  await shot(page, "ended", context);
  await layout(page, context, "ended", narrow);
  const sessionsBefore = stub.terminal.sessions.length;
  await page.waitForTimeout(1500);
  if (stub.terminal.sessions.length !== sessionsBefore) fail(context, "the page reconnected by itself");

  await page.click("button:has-text('Reconnect')");
  await until(() => stub.terminal.sessions.length === sessionsBefore + 1, "the new session", context);
  await waitForText(page, "deploy@web-01", context);
  const second = stub.terminal.sessions.at(-1);
  const screenAfter = await screenText(page);
  if (screenAfter.includes("hello")) fail(context, "the old screen was not cleared on reconnect");
  await shot(page, "reconnected", context);
  await page.waitForTimeout(1200);
  if (second.input.length > 0) fail(context, "the new session received bytes nobody typed: " + JSON.stringify(second.input.map((bytes) => String.fromCharCode(...bytes)).join("")));

  second.sendText({ t: "error", code: "revoked" });
  second.close(4001, "revoked");
  await page.waitForSelector(".term-banner:has-text('Access revoked')", { timeout: 6000 }).catch(() => fail(context, "no revoked banner"));
  await shot(page, "revoked", context);
  await layout(page, context, "revoked", narrow);
  const revokedActions = await page.locator(`${PANE} .term-banner .actions .btn`).allTextContents();
  if (revokedActions.join() !== "Close terminal") fail(context, "the revoked banner offers " + revokedActions.join());
  await page.click(`${PANE} .term-banner button:has-text('Close terminal')`);
  await page.waitForSelector(".panel.quick");

  stub.terminal.denyNext = { status: 403, body: { error: "denied", ref: "D-4C1E82A9" } };
  await quickOpen(page, "web-01", "deploy", narrow);
  await page.waitForSelector(".term-banner:has-text('Access denied')", { timeout: 6000 }).catch(() => fail(context, "no denied banner"));
  const deniedRef = await page.locator(".term-banner .ref .mono").textContent().catch(() => null);
  if (deniedRef !== "D-4C1E82A9") fail(context, "the denied banner shows the reference " + JSON.stringify(deniedRef));
  await shot(page, "denied", context);
  await layout(page, context, "denied", narrow);

  await page.click("button:has-text('Try again')");
  await until(() => stub.terminal.sessions.length === sessionsBefore + 2, "the third session", context);
  await waitConnected(page);
  const third = stub.terminal.sessions.at(-1);
  await page.goto(stub.origin + "/#/nodes");
  await page.waitForSelector(".node-card");
  await page.waitForTimeout(400);
  if (third.closed !== null) fail(context, "moving to the nodes page closed the session with " + third.closed);
  const railCount = await page.locator(".rail-count").textContent().catch(() => null);
  if (railCount !== "1") fail(context, "the rail count is " + JSON.stringify(railCount));
  await page.goto(stub.origin + "/#/terminal");
  await page.waitForSelector(`${PANE} .term-host canvas`);
  await waitConnected(page);
  await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
  await until(() => third.closed !== null, "the pagehide close of the third session", context);
  if (third.closed !== 1000) fail(context, "pagehide closed the socket with " + third.closed);
  await page.reload();
  await page.waitForSelector(".panel.quick");

  await openSession(page, stub, context, "web-02", null, narrow);
  const fourth = stub.terminal.sessions.at(-1);
  await page.evaluate(() => window.dispatchEvent(new Event("pagehide")));
  await until(() => fourth.closed !== null, "the pagehide close", context);
  await page.reload();
  await page.waitForSelector(".panel.quick");

  await navigationChecks(page, stub, context, width);

  const violations = await page.evaluate(() => window.__csp);
  if (violations.length > 0) fail(context, "CSP violations: " + violations.join("; "));
  const outside = requests.filter((url) => !url.startsWith(stub.origin + "/"));
  if (outside.length > 0) fail(context, "requests outside the console: " + outside.join(", "));
  const badSockets = sockets.filter((url) => !url.startsWith("ws://127.0.0.1:"));
  if (badSockets.length > 0) fail(context, "unexpected sockets: " + badSockets.join(", "));
  for (const problem of problems) fail(context, problem);
  await browserContext.close();
}

const REFUSALS = [
  ["account_refused", "H-9D0311FE", "Your account could not be created.", "refused"],
  ["account_failed", "H-51C07A42", "The node could not create your account.", "failed"],
  ["no_account", "H-0000000D", "There is no account deploy on web-02.", "no-account"],
];

async function openWeb02(page, stub, context, narrow) {
  const before = stub.terminal.sessions.length;
  await page.goto(stub.origin + "/#/nodes");
  await page.waitForSelector(".node-card");
  await page.goto(stub.origin + "/#/terminal");
  await page.waitForSelector(".panel.quick, .ws:not([hidden])");
  await closeAllTabs(page, narrow);
  await page.waitForSelector(".panel.quick");
  await quickOpen(page, "web-02", "deploy", narrow);
  await until(() => stub.terminal.sessions.length === before + 1, "the account session", context);
  return stub.terminal.sessions.at(-1);
}

async function runAccount(browser, stub, width, theme) {
  const context = `account-${theme}-${width}`;
  const narrow = width <= 520;
  const browserContext = await browser.newContext({ viewport: { width, height: width < 600 ? 800 : 900 }, colorScheme: theme, deviceScaleFactor: 1, reducedMotion: "reduce" });
  await browserContext.grantPermissions(["clipboard-read", "clipboard-write"], { origin: stub.origin });
  const { page, problems } = await instrument(browserContext, stub.origin);
  await page.goto(stub.origin + "/");
  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });

  await page.goto(stub.origin + "/#/terminal");
  await page.waitForSelector(".panel.quick");
  const marked = await page.locator(".quick-row:has(.badge.b-acct) .name").allTextContents();
  if (marked.join(",") !== "web-02") fail(context, "the Creates accounts marker is on " + JSON.stringify(marked));
  await trackTerminals(page);
  await shot(page, "account-picker", context);
  await layout(page, context, "account-picker", narrow);
  await page.click('.quick-row:has(.name:text-is("web-02")) button:has-text("Choose login")');
  await shot(page, "account-picker-chosen", context);
  await layout(page, context, "account-picker-chosen", narrow);

  await page.goto(stub.origin + "/#/nodes");
  await page.waitForSelector(".node-card");
  const cardMarks = await page.locator(".node-card:has(.badge.b-acct) .node-name").allTextContents();
  if (cardMarks.join(",") !== "web-02") fail(context, "the node cards with the marker are " + JSON.stringify(cardMarks));
  await page.click('button[aria-label="Connect to web-02"]');
  await page.waitForSelector(".menu .menu-info");
  await shot(page, "account-menu", context);
  await layout(page, context, "account-menu", narrow);
  await page.keyboard.press("Escape");

  stub.terminal.plan = { account: { home: "/home/deploy" } };
  const held = await openWeb02(page, stub, context, narrow);
  await page.waitForSelector(".term-banner:has-text('Creating your account deploy on web-02…')", { timeout: 6000 }).catch(() => fail(context, "no progress banner"));
  await shot(page, "account-creating", context);
  await layout(page, context, "account-creating", narrow);
  held.release();
  await page.waitForSelector(".term-banner:has-text('Account created.')", { timeout: 6000 }).catch(() => fail(context, "no created banner"));
  await waitConnected(page);
  const createdText = await page.locator(".term-banner").textContent();
  if (!createdText.includes("/home/deploy")) fail(context, "the created banner lacks the home path: " + createdText);
  await waitForText(page, "deploy@web-02", context);
  if ((await screenText(page)).includes("Account created")) fail(context, "the console wrote into the terminal area");
  await shot(page, "account-created", context);
  await layout(page, context, "account-created", narrow);
  await page.click(".term-banner button:has-text('Dismiss')");
  if ((await page.locator(".term-banner").textContent()) !== "") fail(context, "the created banner was not dismissed");

  for (const [code, reference, title, name] of REFUSALS) {
    stub.terminal.plan = { refuse: { code, ref: reference } };
    await openWeb02(page, stub, context, narrow);
    await page.waitForSelector(`.term-banner:has-text('${title}')`, { timeout: 6000 }).catch(() => fail(context, "no banner for " + code));
    const shown = await page.locator(".term-banner .ref .mono").textContent().catch(() => null);
    if (shown !== reference) fail(context, `${code} shows the reference ${JSON.stringify(shown)}`);
    await shot(page, "account-" + name, context);
    await layout(page, context, "account-" + name, narrow);
    if (name === "refused") {
      await page.click(".term-banner .ref button");
      await until(async () => (await page.evaluate(() => navigator.clipboard.readText())) === reference, "the copied reference", context);
    }
  }

  const violations = await page.evaluate(() => window.__csp);
  if (violations.length > 0) fail(context, "CSP violations: " + violations.join("; "));
  for (const problem of problems) fail(context, problem);
  notes.push(`${context}: Creates accounts marker on the picker and the node cards, the Connect menu note, the creating banner, the created banner with its home path, and ${REFUSALS.length} refusals with their references (Copy checked on the first)`);
  await browserContext.close();
}

async function runDisabled(browser, width) {
  const context = `disabled-${width}`;
  const stub = await startStub({ permissions: ["nodes.approve"] });
  const browserContext = await browser.newContext({ viewport: { width, height: 800 }, deviceScaleFactor: 1, reducedMotion: "reduce" });
  const { page, problems } = await instrument(browserContext, stub.origin);
  await page.goto(stub.origin + "/");
  await page.click("a.btn-primary");
  await page.waitForSelector(".rail a", { state: "attached" });
  await page.goto(stub.origin + "/#/terminal");
  await page.waitForSelector("text=The web terminal is turned off");
  await shot(page, "disabled", context);
  await layout(page, context, "disabled", width <= 520);
  if ((await page.locator('.rail a[href="#/terminal"]').count()) !== 0) fail(context, "the terminal area is still in the navigation");
  for (const problem of problems.filter((entry) => !/status of 404/.test(entry))) fail(context, problem);
  await browserContext.close();
  await stub.close();
}

async function runEmpty(browser, width) {
  const context = `empty-${width}`;
  const stub = await startStub({ permissions: [] });
  stub.setTargets([]);
  const browserContext = await browser.newContext({ viewport: { width, height: 800 }, deviceScaleFactor: 1, reducedMotion: "reduce" });
  const { page, problems } = await instrument(browserContext, stub.origin);
  await page.goto(stub.origin + "/");
  await page.click("a.btn-primary");
  await page.waitForSelector("text=No nodes available to you");
  await shot(page, "empty", context);
  await layout(page, context, "empty", width <= 520);
  for (const problem of problems) fail(context, problem);
  await browserContext.close();
  await stub.close();
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const stub = await startStub({ permissions: ["nodes.approve", "sessions.read", "audit.read"] });
  stub.setTargets(FLEET);
  const browser = await chromium.launch();
  try {
    for (const theme of THEMES) {
      for (const width of WIDTHS) {
        await runContext(browser, stub, width, theme);
        await runLongNames(browser, stub, width, theme);
        await runAccount(browser, stub, width, theme);
      }
    }
    for (const width of WIDTHS) {
      await runDisabled(browser, width);
      await runEmpty(browser, width);
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
    console.log("web terminal: picker, session, resize, key bar, hostile output, queries, close handling and CSP checks passed");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
