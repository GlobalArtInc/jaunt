export const failures = [];

export function fail(context, message) {
  failures.push(context + ": " + message);
}

export async function instrument(browserContext, origin) {
  await browserContext.addInitScript(() => {
    window.__csp = [];
    window.__clipboard = 0;
    window.__opened = 0;
    window.__long = [];
    window.__sockets = [];
    window.__drift = 0;
    let lastTick = performance.now();
    setInterval(() => {
      const now = performance.now();
      window.__drift = Math.max(window.__drift, now - lastTick - 20);
      lastTick = now;
    }, 20);
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
    if (navigator.clipboard && navigator.clipboard.readText) {
      const original = navigator.clipboard.readText.bind(navigator.clipboard);
      navigator.clipboard.readText = (...args) => {
        window.__clipboard += 1;
        return original(...args);
      };
    }
    const execCommand = document.execCommand.bind(document);
    document.execCommand = (name, ...rest) => {
      if (["copy", "cut", "paste"].includes(String(name).toLowerCase())) window.__clipboard += 1;
      return execCommand(name, ...rest);
    };
    const open = window.open.bind(window);
    window.open = (...args) => {
      window.__opened += 1;
      return open(...args);
    };
    const NativeSocket = window.WebSocket;
    window.WebSocket = function (url, protocols) {
      window.__sockets.push({ url: String(url), protocols: Array.isArray(protocols) ? protocols.slice() : [protocols] });
      return new NativeSocket(url, protocols);
    };
    window.WebSocket.prototype = NativeSocket.prototype;
    for (const name of ["CONNECTING", "OPEN", "CLOSING", "CLOSED"]) window.WebSocket[name] = NativeSocket[name];
  });
  const page = await browserContext.newPage();
  const problems = [];
  const requests = [];
  page.on("console", (message) => {
    const optional = /\/v1\/(client-config)$/.test(message.location().url || "") && /status of 404/.test(message.text());
    const refused = /status of (401|403|429)/.test(message.text()) || /WebSocket connection/.test(message.text());
    if ((message.type() === "error" || message.type() === "warning") && !optional && !refused) {
      problems.push("console " + message.type() + ": " + message.text().slice(0, 200));
    }
  });
  page.on("pageerror", (error) => problems.push("page error: " + String((error && error.stack) || error).replace(/\s+/g, " ").slice(0, 600)));
  page.on("dialog", async (dialog) => {
    problems.push("dialog: " + dialog.message().slice(0, 80));
    await dialog.dismiss();
  });
  page.on("request", (request) => requests.push(request.url()));
  page.on("requestfailed", (request) => problems.push("request failed: " + request.url()));
  return { page, problems, requests };
}

export async function layout(page, context, label, narrow) {
  const result = await page.evaluate((isNarrow) => {
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
    const lum = (rgb) => {
      const [r, g, b] = rgb.map((value) => value / 255).map((value) => (value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4));
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const small = [];
    const lowContrast = [];
    const walker = document.createTreeWalker(document.querySelector("main"), NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const text = walker.currentNode;
      const parent = text.parentElement;
      if (!parent || text.data.trim() === "" || parent.closest(".term-host, .visually-hidden")) continue;
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
    const targets = [];
    if (isNarrow) {
      for (const element of document.querySelectorAll(".term-pane:not([hidden]) .term-tools button, .term-pane:not([hidden]) .keybar button, .term-pane:not([hidden]) .statusbar button, .term-pane:not([hidden]) .term-banner button, .term-pane:not([hidden]) .term-banner a, .switcher button, .quick-row button, .pick-login")) {
        const box = element.getBoundingClientRect();
        if (box.width > 0 && box.height > 0 && box.height < 43.5) targets.push((element.textContent || element.getAttribute("aria-label") || element.className).trim().slice(0, 20) + " " + Math.round(box.height));
      }
    }
    const frame = document.querySelector(".term-pane:not([hidden]) .term-frame");
    const box = frame ? frame.getBoundingClientRect() : null;
    return {
      overflow: document.documentElement.scrollWidth - window.innerWidth,
      small,
      lowContrast,
      targets,
      frameRight: box ? Math.round(box.right) : null,
      frameHeight: box ? Math.round(box.height) : null,
      width: window.innerWidth,
    };
  }, narrow);
  if (result.overflow > 0) fail(context, `${label}: the page scrolls horizontally by ${result.overflow}px`);
  for (const entry of result.small) fail(context, `${label}: text under 13px: ${entry}`);
  for (const entry of result.lowContrast) fail(context, `${label}: contrast under 4.5: ${entry}`);
  for (const entry of result.targets) fail(context, `${label}: touch target under 44px: ${entry}`);
  if (result.frameRight !== null && result.frameRight > result.width) fail(context, `${label}: the terminal sticks out of the viewport`);
  return result;
}

export async function until(check, description, context, timeout = 6000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await check()) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  fail(context, "timed out waiting for " + description);
  return false;
}

export const PANE = ".term-pane:not([hidden])";

export async function quickOpen(page, node, login, narrow) {
  const inline = (await page.locator(".panel.quick").count()) > 0;
  if (!inline && (await page.locator(".modal.quick").count()) === 0) {
    if (narrow) await page.click('.switcher .icon-btn[aria-label="New terminal"]');
    else await page.click('.tabbar button:has-text("New terminal")');
    await page.waitForSelector(".modal.quick");
  }
  const scope = inline ? ".panel.quick" : ".modal.quick";
  const row = `${scope} .quick-row:has(.name:text-is("${node}"))`;
  if ((await page.locator(`${row} button:has-text("Choose login")`).count()) > 0) await page.click(`${row} button:has-text("Choose login")`);
  if (login !== null) await page.click(`${row} label.pick-login:has(input[value="${login}"])`);
  await page.click(`${scope} footer .btn-primary`);
}

export async function waitConnected(page) {
  await page.waitForFunction(() => /Connected/.test(document.querySelector(".term-pane:not([hidden]) .statusbar [role=status]")?.textContent || ""), null, { timeout: 8000 });
}

export async function clickTool(page, label, narrow) {
  if (!narrow) {
    await page.click(`${PANE} button:text-is("${label}")`);
    return;
  }
  await page.click(`${PANE} .term-tools .n-flex button`);
  await page.click(`.menu [role=menuitem]:has-text("${label}")`);
}

export async function closeAllTabs(page, narrow) {
  for (let round = 0; round < 8; round += 1) {
    if ((await page.locator(".ws:not([hidden])").count()) === 0) return;
    const panes = await page.locator(".term-pane").count();
    if (narrow && (await page.locator(`${PANE} .term-tools`).isVisible())) {
      await page.click(`${PANE} .term-tools .n-flex button`);
      await page.click('.menu [role=menuitem]:has-text("Close terminal")');
    } else if (narrow) {
      await page.click(".switcher-btn");
      await page.click('.menu [role=menuitem]:has-text("Close ended terminals")');
    } else {
      await page.click(".ttab button[aria-label^='Close ']");
    }
    const confirm = await page.waitForSelector("[role=dialog] button:has-text('Close terminal')", { timeout: 300 }).catch(() => null);
    if (confirm) await confirm.click();
    await page.waitForFunction((count) => document.querySelectorAll(".term-pane").length < count, panes, { timeout: 5000 });
  }
}

