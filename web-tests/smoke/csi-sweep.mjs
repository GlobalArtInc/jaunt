import { chromium } from "playwright";

import { startStub } from "./stub.mjs";

const LIMIT_MS = 500;
const GUARD_MS = Number(process.env.CSI_SWEEP_GUARD_MS || 120_000);
const COUNTS = ["999999999", "2147483647", "999999999;999999999"];
const PREFIXES = ["", "?", ">", "<", "="];
const INTERMEDIATES = ["", ...Array.from({ length: 16 }, (_, index) => String.fromCharCode(0x20 + index))];
const FINALS = (process.env.CSI_SWEEP_FINALS || "").split("").filter(Boolean).length > 0 ? process.env.CSI_SWEEP_FINALS.split("") : Array.from({ length: 0x7f - 0x40 }, (_, index) => String.fromCharCode(0x40 + index));

function groups() {
  const found = [];
  for (const prefix of PREFIXES) {
    for (const intermediate of INTERMEDIATES) {
      for (const count of COUNTS) {
        found.push({ prefix, intermediate, count });
      }
    }
  }
  return found;
}

async function sweepGroup(page, group) {
  return page.evaluate(
    async ({ prefix, intermediate, count, finals }) => {
      const timings = [];
      for (const final of finals) {
        const sequence = "\u001b[" + prefix + count + intermediate + final;
        window.__sink.write("\u001bcA" + sequence);
        const started = performance.now();
        await window.__sink.idle();
        timings.push([final, performance.now() - started]);
      }
      return timings;
    },
    { ...group, finals: FINALS },
  );
}

async function main() {
  const stub = await startStub({ permissions: [] });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  const problems = [];
  page.on("pageerror", (error) => problems.push("page error: " + String(error).slice(0, 200)));
  page.on("console", (message) => {
    if ((message.type() === "error" || message.type() === "warning") && !/status of 401/.test(message.text())) {
      problems.push("console " + message.type() + ": " + message.text().slice(0, 200));
    }
  });
  await page.goto(stub.origin + "/");
  await page.evaluate(async () => {
    const { createTerminalSink, loadTerminalLibraries } = await import("/assets/js/recording/terminal.js");
    const libraries = await loadTerminalLibraries();
    const host = document.createElement("div");
    document.body.appendChild(host);
    window.__sink = createTerminalSink({ container: host, cols: 80, rows: 24, libraries });
    window.__long = [];
    window.__gap = 0;
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) window.__long.push(entry.duration);
    }).observe({ type: "longtask", buffered: true });
    let last = performance.now();
    setInterval(() => {
      const now = performance.now();
      window.__gap = Math.max(window.__gap, now - last - 50);
      last = now;
    }, 50);
  });

  let tested = 0;
  let slowest = ["", 0];
  const slow = [];
  const failures = [];
  for (const group of groups()) {
    const label = `CSI ${group.prefix}${group.count}${group.intermediate}<final>`;
    let timings;
    try {
      timings = await Promise.race([sweepGroup(page, group), new Promise((_, reject) => setTimeout(() => reject(new Error("the page froze")), GUARD_MS))]);
    } catch (error) {
      failures.push(`${label}: ${error.message}`);
      break;
    }
    for (const [final, ms] of timings) {
      tested += 1;
      if (ms > slowest[1]) slowest = [label.replace("<final>", final), ms];
      if (ms >= LIMIT_MS) failures.push(`${label.replace("<final>", final)} took ${Math.round(ms)} ms`);
      else if (ms >= 150) slow.push(`${label.replace("<final>", final)} ${Math.round(ms)} ms`);
    }
  }

  if (failures.length === 0) {
    const longest = await page.evaluate(() => ({ task: Math.max(0, ...window.__long), gap: window.__gap }));
    if (longest.task >= LIMIT_MS) failures.push(`the longest main-thread task was ${Math.round(longest.task)} ms`);
    if (longest.gap >= LIMIT_MS) failures.push(`the page stopped answering timers for ${Math.round(longest.gap)} ms`);
    console.log(`longest main-thread task ${Math.round(longest.task)} ms, longest timer delay ${Math.round(longest.gap)} ms`);
    const responsive = await Promise.race([page.evaluate(() => 1 + 1), new Promise((resolve) => setTimeout(() => resolve(null), 5000))]);
    if (responsive !== 2) failures.push("the page does not answer after the sweep");
  }
  failures.push(...problems);
  console.log(`sequences tested: ${tested}; slowest ${slowest[0] ? JSON.stringify(slowest[0]) + " " + Math.round(slowest[1]) + " ms" : "none"}`);
  for (const entry of slow.slice(0, 10)) console.log("slow: " + entry);
  await browser.close();
  await stub.close();
  if (failures.length > 0) {
    console.error(`${failures.length} failure(s):`);
    for (const entry of failures.slice(0, 40)) console.error(" - " + entry);
    process.exitCode = 1;
  } else {
    console.log("csi sweep: no sequence kept the main thread for 500 ms or more");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
