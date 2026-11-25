import { chromium } from "playwright";

import { startStub } from "./stub.mjs";

const REPS = Number(process.env.C0_REPS || 50);
const SLOW_MS = Number(process.env.C0_SLOW_MS || 100);
const CASE_LIMIT_MS = Number(process.env.C0_CASE_LIMIT_MS || 10000);
const FINALS = ["L", "S", "T", "M", "Z", "@", "P", "X", "b"];
const SAMPLED_POSITIONS = [1, 2, 4, 6];
const TOKENS = 7;
const RUN_LIMIT_MS = 12 * 60 * 1000;
const CLOSE_MS = 5000;

function withDeadline(promise, ms) {
  let timer;
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ timeout: true }), ms);
  });
  return Promise.race([promise.then((value) => ({ value }), (error) => ({ error: String((error && error.message) || error).slice(0, 300) })), deadline]).finally(() => clearTimeout(timer));
}

function cases() {
  const found = [];
  for (let code = 0; code < 0x20; code += 1) {
    for (const final of FINALS) {
      for (let position = 0; position <= TOKENS; position += 1) {
        if (final !== FINALS[0] && !SAMPLED_POSITIONS.includes(position)) {
          continue;
        }
        for (const mode of ["raw", "writer"]) {
          found.push({ code, final, position, mode });
        }
      }
    }
  }
  return found;
}

async function setupLab() {
  const { createTerminalSink, createGuardedWriter, loadTerminalLibraries } = await import("/assets/js/recording/terminal.js");
  const libraries = await loadTerminalLibraries();
  const host = document.createElement("div");
  document.body.appendChild(host);
  const sink = createTerminalSink({ container: host, cols: 133, rows: 37, libraries });
  const terminal = sink.terminal;
  const encoder = new TextEncoder();
  const sentinel = () => new Promise((resolve) => terminal.write(" ", resolve));
  window.__runCase = async ({ code, final, position, mode, reps }) => {
    const tokens = ["\u001b", "[", "4", "9", "9", "9", final];
    const unit = [...tokens.slice(0, position), String.fromCharCode(code), ...tokens.slice(position)].join("");
    const text = ("x" + unit).repeat(reps);
    terminal.write("\u001bc");
    await sentinel();
    const started = performance.now();
    if (mode === "raw") {
      terminal.write(text);
    } else {
      const writer = createGuardedWriter(terminal, { setTimeout: (callback, ms) => setTimeout(callback, ms), clearTimeout: (id) => clearTimeout(id) });
      writer.write(encoder.encode(text));
      writer.dispose();
    }
    await sentinel();
    return performance.now() - started;
  };
}

async function main() {
  const stub = await startStub({ permissions: [] });
  const server = await chromium.launchServer();
  const child = server.process();
  const kill = (reason) => {
    console.error(reason);
    child.kill("SIGKILL");
    process.exit(1);
  };
  setTimeout(() => kill(`the sweep exceeded ${RUN_LIMIT_MS / 1000} s and was stopped`), RUN_LIMIT_MS).unref();
  const browser = await chromium.connect(server.wsEndpoint());
  let page = null;
  let cdp = null;
  const open = async () => {
    page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
    cdp = await page.context().newCDPSession(page);
    await page.goto(stub.origin + "/");
    const setup = await withDeadline(page.evaluate(setupLab), CASE_LIMIT_MS);
    if (setup.timeout || setup.error) kill(`the sweep page did not start: ${setup.error || "timeout"}`);
  };
  await open();
  const rows = new Map();
  const hung = [];
  const all = cases();
  for (const entry of all) {
    const row = rows.get(entry.code) || { code: entry.code, raw: [], writer: [] };
    rows.set(entry.code, row);
    const running = page.evaluate((value) => window.__runCase(value), { ...entry, reps: REPS });
    running.catch(() => undefined);
    const outcome = await withDeadline(running, CASE_LIMIT_MS);
    if (outcome.timeout || outcome.error) {
      hung.push(`0x${entry.code.toString(16).padStart(2, "0")} ${entry.final}${entry.position} ${entry.mode}: ${outcome.error || `no answer within ${CASE_LIMIT_MS} ms`}`);
      row[entry.mode].push(entry.final + entry.position + "!");
      await withDeadline(cdp.send("Runtime.terminateExecution"), 2000);
      const closed = await withDeadline(page.context().close(), CLOSE_MS);
      if (closed.timeout) kill("a hung sweep page could not be closed");
      await open();
      continue;
    }
    if (outcome.value > SLOW_MS) {
      row[entry.mode].push(entry.final + entry.position);
    }
  }
  await withDeadline(browser.close(), CLOSE_MS);
  await withDeadline(server.close(), CLOSE_MS);
  child.kill("SIGKILL");
  await stub.close();
  const hex = (code) => "0x" + code.toString(16).padStart(2, "0");
  console.log(`unit: x ESC [ 4 9 9 9 <final> with one C0 byte inserted before token 0..7 (7 = after the final); every position for L, positions ${SAMPLED_POSITIONS.join(",")} for ${FINALS.slice(1).join(" ")}; ${REPS} repetitions, slow above ${SLOW_MS} ms, a case without an answer within ${CASE_LIMIT_MS} ms is marked with !`);
  let slow = 0;
  for (const row of rows.values()) {
    slow += row.raw.length + row.writer.length;
    console.log(`${hex(row.code)} raw terminal slow at [${row.raw.join(",")}]  guarded writer slow at [${row.writer.join(",")}]`);
  }
  for (const entry of hung) console.error("hung: " + entry);
  if (!process.env.JAUNT_ASSETS && (slow > 0 || hung.length > 0)) {
    console.error(`${slow} slow cell(s) and ${hung.length} hung case(s) with every protection on`);
    process.exit(1);
  }
  console.log(process.env.JAUNT_ASSETS ? `experimental assets: matrix only, ${all.length} cases` : `c0 sweep: ${all.length} cases, no C0 byte at any position kept the main thread busy`);
  process.exit(0);
}

main().catch((error) => {
  console.error(String((error && error.stack) || error));
  process.exit(1);
});
