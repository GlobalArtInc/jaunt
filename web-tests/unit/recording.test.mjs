import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";

import { HOSTILE, SESSION_ID, castLines, recordingManifest, sessionDetail } from "../fixtures.mjs";
import { byText, click, json, mount, press, settle, signedIn, type, until } from "./support.mjs";

const VIEWS = "../../crates/jaunt-web/assets/assets/js/views/recording.js";
const SESSION = "GET /v1/admin/sessions/" + SESSION_ID;
const MANIFEST = "GET /v1/admin/sessions/" + SESSION_ID + "/recording/manifest";
const STREAM = "GET /v1/admin/sessions/" + SESSION_ID + "/recording";
const DOWNLOAD = "/v1/admin/sessions/" + SESSION_ID + "/recording?download=1";

let ui = null;
let hooks = null;
let original = null;
let sinks = [];
let clock = null;

function fakeClock() {
  const state = { time: 0, timers: [] };
  return {
    state,
    now: () => state.time,
    setTimeout(callback, ms) {
      const id = state.timers.length + 1;
      state.timers.push({ callback, at: state.time + ms, id });
      return id;
    },
    clearTimeout(id) {
      state.timers = state.timers.filter((timer) => timer.id !== id);
    },
    advance(ms) {
      const end = state.time + ms;
      for (;;) {
        const due = state.timers.filter((timer) => timer.at <= end).sort((a, b) => a.at - b.at)[0];
        if (!due) {
          break;
        }
        state.timers = state.timers.filter((timer) => timer !== due);
        state.time = Math.max(state.time, due.at);
        due.callback();
      }
      state.time = end;
    },
  };
}

beforeEach(async () => {
  ({ playerHooks: hooks } = await import(VIEWS));
  original = { ...hooks };
  sinks = [];
  clock = fakeClock();
  hooks.loadLibraries = async () => ({});
  hooks.createSink = (options) => {
    const sink = { options, ops: [], write: (text) => sink.ops.push(["write", text]), resize: () => {}, reset: () => sink.ops.push(["reset"]), dispose: () => (sink.disposed = true) };
    sinks.push(sink);
    return sink;
  };
  hooks.clock = clock;
});

afterEach(() => {
  Object.assign(hooks, original);
  if (ui) {
    ui.stop();
    ui = null;
  }
});

const castReply = (bytes) => ({ status: 200, raw: bytes, contentType: "application/x-asciicast" });
const SCRIPT = [[0.5, "o", "A"], [1, "o", "B"], [3, "o", "C"]];

function open(routes, permissions) {
  return mount({ ...signedIn(permissions), ...routes }, "#/sessions/" + SESSION_ID);
}

function streamCalls() {
  return ui.server.calls.filter((call) => call.path.includes("/recording"));
}

async function watch(extra = {}, cast = castLines(...SCRIPT), manifest = {}) {
  ui = await open({ [SESSION]: json(200, sessionDetail({ recording: "complete" })), [MANIFEST]: json(200, recordingManifest(manifest)), [STREAM]: castReply(cast), ...extra });
  click(byText(ui.root, "button", "Watch recording"));
  await until(() => ui.root.querySelector(".player"), "the player");
  await settle();
}

const panelText = () => ui.root.querySelector(".recording").textContent;

test("without recordings.read the panel says the content is hidden and makes no recording request", async () => {
  for (const recording of ["complete", "incomplete", "receiving", "none"]) {
    ui = await open({ [SESSION]: json(200, sessionDetail({ recording })) }, ["sessions.read"]);
    if (recording === "none") {
      assert.doesNotMatch(panelText(), /not its content|recordings\.read/);
      assert.match(panelText(), /No recording/);
    } else {
      assert.match(panelText(), /not its content/);
      assert.match(panelText(), /recordings\.read/);
    }
    assert.equal(streamCalls().length, 0, recording);
    assert.equal(byText(ui.root, "button", "Watch recording"), undefined);
    ui.stop();
    ui = null;
  }
});

test("a session with no recording and one still arriving explain themselves without a request", async () => {
  ui = await open({ [SESSION]: json(200, sessionDetail({ recording: "none" })) });
  assert.match(panelText(), /No recording/);
  assert.match(panelText(), /no recording/);
  assert.equal(streamCalls().length, 0);
  ui.stop();

  ui = await open({ [SESSION]: json(200, sessionDetail({ recording: "receiving" })) });
  assert.match(panelText(), /Receiving/);
  assert.match(panelText(), /still being uploaded/);
  assert.equal(streamCalls().length, 0);
  click(byText(ui.root, "button", "Check again"));
  await settle();
  assert.equal(ui.server.count("GET", "/v1/admin/sessions/" + SESSION_ID), 2);
});

test("a complete recording shows its facts and plays only after Watch is pressed", async () => {
  ui = await open({ [SESSION]: json(200, sessionDetail({ recording: "complete" })), [MANIFEST]: json(200, recordingManifest()), [STREAM]: castReply(castLines(...SCRIPT)) });
  assert.match(panelText(), /Complete/);
  assert.match(panelText(), /Interactive shell/);
  assert.match(panelText(), /4\.0 KiB/);
  assert.equal(ui.server.count("GET", "/v1/admin/sessions/" + SESSION_ID + "/recording/manifest"), 1);
  assert.equal(ui.server.count("GET", "/v1/admin/sessions/" + SESSION_ID + "/recording"), 0);
  const download = ui.root.querySelector('a[href$="download=1"]');
  assert.equal(download.getAttribute("href"), DOWNLOAD);
  assert.equal(download.textContent, "Download .cast");

  click(byText(ui.root, "button", "Watch recording"));
  await until(() => ui.root.querySelector(".player"), "the player");
  assert.equal(ui.server.count("GET", "/v1/admin/sessions/" + SESSION_ID + "/recording"), 1);
  assert.equal(sinks.length, 1);
  assert.equal(sinks[0].options.cols, 80);
  assert.equal(sinks[0].options.rows, 24);
  assert.equal(ui.root.querySelector(".player-time").textContent, "0:00 / 0:03");
});

test("play, pause, restart, speed and the seek bar drive the playback and the time display", async () => {
  await watch();
  const play = () => byText(ui.root, "button", "Play") || byText(ui.root, "button", "Pause");
  const writes = () => sinks[0].ops.filter((op) => op[0] === "write").map((op) => op[1]).join("");
  click(play());
  assert.equal(play().textContent, "Pause");
  clock.advance(1000);
  assert.equal(writes(), "AB");
  assert.equal(ui.root.querySelector(".player-time").textContent, "0:01 / 0:03");
  click(play());
  assert.equal(play().textContent, "Play");
  clock.advance(5000);
  assert.equal(writes(), "AB");

  const speed = ui.root.querySelector("#player-speed");
  assert.deepEqual(Array.from(speed.options).map((option) => option.textContent), ["0.5x", "1x", "2x", "4x", "8x"]);
  speed.value = "8";
  speed.dispatchEvent(new window.Event("change", { bubbles: true }));
  click(play());
  clock.advance(300);
  assert.equal(writes(), "ABC");
  assert.match(ui.root.querySelector('[role="status"].visually-hidden').textContent, /Finished/);

  const seek = ui.root.querySelector("#player-seek");
  assert.equal(seek.max, "30");
  type(seek, "7");
  assert.equal(ui.root.querySelector(".player-time").textContent, "0:00 / 0:03");
  assert.equal(seek.getAttribute("aria-valuetext"), "0:00 of 0:03");
  click(byText(ui.root, "button", "Restart"));
  assert.equal(ui.root.querySelector(".player-time").textContent, "0:00 / 0:03");
  assert.equal(play().textContent, "Pause");
});

test("the keyboard controls the player from the screen and from the seek bar", async () => {
  await watch();
  const screen = ui.root.querySelector(".player-screen");
  const seek = ui.root.querySelector("#player-seek");
  const time = () => ui.root.querySelector(".player-time").textContent;
  assert.equal(screen.getAttribute("tabindex"), "0");
  assert.ok(screen.getAttribute("aria-label"));

  assert.equal(press(screen, " ").defaultPrevented, true);
  assert.equal(byText(ui.root, "button", "Pause") !== undefined, true);
  press(screen, " ");
  assert.equal(byText(ui.root, "button", "Play") !== undefined, true);
  press(screen, "ArrowRight");
  assert.equal(time(), "0:03 / 0:03");
  press(seek, "ArrowLeft");
  assert.equal(time(), "0:00 / 0:03");
  press(seek, "End");
  assert.equal(time(), "0:03 / 0:03");
  press(seek, "Home");
  assert.equal(time(), "0:00 / 0:03");
  assert.equal(press(seek, "a").defaultPrevented, false);
  const playButton = byText(ui.root, "button", "Play");
  assert.equal(press(playButton, " ").defaultPrevented, false);
  assert.equal(press(screen, "ArrowRight", { ctrlKey: true }).defaultPrevented, false);
});

test("incomplete and salvaged recordings say what is wrong in plain words and are still playable", async () => {
  ui = await open({ [SESSION]: json(200, sessionDetail({ recording: "incomplete" })), [MANIFEST]: json(200, recordingManifest({ state: "incomplete", incomplete: true, salvaged: true })) });
  assert.match(panelText(), /Incomplete/);
  assert.match(panelText(), /Some parts are missing/);
  assert.match(panelText(), /Cut short by a server restart or timeout/);
  assert.ok(byText(ui.root, "button", "Watch recording"));
});

test("a metadata-only recording shows the command as text and offers nothing to play", async () => {
  const command = HOSTILE.tag + HOSTILE.control;
  ui = await open({ [SESSION]: json(200, sessionDetail({ recording: "complete" })), [MANIFEST]: json(200, recordingManifest({ kind: "exec", has_cast: false, command, raw_bytes: 0, chunks: 0 })) });
  assert.match(panelText(), /metadata only/);
  assert.match(panelText(), /<img src=x/);
  assert.equal(ui.root.querySelectorAll(".recording img, .recording a[href*='download']").length, 0);
  assert.equal(byText(ui.root, "button", "Watch recording"), undefined);
});

test("a recording over the playback limit offers only the download and never opens the stream", async () => {
  ui = await open({ [SESSION]: json(200, sessionDetail({ recording: "complete" })), [MANIFEST]: json(200, recordingManifest({ raw_bytes: 70 * 1024 * 1024 })) });
  assert.match(panelText(), /larger than the 64 MiB/);
  assert.equal(byText(ui.root, "button", "Watch recording"), undefined);
  assert.equal(ui.root.querySelector('a[href$="download=1"]').getAttribute("href"), DOWNLOAD);
  assert.equal(streamCalls().filter((call) => !call.path.endsWith("/manifest")).length, 0);
});

test("the size the browser accepts follows the limit the server announces", async () => {
  const cast = castLines(...SCRIPT, [4, "o", "x".repeat(400)]);
  ui = await open({ [SESSION]: json(200, sessionDetail({ recording: "complete" })), [MANIFEST]: json(200, recordingManifest({ raw_bytes: 100, playback_limit_bytes: 300 })), [STREAM]: castReply(cast) });
  click(byText(ui.root, "button", "Watch recording"));
  await until(() => ui.root.querySelector(".banner-danger"), "the size refusal");
  assert.match(panelText(), /too large to play in the browser/);
  assert.equal(sinks.length, 0);
  ui.stop();
  ui = null;

  await watch({}, cast, { raw_bytes: cast.length, playback_limit_bytes: cast.length });
  assert.equal(sinks.length, 1);
});

test("manifest errors get their own message and only recoverable ones offer a retry", async () => {
  const cases = [
    [403, /refused to show/, false],
    [404, /not available/, false],
    [409, /not ready yet/, true],
    [500, /could not be loaded/, true],
  ];
  for (const [status, message, retry] of cases) {
    ui = await open({ [SESSION]: json(200, sessionDetail({ recording: "complete" })), [MANIFEST]: json(status, { error: "x" }) });
    assert.match(panelText(), message, String(status));
    assert.equal(byText(ui.root, "button", "Try again") !== undefined, retry, String(status));
    ui.stop();
    ui = null;
  }
  ui = await open({
    [SESSION]: json(200, sessionDetail({ recording: "complete" })),
    [MANIFEST]: () => {
      throw new TypeError("offline");
    },
  });
  assert.match(panelText(), /Check the connection/);
});

test("stream errors are explained: too large, not ready, gone, refused and an unreadable header", async () => {
  const cases = [
    [{ status: 413, body: { error: "recording_too_large" } }, /larger than the 64 MiB/],
    [{ status: 409, body: { error: "recording_not_ready" } }, /not ready yet/],
    [{ status: 404, body: { error: "not_found" } }, /not available/],
    [{ status: 403, body: { error: "forbidden" } }, /refused to show/],
    [castReply(castLines().slice(0, 0)), /header is not valid/],
    [castReply(new TextEncoder().encode('{"version":1}\n')), /header is not valid/],
  ];
  for (const [reply, message] of cases) {
    await watchFailure(reply, message);
  }
});

async function watchFailure(reply, message) {
  ui = await open({ [SESSION]: json(200, sessionDetail({ recording: "complete" })), [MANIFEST]: json(200, recordingManifest()), [STREAM]: reply });
  click(byText(ui.root, "button", "Watch recording"));
  await until(() => ui.root.querySelector(".banner-danger, .banner-info"), "the failure notice");
  assert.match(panelText(), message);
  assert.equal(ui.root.querySelector(".player"), null);
  assert.equal(sinks.length, 0);
  ui.stop();
  ui = null;
}

test("a network failure while streaming offers another try", async () => {
  ui = await open({
    [SESSION]: json(200, sessionDetail({ recording: "complete" })),
    [MANIFEST]: json(200, recordingManifest()),
    [STREAM]: () => {
      throw new TypeError("offline");
    },
  });
  click(byText(ui.root, "button", "Watch recording"));
  await until(() => byText(ui.root, "button", "Try again"), "the retry button");
  assert.match(panelText(), /Check the connection/);
});

test("damaged lines are skipped, counted and reported while the rest plays", async () => {
  await watch({}, castLines([0.5, "o", "A"], "garbage", "[1,2", [1, "o", "B"]));
  assert.match(panelText(), /2 lines of the recording could not be read and were skipped/);
  const seek = ui.root.querySelector("#player-seek");
  press(seek, "End");
  assert.equal(sinks[0].ops.filter((op) => op[0] === "write").map((op) => op[1]).join(""), "AB");
});

test("typed input stays hidden unless the manifest says it was recorded and the toggle is on, with a warning", async () => {
  const withInput = castLines([0.5, "o", "$ "], [1, "i", "secret\r"], [1.5, "o", "ok"]);
  await watch({}, withInput);
  assert.equal(ui.root.querySelector("#player-input"), null);
  assert.equal(ui.root.querySelector(".banner-warn"), null);
  press(ui.root.querySelector("#player-seek"), "End");
  assert.equal(sinks[0].ops.filter((op) => op[0] === "write").map((op) => op[1]).join("").includes("secret"), false);
  ui.stop();
  ui = null;
  sinks = [];

  await watch({}, withInput, { input_recorded: true });
  const toggle = ui.root.querySelector("#player-input");
  assert.equal(toggle.checked, false);
  assert.match(ui.root.querySelector(".banner-warn").textContent, /passwords and other secrets/);
  press(ui.root.querySelector("#player-seek"), "End");
  const text = () => sinks[0].ops.filter((op) => op[0] === "write").map((op) => op[1]).join("");
  assert.equal(text().includes("secret"), false);
  toggle.checked = true;
  toggle.dispatchEvent(new window.Event("change", { bubbles: true }));
  assert.equal(text().endsWith("$ \u001b[7msecret^M\u001b[27mok"), true);
});

test("a recording without any input events shows no toggle even when input was recorded", async () => {
  await watch({}, castLines([0.5, "o", "A"]), { input_recorded: true });
  assert.equal(ui.root.querySelector("#player-input"), null);
  assert.match(ui.root.querySelector(".banner-warn").textContent, /passwords/);
});

test("hostile output reaches the emulator only as data and builds no element, link or script in the console", async () => {
  const hostile = "\u001b]0;pwned\u0007\u001b]52;c;aGk=\u0007\u001b]8;;javascript:alert(1)\u001b\\<img src=x onerror=window.__pwned=1>\u001b]8;;\u001b\\\u009d0;t\u009c";
  await watch({}, castLines([0.1, "o", hostile], [0.2, "o", HOSTILE.quote], [0.3, "o", "x".repeat(200_000)]));
  press(ui.root.querySelector("#player-seek"), "End");
  const written = sinks[0].ops.filter((op) => op[0] === "write").map((op) => op[1]).join("");
  assert.equal(written.includes(hostile), true);
  assert.equal(ui.root.querySelectorAll("img, script, iframe, object, embed, svg:not(.icon), style").length, 0);
  assert.equal(window.__pwned, undefined);
  assert.equal(document.title, "Session 5b1c0a42 · Jaunt");
  for (const link of ui.root.querySelectorAll("a[href]")) {
    assert.match(link.getAttribute("href"), /^(#\/[A-Za-z0-9\/_\-.~%:=&?+]*|\/v1\/admin\/sessions\/[0-9a-f-]{36}\/recording\?download=1|\/v1\/web\/login[?=A-Za-z0-9%._~-]*)$/);
  }
});

test("leaving the page disposes the player and the terminal", async () => {
  await watch();
  click(byText(ui.root, "button", "Play"));
  window.location.hash = "#/sessions";
  await until(() => sinks[0].disposed === true, "the terminal to be disposed");
  const timers = clock.state.timers.length;
  clock.advance(10_000);
  assert.equal(timers, 0);
});

test("every string the recording view uses is defined in the strings module", async () => {
  const { readFile } = await import("node:fs/promises");
  const { S } = await import("../../crates/jaunt-web/assets/assets/js/strings.js");
  for (const file of ["views/recording.js"]) {
    const source = await readFile(new URL("../../crates/jaunt-web/assets/assets/js/" + file, import.meta.url), "utf8");
    const used = new Set(Array.from(source.matchAll(/S\.recording\.(\w+)/g), (match) => match[1]));
    assert.ok(used.size > 20);
    for (const name of used) {
      assert.notEqual(S.recording[name], undefined, name);
    }
    assert.doesNotMatch(source, /(text|textContent|title): "[A-Za-z]/);
  }
});
