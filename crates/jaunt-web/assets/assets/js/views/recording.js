import { el, replace } from "../dom.js";
import { bytes, clean, time } from "../format.js";
import { CAST_LIMITS, CastError, readCast } from "../recording/cast.js";
import { SPEEDS, createDriver, realClock } from "../recording/driver.js";
import { createTerminalSink, loadTerminalLibraries } from "../recording/terminal.js";
import { isUnsafeTerminalError } from "../terminal/cells.js";
import { S } from "../strings.js";
import { badge, banner, button, facts, linkButton, panel } from "../ui.js";

const SESSIONS = "/v1/admin/sessions";
const SKIP_SECONDS = 5;
const PAGE_SECONDS = 30;
const SEEK_STEPS_PER_SECOND = 10;
const STATE_BADGES = {
  none: ["off", () => S.recording.stateNone],
  receiving: ["info", () => S.recording.stateReceiving],
  complete: ["ok", () => S.recording.stateComplete],
  incomplete: ["warn", () => S.recording.stateIncomplete],
};
const KIND_TEXT = { shell: () => S.recording.kindShell, exec: () => S.recording.kindExec, sftp: () => S.recording.kindSftp };

export const playerHooks = {
  loadLibraries: () => loadTerminalLibraries(),
  createSink: (options) => createTerminalSink(options),
  clock: realClock,
};

export function clockText(seconds) {
  const whole = Math.max(0, Math.floor(Number.isFinite(seconds) ? seconds : 0));
  const hours = Math.floor(whole / 3600);
  const minutes = Math.floor((whole % 3600) / 60);
  const rest = String(whole % 60).padStart(2, "0");
  return hours > 0 ? hours + ":" + String(minutes).padStart(2, "0") + ":" + rest : minutes + ":" + rest;
}

function limitsFor(manifest) {
  const limit = manifest.playback_limit_bytes;
  return Number.isFinite(limit) && limit > 0 ? { ...CAST_LIMITS, maxBytes: limit } : CAST_LIMITS;
}

function stateOf(session) {
  const value = typeof session.recording === "string" ? session.recording : session.recording && session.recording.state;
  return Object.hasOwn(STATE_BADGES, value) ? value : "none";
}

function downloadLink(base, label) {
  try {
    return linkButton(label, base + "?download=1");
  } catch {
    return null;
  }
}

function failureText(error) {
  const status = error && typeof error.status === "number" ? error.status : -1;
  if (status === 0) {
    return S.recording.network;
  }
  if (status === 403) {
    return S.recording.denied;
  }
  if (status === 404) {
    return S.recording.gone;
  }
  if (status === 409) {
    return S.recording.notReady;
  }
  return S.recording.failed;
}

function statusLine(state) {
  const [kind, text] = STATE_BADGES[state];
  return el("p", { class: "recording-state" }, badge(kind, text()));
}

export function recordingPanel(ctx, session) {
  const body = el("div", { class: "recording" });
  const base = SESSIONS + "/" + encodeURIComponent(session.id) + "/recording";
  const state = stateOf(session);
  let live = null;

  function teardown() {
    if (live !== null) {
      live.dispose();
      live = null;
    }
  }
  ctx.onCleanup(teardown);

  function show(...children) {
    teardown();
    replace(body, ...children);
  }

  function retryButton(action) {
    return button(S.recording.retry, { kind: "primary", onClick: action });
  }

  function failure(error, retry) {
    const parts = [banner("danger", failureText(error))];
    const actions = [];
    if (error && (error.status === 409 || error.status === 0 || error.status >= 500 || error.status === undefined)) {
      actions.push(retryButton(retry));
    }
    show(statusLine(state), ...parts, actions.length > 0 ? el("div", { class: "actions" }, ...actions) : null);
  }

  async function loadManifest() {
    show(statusLine(state), el("p", { class: "muted", role: "status", text: S.recording.loading }));
    let manifest;
    try {
      manifest = await ctx.api.get(base + "/manifest");
    } catch (error) {
      if (ctx.isCurrent() && error.status !== 401) {
        failure(error, loadManifest);
      }
      return;
    }
    if (ctx.isCurrent()) {
      showManifest(manifest);
    }
  }

  function manifestFacts(manifest) {
    return facts([
      [S.recording.kind, KIND_TEXT[manifest.kind] ? KIND_TEXT[manifest.kind]() : clean(manifest.kind)],
      [S.recording.command, manifest.command ? clean(manifest.command) : null, { mono: true }],
      [S.recording.started, Number.isFinite(manifest.started_at) ? time(manifest.started_at) : null],
      [S.recording.ended, Number.isFinite(manifest.ended_at) ? time(manifest.ended_at) : null],
      [S.recording.size, manifest.has_cast ? bytes(manifest.raw_bytes) : null],
      [S.recording.chunks, manifest.has_cast ? String(manifest.chunks) : null],
      [S.recording.inputRecorded, manifest.input_recorded ? S.recording.inputRecordedYes : S.recording.inputRecordedNo],
    ]);
  }

  function showManifest(manifest) {
    const notices = manifestBanners(manifest);
    const download = manifest.has_cast ? downloadLink(base, S.recording.download) : null;
    const oversize = manifest.has_cast && Number.isFinite(manifest.playback_limit_bytes) && manifest.raw_bytes > manifest.playback_limit_bytes;
    const actions = [];
    if (!manifest.has_cast) {
      notices.push(el("p", { class: "muted", text: S.recording.metadataOnly }));
    } else if (oversize) {
      notices.push(banner("info", S.recording.tooLarge(bytes(manifest.playback_limit_bytes))));
    } else {
      actions.push(button(S.recording.watch, { kind: "primary", onClick: () => watch(manifest) }));
    }
    if (download) {
      actions.push(download);
    }
    show(statusLine(state), manifestFacts(manifest), ...notices, actions.length > 0 ? el("div", { class: "actions" }, ...actions) : null);
  }

  async function watch(manifest) {
    const controller = new AbortController();
    show(statusLine(state), el("p", { class: "muted", role: "status", text: S.recording.loading }));
    live = { dispose: () => controller.abort() };
    let cast;
    let libraries;
    try {
      libraries = await playerHooks.loadLibraries();
      const response = await ctx.api.stream(base, controller.signal);
      if (!response.body) {
        throw new CastError("no_body");
      }
      cast = await readCast(response.body, { signal: controller.signal, limits: limitsFor(manifest) });
    } catch (error) {
      if (controller.signal.aborted || !ctx.isCurrent() || error.status === 401) {
        return;
      }
      streamFailure(error, manifest);
      return;
    }
    if (!ctx.isCurrent() || controller.signal.aborted) {
      return;
    }
    mountPlayer(cast, manifest, libraries);
  }

  function streamFailure(error, manifest) {
    if (error instanceof CastError) {
      const text = error.code === "too_large" ? S.recording.overCap : error.code === "bad_header" ? S.recording.unreadable : S.recording.failed;
      show(statusLine(state), banner("danger", text), el("div", { class: "actions" }, downloadLink(base, S.recording.download)));
    } else if (error && error.status === 413) {
      show(statusLine(state), banner("info", S.recording.tooLarge(bytes(manifest.playback_limit_bytes))), el("div", { class: "actions" }, downloadLink(base, S.recording.download)));
    } else {
      failure(error, () => watch(manifest));
    }
  }

  function mountPlayer(cast, manifest, libraries) {
    const screen = el("div", { class: "player-screen", role: "region", "aria-label": S.recording.screen, tabindex: "0" });
    const playButton = button(S.recording.play, { kind: "primary" });
    const restartButton = button(S.recording.restart);
    const speedSelect = el("select", { id: "player-speed" }, SPEEDS.map((value) => el("option", { value: String(value), text: S.recording.speedOption(value) })));
    speedSelect.value = "1";
    const seek = el("input", { type: "range", id: "player-seek", min: "0", max: "0", step: "1", value: "0" });
    const timeText = el("span", { class: "player-time", text: "" });
    const announce = el("p", { class: "visually-hidden", role: "status" });
    const compress = el("input", { type: "checkbox", id: "player-compress", checked: true });
    const inputToggle = el("input", { type: "checkbox", id: "player-input" });
    const showInputControl = manifest.input_recorded && cast.hasInput;

    const skipped = cast.skipped > 0 ? el("p", { class: "muted", role: "status", text: S.recording.skipped(cast.skipped) }) : null;
    const download = downloadLink(base, S.recording.download);
    const controls = el(
      "div",
      { class: "player-controls" },
      playButton,
      restartButton,
      el("div", { class: "player-field" }, el("label", { for: "player-speed", text: S.recording.speed }), speedSelect),
      el("div", { class: "player-seek" }, el("label", { for: "player-seek", text: S.recording.seek }), seek),
      timeText,
    );
    const options = el(
      "div",
      { class: "player-options" },
      el("div", { class: "check" }, compress, el("label", { for: "player-compress" }, S.recording.compress, el("span", { class: "field-hint", text: " " + S.recording.compressHint }))),
      showInputControl ? el("div", { class: "check" }, inputToggle, el("label", { for: "player-input", text: S.recording.showInput })) : null,
    );
    const player = el(
      "div",
      { class: "player" },
      controls,
      screen,
      announce,
      options,
      manifest.input_recorded ? banner("warn", S.recording.inputWarning) : null,
      skipped,
      el("p", { class: "muted small", text: S.recording.shortcuts }),
      el("div", { class: "actions" }, download),
    );
    show(statusLine(state), manifestFacts(manifest), ...manifestBanners(manifest), player);

    let sink;
    try {
      sink = playerHooks.createSink({ container: screen, cols: cast.header.cols, rows: cast.header.rows, libraries });
    } catch (error) {
      show(statusLine(state), banner("danger", isUnsafeTerminalError(error) ? S.recording.unsafe : S.recording.failed), el("div", { class: "actions" }, downloadLink(base, S.recording.download)));
      return;
    }
    const driver = createDriver({ cast, sink, clock: playerHooks.clock });
    live = {
      dispose: () => {
        driver.dispose();
        sink.dispose();
      },
    };

    let lastStatus = "paused";
    function paint(snapshot) {
      playButton.textContent = snapshot.status === "playing" ? S.recording.pause : S.recording.play;
      seek.max = String(Math.ceil(snapshot.duration * SEEK_STEPS_PER_SECOND));
      seek.value = String(Math.round(snapshot.position * SEEK_STEPS_PER_SECOND));
      const elapsed = clockText(snapshot.position);
      const total = clockText(snapshot.duration);
      seek.setAttribute("aria-valuetext", S.recording.seekValue(elapsed, total));
      timeText.textContent = S.recording.elapsed(elapsed, total);
      if (snapshot.status !== lastStatus) {
        lastStatus = snapshot.status;
        announce.textContent = S.recording.status[snapshot.status];
      }
    }
    driver.onChange(paint);
    paint(driver.snapshot());

    playButton.addEventListener("click", () => driver.toggle());
    restartButton.addEventListener("click", () => driver.restart());
    speedSelect.addEventListener("change", () => driver.setSpeed(Number(speedSelect.value)));
    seek.addEventListener("input", () => driver.seek(Number(seek.value) / SEEK_STEPS_PER_SECOND));
    compress.addEventListener("change", () => driver.setCompressIdle(compress.checked));
    inputToggle.addEventListener("change", () => driver.setShowInput(inputToggle.checked));
    player.addEventListener("keydown", (event) => handleKey(event, driver));
  }

  function manifestBanners(manifest) {
    const notices = [];
    if (manifest.incomplete) {
      notices.push(banner("warn", S.recording.incompleteTitle, S.recording.incompleteBody));
    }
    if (manifest.salvaged) {
      notices.push(banner("warn", S.recording.salvagedTitle, S.recording.salvagedBody));
    }
    return notices;
  }

  if (!ctx.can("recordings.read")) {
    replace(body, statusLine(state), state === "none" ? el("p", { class: "muted", text: S.recording.noneBody }) : banner("info", S.recording.noPermission, S.recording.noPermissionNeeded));
  } else if (state === "none") {
    replace(body, statusLine(state), el("p", { class: "muted", text: S.recording.noneBody }));
  } else if (state === "receiving") {
    replace(body, statusLine(state), el("p", { class: "muted", text: S.recording.receivingBody }), el("div", { class: "actions" }, button(S.recording.refresh, { onClick: () => ctx.reload() })));
  } else {
    loadManifest();
  }
  return panel(S.recording.heading, body);
}

function handleKey(event, driver) {
  if (event.altKey || event.ctrlKey || event.metaKey) {
    return;
  }
  const target = event.target;
  const tag = target && target.tagName ? target.tagName.toLowerCase() : "";
  const isRange = tag === "input" && target.type === "range";
  const takesKeys = tag === "button" || tag === "select" || tag === "a" || (tag === "input" && !isRange);
  if (takesKeys) {
    return;
  }
  let handled = true;
  if (event.key === "ArrowLeft") {
    driver.skip(-SKIP_SECONDS);
  } else if (event.key === "ArrowRight") {
    driver.skip(SKIP_SECONDS);
  } else if (event.key === "PageDown") {
    driver.skip(-PAGE_SECONDS);
  } else if (event.key === "PageUp") {
    driver.skip(PAGE_SECONDS);
  } else if (event.key === "Home") {
    driver.seek(0);
  } else if (event.key === "End") {
    driver.seek(Infinity);
  } else if (event.key === " ") {
    driver.toggle();
  } else {
    handled = false;
  }
  if (handled) {
    event.preventDefault();
  }
}
