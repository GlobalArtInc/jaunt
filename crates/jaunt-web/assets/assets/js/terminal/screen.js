import { el, replace } from "../dom.js";
import { openConfirm } from "../dialog.js";
import { clean } from "../format.js";
import { icon } from "../icons.js";
import { menuButton } from "../menu.js";
import { S } from "../strings.js";
import { badge, banner, button } from "../ui.js";
import { isUnsafeTerminalError } from "./cells.js";
import { createConnection } from "./connection.js";
import { fitSize } from "./fit.js";
import { FONT_SIZES } from "./fonts.js";
import { terminalHooks } from "./hooks.js";
import { KEY_BAR, createModifiers, keySequence, sanitizePaste } from "./keys.js";
import { latencyBand, latencyBars, latencyTotal } from "./latency.js";
import { openingSteps } from "./steps.js";

const FONT_KEY = "jaunt-terminal-font";
const RESIZE_DEBOUNCE_MS = 150;
const INITIAL_SIZE = { cols: 80, rows: 24 };
const CAUSE_KINDS = { info: "info", warn: "warn", danger: "danger" };
const ACTIONS = {
  denied: ["retry", "another"],
  limit: ["retry", "show"],
  revoked: ["close"],
  disabled: ["close"],
  unsafe: ["close"],
  account_refused: ["login"],
  no_account: ["login"],
  account_failed: ["retry"],
};
const DEFAULT_ACTIONS = ["retry", "close"];
const SHORT_ID_CHARS = 8;
const IDLE_LOW_SECONDS = 30;
const MAX_IDLE_WARNING_SECONDS = 3600;
const GLYPHS = {
  connecting: ["st-off", "◌"],
  ready: ["st-ok", "●"],
  idle: ["st-warn", "▲"],
  endedInfo: ["st-off", "○"],
  endedBad: ["st-bad", "✕"],
};
const RECORDING_CLASSES = { full: "b-rec", output: "b-ro", off: "b-off" };

function readFontIndex() {
  try {
    const index = FONT_SIZES.indexOf(Number(localStorage.getItem(FONT_KEY)));
    return index === -1 ? 0 : index;
  } catch {
    return 0;
  }
}

function writeFontIndex(index) {
  try {
    localStorage.setItem(FONT_KEY, String(FONT_SIZES[index]));
  } catch {
    return;
  }
}

function lowerFirst(value) {
  return value === "" ? value : value[0].toLowerCase() + value.slice(1);
}

function combo(keys) {
  const parts = [];
  keys.forEach((key, index) => {
    if (index > 0) {
      parts.push("+");
    }
    parts.push(el("kbd", { text: key }));
  });
  return parts;
}

export function createSession(env, { node, login }) {
  const names = { node: clean(node), login: clean(login) };
  const label = names.login + "@" + names.node;
  const text = S.terminal.session;
  const modifiers = createModifiers();
  let fontIndex = readFontIndex();
  let terminal = null;
  let libraries = null;
  let connection = null;
  let generation = 0;
  let disposed = false;
  let active = false;
  let ticker = null;
  let resizeTimer = null;
  let stopObserving = null;
  let keysShown = terminalHooks.prefersKeyBar();
  let pasting = false;
  let writer = null;
  let tabState = "connecting";
  let stateWords = text.states.starting;
  let endedTitle = null;
  let wasReady = false;
  let stage = "ticket";
  let withAccount = false;
  let recording = null;
  let latency = null;
  let sessionId = null;
  let idle = null;
  let idleBanner = null;

  const clock = () => terminalHooks.connection.clock;

  const stateSlot = el("span", { class: "item-state", role: "status" });
  const timeText = el("span", { class: "mono term-elapsed", text: text.clock(0) });
  const idText = el("span", { class: "mono", text: "" });
  const idCopy = el("button", { type: "button", class: "icon-btn", "aria-label": text.copyId, on: { click: () => copySessionId() } }, icon("copy", { size: "sm" }));
  const idItem = el("span", { class: "item sid", hidden: true }, el("span", { class: "k", text: text.sessionLabel }), idText, idCopy);
  const latencyBarsNode = el("span", { class: "lat-bars", "aria-hidden": "true" }, el("i"), el("i"), el("i"));
  const latencyValue = el("span", { class: "mono", text: "" });
  const latencyWord = el("span", { class: "lat-word", text: "" });
  const latencyBox = el("span", { class: "lat" }, latencyBarsNode, latencyValue);
  const latencyItem = el("span", { class: "item", hidden: true }, el("span", { class: "k", text: text.latency }), latencyBox, latencyWord);
  const recordingItem = el("span", { class: "item", hidden: true });
  const leave = button(text.leave, { small: true, onClick: () => leaveTerminal() });
  leave.classList.add("w-only");
  const disconnect = button(text.disconnect, { small: true, onClick: () => requestDisconnect() });
  const statusBar = el(
    "div",
    { class: "statusbar sess-head", role: "group", "aria-label": text.statusLabel, tabindex: "-1" },
    el("span", { class: "item w-only" }, el("span", { class: "k", text: text.node }), el("span", { class: "mono", text: names.node })),
    el("span", { class: "item w-only" }, el("span", { class: "k", text: text.login }), el("span", { class: "mono", text: names.login })),
    el("span", { class: "item" }, el("span", { class: "k", text: text.state }), stateSlot),
    el("span", { class: "item" }, el("span", { class: "k", text: text.elapsed }), timeText),
    idItem,
    latencyItem,
    recordingItem,
    el("span", { class: "item push w-only" }, disconnect),
  );

  const copyButton = button(text.copy, { small: true, onClick: () => copySelection() });
  copyButton.classList.add("w-only");
  const pasteButton = button(text.paste, { small: true, onClick: () => pasteFromClipboard() });
  const smaller = button(text.fontSmallerGlyph, { small: true, onClick: () => changeFont(-1) });
  const larger = button(text.fontLargerGlyph, { small: true, onClick: () => changeFont(1) });
  smaller.setAttribute("aria-label", text.fontSmaller);
  larger.setAttribute("aria-label", text.fontLarger);
  smaller.classList.add("w-only");
  larger.classList.add("w-only");
  const sizeText = el("span", { class: "muted small term-size w-only" });
  const keysToggle = el(
    "button",
    { type: "button", class: "btn btn-sm", "aria-pressed": String(keysShown), data: { action: "keys" }, on: { click: () => toggleKeys() } },
    icon("keyboard", { size: "sm" }),
    el("span", { class: "w-only", text: text.keyBar }),
    el("span", { class: "n-only", text: text.keysShort }),
  );
  const moreMenu = menuButton({
    className: "btn btn-sm",
    align: "end",
    content: [el("span", { text: text.more }), icon("chevronDown", { size: "sm" })],
    items: () => moreEntries(),
  });
  moreMenu.element.classList.add("n-flex");
  const tools = el(
    "div",
    { class: "term-tools", role: "toolbar", "aria-label": text.toolsLabel },
    copyButton,
    pasteButton,
    el("span", { class: "tools-sep w-only", "aria-hidden": "true" }),
    smaller,
    sizeText,
    larger,
    keysToggle,
    el("span", { class: "push" }),
    leave,
    moreMenu.element,
  );
  const note = el("p", { class: "muted small term-note", role: "status" });
  const stepsSlot = el("div", { class: "term-steps" });
  const bannerSlot = el("div", { class: "term-banner" });
  const idleLive = el("p", { class: "visually-hidden", role: "status" });
  const host = el("div", { class: "term-host", role: "region", "aria-label": text.screen(names.login, names.node) });
  const frame = el("div", { class: "term-frame" }, host);
  const keyBar = el("div", { class: "keybar", role: "group", "aria-label": text.keyBarLabel, hidden: !keysShown });
  const keyButtons = new Map();
  for (const entry of KEY_BAR) {
    const [keyLabel, keyName] = text.keys[entry.id];
    const key = el("button", { type: "button", class: "key-btn", "aria-label": keyName, "aria-pressed": entry.kind === "modifier" ? "false" : null, data: { key: entry.id } }, keyLabel);
    key.addEventListener("mousedown", (event) => event.preventDefault());
    key.addEventListener("click", () => pressKey(entry));
    keyButtons.set(entry.id, key);
    keyBar.appendChild(key);
  }
  const sizeLine = el("span", { class: "mono w-only" });
  const latencyLine = el("span", { class: "w-only", hidden: true });
  const closingLine = el("span", {});
  const help = el(
    "p",
    { class: "term-status" },
    sizeLine,
    latencyLine,
    el("span", {}, text.focusStay, " ", combo(["Ctrl", "Alt", "Esc"]), " " + text.focusLeaves, el("span", { class: "w-only" }, ", ", combo(["Ctrl", "Alt", "PgUp"]), "/", el("kbd", { text: "PgDn" }), " " + text.focusSwitches), "."),
    closingLine,
  );
  const termCol = el("div", { class: "term-col" }, frame, keyBar, help);
  const split = el("div", { class: "ws-split" }, termCol);
  const pane = el("div", { class: "term-pane", role: "tabpanel", hidden: true }, statusBar, tools, note, stepsSlot, bannerSlot, idleLive, split);

  modifiers.onChange((state) => {
    for (const id of ["ctrl", "alt"]) {
      keyButtons.get(id).setAttribute("aria-pressed", String(state[id]));
    }
    if (state.ctrl || state.alt) {
      say(text.modifierOn([state.ctrl ? text.modifierNames.ctrl : null, state.alt ? text.modifierNames.alt : null].filter(Boolean).join("+")));
    }
  });

  function say(message) {
    note.textContent = message;
  }

  function changed() {
    env.onChange();
  }

  function moreEntries() {
    const entries = [
      { text: text.copy, onSelect: () => copySelection() },
      { text: text.fontSmaller, disabled: fontIndex === 0, onSelect: () => changeFont(-1) },
      { text: text.fontLarger, disabled: fontIndex === FONT_SIZES.length - 1, onSelect: () => changeFont(1) },
      { text: text.leave, onSelect: () => leaveTerminal() },
    ];
    if (tabState !== "endedInfo" && tabState !== "endedBad") {
      entries.push({ type: "separator" });
      entries.push({ text: text.disconnect, danger: true, onSelect: () => requestDisconnect() });
    }
    entries.push({ text: text.closeTerminal, onSelect: () => env.requestClose() });
    return entries;
  }

  function paintFont() {
    sizeText.textContent = text.fontSize(FONT_SIZES[fontIndex]);
    smaller.disabled = fontIndex === 0;
    larger.disabled = fontIndex === FONT_SIZES.length - 1;
  }

  function paintSize() {
    sizeLine.textContent = terminal === null ? "" : text.size(terminal.cols, terminal.rows);
  }

  function paintClosing() {
    closingLine.textContent = text.closingNote(env.terminalCount());
  }

  function setTab(next, words) {
    tabState = next;
    stateWords = words;
    changed();
  }

  function paintState(kind, words) {
    replace(stateSlot, badge(kind, words));
  }

  function paintSteps() {
    if (stage === null) {
      replace(stepsSlot);
      return;
    }
    const steps = openingSteps({ withAccount, current: stage });
    replace(
      stepsSlot,
      el(
        "ol",
        { class: "step-list", "aria-label": text.steps.label },
        steps.map((step, index) => {
          const caption = step.id === "node" ? text.steps.node(names.node) : text.steps[step.id];
          return el(
            "li",
            { class: step.done ? "done" : null, "aria-current": step.current ? "step" : null },
            el("span", { class: "num", "aria-hidden": step.done ? "true" : null, text: step.done ? text.steps.done : String(index + 1) }),
            el("span", { text: caption }),
            step.done ? el("span", { class: "visually-hidden", text: text.steps.doneWord }) : null,
          );
        }),
      ),
      el("p", { class: "muted small", text: text.notReadyNote }),
    );
  }

  function paintLatency() {
    if (latency === null) {
      latencyItem.hidden = true;
      latencyLine.hidden = true;
      latencyLine.textContent = "";
      return;
    }
    const total = latencyTotal(latency.clientMs, latency.nodeMs);
    const band = latencyBand(total);
    latencyBox.className = "lat lat-" + band;
    Array.from(latencyBarsNode.children).forEach((bar, index) => bar.classList.toggle("on", index < latencyBars(band)));
    latencyValue.textContent = text.latencyValue(Math.round(total));
    latencyWord.textContent = text.latencyWords[band];
    latencyItem.hidden = false;
    latencyLine.textContent = text.latencyDetail(Math.round(latency.clientMs), latency.nodeMs === null ? null : Math.round(latency.nodeMs));
    latencyLine.hidden = false;
  }

  function paintRecording() {
    if (recording === null) {
      replace(recordingItem);
      recordingItem.hidden = true;
      return;
    }
    const [long, short] = text.recording[recording];
    replace(recordingItem, el("span", { class: "badge " + RECORDING_CLASSES[recording] }, el("span", { class: "w-only", text: long }), el("span", { class: "n-only", text: short })));
    recordingItem.hidden = false;
  }

  function paintId() {
    if (sessionId === null) {
      idItem.hidden = true;
      return;
    }
    idText.textContent = sessionId.slice(0, SHORT_ID_CHARS);
    idItem.hidden = false;
  }

  function fit() {
    if (terminal === null || disposed) {
      return;
    }
    const next = fitSize(host, terminal);
    if (next !== null && (next.cols !== terminal.cols || next.rows !== terminal.rows)) {
      terminal.resize(next.cols, next.rows);
    }
    if (connection !== null) {
      connection.sendResize(terminal.cols, terminal.rows);
    }
    paintSize();
  }

  function scheduleFit() {
    if (disposed) {
      return;
    }
    if (resizeTimer !== null) {
      clock().clearTimeout(resizeTimer);
    }
    resizeTimer = clock().setTimeout(() => {
      resizeTimer = null;
      fit();
    }, RESIZE_DEBOUNCE_MS);
  }

  function changeFont(delta) {
    const next = Math.min(Math.max(fontIndex + delta, 0), FONT_SIZES.length - 1);
    if (next === fontIndex) {
      return;
    }
    fontIndex = next;
    writeFontIndex(fontIndex);
    if (terminal !== null) {
      terminal.options.fontSize = FONT_SIZES[fontIndex];
    }
    paintFont();
    scheduleFit();
  }

  function toggleKeys() {
    keysShown = !keysShown;
    keyBar.hidden = !keysShown;
    keysToggle.setAttribute("aria-pressed", String(keysShown));
    scheduleFit();
  }

  function focusTerminal() {
    if (terminal !== null && !disposed && active) {
      terminal.focus();
    }
  }

  function leaveTerminal() {
    if (terminal !== null) {
      terminal.blur();
    }
    statusBar.focus({ preventScroll: true });
    say(text.focusLeft);
  }

  function clearIdle() {
    if (idle === null) {
      return;
    }
    const shownBanner = idleBanner;
    idle = null;
    idleBanner = null;
    if (shownBanner !== null && shownBanner.isConnected) {
      replace(bannerSlot);
    }
    idleLive.textContent = "";
    if (tabState === "idle") {
      paintState("ok", text.states.ready);
      setTab("ready", S.terminal.tabs.states.ready);
    }
  }

  function sendUser(data) {
    if (connection === null) {
      return;
    }
    if (connection.sendInput(data)) {
      if (note.textContent !== "") {
        say("");
      }
      if (idle !== null) {
        connection.sendActive();
        clearIdle();
      }
    }
  }

  function onUserInput(data) {
    sendUser(typeof data === "string" && !pasting ? modifiers.applyToText(data) : data);
  }

  function onReply(reply) {
    if (connection !== null) {
      connection.sendInput(reply, { user: false });
    }
  }

  function disposeTerminal() {
    if (writer !== null) {
      writer.dispose();
      writer = null;
    }
    if (terminal !== null) {
      terminal.dispose();
      terminal = null;
    }
  }

  function pressKey(entry) {
    if (entry.kind === "modifier") {
      modifiers.toggle(entry.id);
      focusTerminal();
      return;
    }
    let data;
    if (entry.kind === "char") {
      data = modifiers.applyToText(entry.key);
    } else {
      const state = modifiers.state();
      const modes = terminal !== null ? terminal.modes : null;
      data = keySequence(entry.key, { applicationCursor: Boolean(modes && modes.applicationCursorKeysMode), ctrl: state.ctrl, alt: state.alt });
      modifiers.clear();
    }
    if (data !== null) {
      sendUser(data);
    }
    focusTerminal();
  }

  function pasteText(value) {
    if (connection === null || !connection.isReady() || terminal === null) {
      say(text.pasteNotReady);
      return;
    }
    pasting = true;
    try {
      terminal.paste(sanitizePaste(value));
    } finally {
      pasting = false;
    }
  }

  async function pasteFromClipboard() {
    const clipboard = terminalHooks.clipboard();
    if (!clipboard || typeof clipboard.readText !== "function") {
      say(text.pasteBlocked);
      return;
    }
    let value;
    try {
      value = await clipboard.readText();
    } catch {
      say(text.pasteBlocked);
      return;
    }
    if (disposed) {
      return;
    }
    pasteText(typeof value === "string" ? value : "");
    focusTerminal();
  }

  async function copySelection() {
    const selected = terminal !== null ? terminal.getSelection() : "";
    if (selected === "") {
      say(text.copyEmpty);
      return;
    }
    const clipboard = terminalHooks.clipboard();
    try {
      await clipboard.writeText(selected);
      say(text.copied);
    } catch {
      say(text.copyBlocked);
    }
  }

  async function copySessionId() {
    const clipboard = terminalHooks.clipboard();
    if (sessionId === null || !clipboard || typeof clipboard.writeText !== "function") {
      say(text.idCopyBlocked);
      return;
    }
    try {
      await clipboard.writeText(sessionId);
      say(text.idCopied);
    } catch {
      say(text.idCopyBlocked);
    }
  }

  function onPaste(event) {
    const data = event.clipboardData;
    event.preventDefault();
    event.stopPropagation();
    pasteText(data && typeof data.getData === "function" ? data.getData("text/plain") : "");
  }

  function onKey(event) {
    if (event.type === "keydown" && event.ctrlKey && event.altKey && event.key === "Escape") {
      event.preventDefault();
      leaveTerminal();
      return false;
    }
    if (event.type === "keydown" && event.ctrlKey && event.altKey && !event.shiftKey && !event.metaKey && (event.key === "PageUp" || event.key === "PageDown")) {
      return false;
    }
    return true;
  }

  function stopTicker() {
    if (ticker !== null) {
      clock().clearInterval(ticker);
      ticker = null;
    }
  }

  function startTicker() {
    stopTicker();
    if (!document.hidden) {
      ticker = clock().setInterval(paintTime, 1000);
    }
  }

  function onVisibility() {
    if (disposed || connection === null) {
      return;
    }
    if (document.hidden) {
      stopTicker();
    } else if (connection.isReady()) {
      connection.resume();
      paintTime();
      startTicker();
    }
  }

  function tickIdle() {
    if (idle === null) {
      return;
    }
    const left = Math.max(0, Math.ceil((idle.deadline - clock().now()) / 1000));
    idle.title.textContent = text.idle.title(text.countdown(left));
    if (!idle.announcedLow && left <= IDLE_LOW_SECONDS) {
      idle.announcedLow = true;
      idleLive.textContent = text.idle.announce(text.countdown(left));
    }
  }

  function paintTime() {
    if (connection !== null) {
      timeText.textContent = text.clock(connection.elapsedMs() / 1000);
    }
    tickIdle();
  }

  function dismissBanner() {
    replace(bannerSlot);
    focusTerminal();
  }

  function copyReference(value) {
    const clipboard = terminalHooks.clipboard();
    if (!clipboard || typeof clipboard.writeText !== "function") {
      say(text.reference.copyBlocked);
      return;
    }
    clipboard.writeText(value).then(
      () => say(text.reference.copied),
      () => say(text.reference.copyBlocked),
    );
  }

  function referenceLine(value) {
    const copy = button(text.reference.copy, { small: true, onClick: () => copyReference(value) });
    copy.setAttribute("aria-label", text.reference.copyLabel(value));
    copy.replaceChildren(icon("copy", { size: "sm" }), el("span", { text: text.reference.copy }));
    return el("p", { class: "ref small" }, el("span", { text: text.reference.label }), el("span", { class: "mono", text: value }), copy);
  }

  function keepOpen(event) {
    if (!terminalHooks.isGesture(event)) {
      return;
    }
    if (connection !== null) {
      connection.sendActive();
    }
    clearIdle();
    focusTerminal();
  }

  function showIdle(seconds) {
    const left = Math.min(seconds, MAX_IDLE_WARNING_SECONDS);
    const timeout = env.config().idleTimeoutSecs;
    const quiet = timeout === null ? null : Math.max(1, Math.round((timeout - left) / 60));
    const keep = button(text.idle.keep, { kind: "primary", small: true, onClick: keepOpen });
    const shown = banner("warn", text.idle.title(text.countdown(left)), text.idle.body(quiet), keep);
    shown.removeAttribute("role");
    idle = { deadline: clock().now() + left * 1000, title: shown.querySelector(".banner-title"), announcedLow: left <= IDLE_LOW_SECONDS };
    idleBanner = shown;
    replace(bannerSlot, shown);
    idleLive.textContent = text.idle.announce(text.countdown(left));
    paintState("warn", text.states.idle);
    setTab("idle", S.terminal.tabs.states.idle);
    if (!active) {
      env.announce(S.terminal.tabs.idleAnnounce(label));
    }
  }

  function showEnded(info) {
    const entry = text.causes[info.cause] || text.causes.lost;
    const extraInfo = { limit: info.limit, idleMinutes: env.config().idleTimeoutSecs === null ? null : Math.max(1, Math.round(env.config().idleTimeoutSecs / 60)) };
    const title = typeof entry[0] === "function" ? entry[0](names.login, names.node) : entry[0];
    let body = typeof entry[1] === "function" ? entry[1](names.login, names.node, extraInfo) : entry[1];
    if (info.cause === "exit") {
      const exit = info.exit || { status: null, signal: null };
      body = exit.signal !== null ? text.exitSignal(exit.signal) : exit.status !== null ? text.exitCode(exit.status) : entry[1];
    }
    if (info.cause === "busy" && info.retryAfter) {
      body = body + " " + text.retryIn(info.retryAfter);
    }
    const kind = CAUSE_KINDS[entry[2]] || "info";
    const actions = [];
    for (const id of ACTIONS[info.cause] || DEFAULT_ACTIONS) {
      if (id === "retry") {
        actions.push(button(info.wasReady && info.cause !== "lost" ? text.reconnect : S.retry, { kind: "primary", small: true, onClick: () => reconnect() }));
      } else if (id === "close") {
        actions.push(button(text.closeTerminal, { small: true, onClick: () => env.requestClose() }));
      } else if (id === "another") {
        actions.push(button(text.chooseOther, { small: true, onClick: () => env.requestNew({}) }));
      } else if (id === "login") {
        actions.push(button(text.chooseOtherLogin, { small: true, onClick: () => env.requestNew({ node }) }));
      } else if (id === "show") {
        actions.push(button(text.showTerminals, { small: true, onClick: () => env.showTerminals() }));
      }
    }
    const extra = [];
    if ((ACTIONS[info.cause] || DEFAULT_ACTIONS).includes("retry") && info.wasReady) {
      extra.push(el("p", { class: "muted small", text: text.reconnectNote }));
    }
    const shown = banner(kind, title, body, ...actions);
    if (typeof info.reference === "string") {
      shown.querySelector(".banner-body > p").after(referenceLine(info.reference));
    }
    clearIdleState();
    latency = null;
    recording = null;
    paintLatency();
    paintRecording();
    if (!info.wasReady && (stage === "ticket" || info.cause === "no_account")) {
      stage = null;
      replace(stepsSlot);
    }
    const stepsNote = stepsSlot.querySelector("p");
    if (stepsNote !== null) {
      stepsNote.remove();
    }
    replace(bannerSlot, shown, ...extra);
    let badgeKind = kind === "info" ? "off" : kind;
    let words = !info.wasReady ? text.states.notOpened : info.cause === "unavailable" || info.cause === "lost" ? text.states.lost : text.states.ended;
    if (!info.wasReady) {
      badgeKind = "danger";
    } else if (info.cause === "revoked") {
      badgeKind = "danger";
      words = text.states.cut;
    } else if (info.cause === "terminated") {
      badgeKind = "danger";
      words = text.states.endedByAdmin;
    }
    paintState(badgeKind, words);
    disconnect.hidden = true;
    tools.hidden = !info.wasReady;
    split.hidden = !info.wasReady;
    if (info.sessionId) {
      sessionId = info.sessionId;
      paintId();
    }
    endedTitle = title;
    wasReady = info.wasReady;
    const reason = lowerFirst(title.replace(/\.$/, ""));
    setTab(badgeKind === "off" ? "endedInfo" : "endedBad", S.terminal.tabs.ended(reason, info.wasReady));
    if (!active) {
      env.announce(S.terminal.tabs.endedAnnounce(label, reason));
    }
    frame.classList.add("ended");
    const focusTarget = bannerSlot.querySelector(".btn-primary") || bannerSlot.querySelector(".btn");
    if (focusTarget && active) {
      focusTarget.focus({ preventScroll: true });
    }
  }

  function clearIdleState() {
    idle = null;
    idleBanner = null;
    idleLive.textContent = "";
  }

  function connectionHandlers(mine) {
    const live = (handler) => (...args) => {
      if (mine === generation && !disposed) {
        handler(...args);
      }
    };
    return {
      onPhase: live((phase) => {
        if (phase === "starting") {
          paintState("wait", text.states.starting);
          setTab("connecting", S.terminal.tabs.states.connecting);
        } else if (phase === "connecting") {
          stage = "node";
          paintSteps();
          paintState("wait", text.states.connecting);
        } else if (phase === "ready") {
          wasReady = true;
          stage = null;
          replace(stepsSlot);
          replace(bannerSlot);
          sessionId = connection.sessionId();
          paintId();
          paintState("ok", text.states.ready);
          setTab("ready", S.terminal.tabs.states.ready);
          terminal.options.disableStdin = false;
          startTicker();
          focusTerminal();
        }
      }),
      onReadyInfo: live(({ recording: mode }) => {
        recording = mode;
        paintRecording();
      }),
      onProgress: live((next) => {
        stage = next;
        if (next === "account") {
          withAccount = true;
          paintState("wait", text.states.creatingAccount);
          setTab("connecting", S.terminal.tabs.states.account);
          replace(bannerSlot, banner("info", text.creating.title(names.login, names.node), text.creating.body));
        }
        paintSteps();
      }),
      onAccountCreated: live(({ home }) => {
        const dismiss = button(text.created.dismiss, { small: true, onClick: dismissBanner });
        const detail = home === null ? text.created.body(names.login, names.node) : text.created.bodyHome(names.login, names.node, clean(home));
        const created = banner("info", text.created.title, detail, dismiss);
        created.querySelector(".banner-icon").replaceChildren(icon("check"));
        replace(bannerSlot, created);
      }),
      onIdle: live((seconds) => showIdle(seconds)),
      onOutput: live((bytes) => writer.write(bytes)),
      onLatency: live((ms, nodeMs) => {
        latency = { clientMs: ms, nodeMs };
        paintLatency();
      }),
      onBlocked: live((reason) => say(reason === "too_large" ? text.pasteTooLarge : text.inputBlocked)),
      onEnd: live((info) => {
        stopTicker();
        paintTime();
        if (terminal !== null) {
          terminal.options.disableStdin = true;
        }
        if (info.cause === "disabled") {
          env.markTerminalOff();
        }
        showEnded(info);
      }),
    };
  }

  async function begin() {
    generation += 1;
    const mine = generation;
    replace(bannerSlot);
    clearIdleState();
    say("");
    latency = null;
    recording = null;
    sessionId = null;
    stage = "ticket";
    withAccount = false;
    wasReady = false;
    endedTitle = null;
    frame.classList.remove("ended");
    tools.hidden = false;
    split.hidden = false;
    paintLatency();
    paintRecording();
    paintId();
    paintSteps();
    timeText.textContent = text.clock(0);
    disconnect.hidden = false;
    paintState("wait", text.states.starting);
    setTab("connecting", S.terminal.tabs.states.connecting);
    try {
      libraries = libraries || (await terminalHooks.loadLibraries());
      if (mine !== generation || disposed) {
        return;
      }
      disposeTerminal();
      terminal = buildTerminal(mine);
    } catch (error) {
      if (mine === generation && !disposed) {
        disposeTerminal();
        showEnded({ cause: isUnsafeTerminalError(error) ? "unsafe" : "library", exit: null, sessionId: null, retryAfter: null, wasReady: false });
      }
      return;
    }
    fit();
    connection = createConnection({
      api: env.api,
      node,
      login,
      size: () => (terminal === null ? null : { cols: terminal.cols, rows: terminal.rows }),
      hooks: terminalHooks.connection,
      handlers: connectionHandlers(mine),
    });
    try {
      await connection.start();
    } catch {
      if (mine === generation && !disposed) {
        connection.close();
        showEnded({ cause: "unavailable", exit: null, sessionId: null, retryAfter: null, wasReady: false });
      }
    }
  }

  function buildTerminal(mine) {
    const current = () => mine === generation && !disposed;
    const created = terminalHooks.createTerminal({
      container: host,
      cols: INITIAL_SIZE.cols,
      rows: INITIAL_SIZE.rows,
      libraries,
      fontSize: FONT_SIZES[fontIndex],
      now: () => clock().now(),
      onInput: (data) => {
        if (current()) {
          onUserInput(data);
        }
      },
      onReply: (reply) => {
        if (current()) {
          onReply(reply);
        }
      },
    });
    created.attachCustomKeyEventHandler(onKey);
    writer = terminalHooks.createWriter(created, clock());
    paintSize();
    return created;
  }

  function reconnect() {
    if (disposed) {
      return;
    }
    modifiers.clear();
    begin().then(() => {
      if (!disposed) {
        env.announce(text.newSession);
      }
    });
  }

  function requestDisconnect() {
    if (connection === null) {
      return;
    }
    if (!connection.recentInput()) {
      connection.close();
      return;
    }
    focusTerminal();
    openConfirm({
      title: text.confirmTitle(names.node),
      intro: text.confirmBody,
      danger: true,
      confirmLabel: text.confirmYes,
      cancelLabel: text.confirmKeep,
      onConfirm: async () => undefined,
      onDone: () => closeNow(),
    });
  }

  function closeNow() {
    if (connection !== null) {
      connection.close();
    }
  }

  function show() {
    active = true;
    pane.hidden = false;
    scheduleFit();
  }

  function hide() {
    active = false;
    pane.hidden = true;
  }

  function dispose() {
    if (disposed) {
      return;
    }
    disposed = true;
    generation += 1;
    closeNow();
    stopTicker();
    if (resizeTimer !== null) {
      clock().clearTimeout(resizeTimer);
      resizeTimer = null;
    }
    if (stopObserving !== null) {
      stopObserving();
    }
    document.removeEventListener("visibilitychange", onVisibility);
    host.removeEventListener("paste", onPaste, true);
    disposeTerminal();
    pane.remove();
  }

  document.addEventListener("visibilitychange", onVisibility);
  host.addEventListener("paste", onPaste, true);
  stopObserving = terminalHooks.observeResize(frame, scheduleFit);
  paintFont();
  paintClosing();

  return {
    label,
    node,
    login,
    pane,
    start: () => begin(),
    show,
    hide,
    dispose,
    refreshCount: paintClosing,
    focus: focusTerminal,
    focusHeader: () => statusBar.focus({ preventScroll: true }),
    closeConnection: closeNow,
    isReady: () => connection !== null && connection.isReady(),
    isEnded: () => tabState === "endedInfo" || tabState === "endedBad",
    snapshot: () => ({ state: tabState, words: stateWords, glyph: GLYPHS[tabState], title: endedTitle, wasReady, recording, elapsedMs: connection === null ? 0 : connection.elapsedMs() }),
  };
}
