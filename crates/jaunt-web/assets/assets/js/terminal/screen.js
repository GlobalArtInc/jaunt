import { el, encodeSegment, replace } from "../dom.js";
import { openConfirm } from "../dialog.js";
import { clean } from "../format.js";
import { icon } from "../icons.js";
import { S } from "../strings.js";
import { badge, banner, button, crumbs, linkButton } from "../ui.js";
import { isUnsafeTerminalError } from "./cells.js";
import { createConnection } from "./connection.js";
import { fitSize } from "./fit.js";
import { FONT_SIZES } from "./fonts.js";
import { terminalHooks } from "./hooks.js";
import { KEY_BAR, createModifiers, keySequence, sanitizePaste } from "./keys.js";

const FONT_KEY = "jaunt-terminal-font";
const RESIZE_DEBOUNCE_MS = 150;
const INITIAL_SIZE = { cols: 80, rows: 24 };
const CAUSE_KINDS = { info: "info", warn: "warn", danger: "danger" };
const NO_RETRY_CAUSES = new Set(["disabled", "unsafe", "account_refused", "no_account"]);
const OTHER_LOGIN_CAUSES = new Set(["account_refused", "no_account"]);

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

export function openSession(ctx, { node, login }) {
  const names = { node: clean(node), login: clean(login) };
  const text = S.terminal.session;
  const modifiers = createModifiers();
  let fontIndex = readFontIndex();
  let terminal = null;
  let libraries = null;
  let connection = null;
  let generation = 0;
  let disposed = false;
  let ticker = null;
  let resizeTimer = null;
  let stopObserving = null;
  let keysShown = terminalHooks.prefersKeyBar();
  let pasting = false;
  let writer = null;

  const clock = () => terminalHooks.connection.clock;

  const stateSlot = el("span", { class: "item", role: "status" });
  const timeText = el("span", { class: "mono term-elapsed", text: text.clock(0) });
  const latencyValue = el("span", { class: "mono", text: "" });
  const latencyItem = el("span", { class: "item", hidden: true }, el("span", { class: "k", text: text.latency }), latencyValue);
  const leave = button(text.leave, { small: true, onClick: () => leaveTerminal() });
  const disconnect = button(text.disconnect, { kind: "danger-outline", small: true, onClick: () => requestDisconnect() });
  const statusBar = el(
    "div",
    { class: "statusbar", role: "group", "aria-label": text.statusLabel, tabindex: "-1" },
    el("span", { class: "item" }, el("span", { class: "k", text: text.node }), el("span", { class: "mono", text: names.node })),
    el("span", { class: "item" }, el("span", { class: "k", text: text.login }), el("span", { class: "mono", text: names.login })),
    el("span", { class: "item" }, el("span", { class: "k", text: text.state }), stateSlot),
    el("span", { class: "item" }, el("span", { class: "k", text: text.elapsed }), timeText),
    latencyItem,
    el("span", { class: "item push" }, leave, disconnect),
  );

  const copyButton = button(text.copy, { small: true, onClick: () => copySelection() });
  const pasteButton = button(text.paste, { small: true, onClick: () => pasteFromClipboard() });
  const smaller = button(text.fontSmallerGlyph, { small: true, onClick: () => changeFont(-1) });
  const larger = button(text.fontLargerGlyph, { small: true, onClick: () => changeFont(1) });
  smaller.setAttribute("aria-label", text.fontSmaller);
  larger.setAttribute("aria-label", text.fontLarger);
  const sizeText = el("span", { class: "muted small term-size" });
  const keysToggle = el("button", { type: "button", class: "btn btn-sm", "aria-pressed": String(keysShown), on: { click: () => toggleKeys() } }, text.keyBar);
  const tools = el("div", { class: "term-tools", role: "group", "aria-label": text.screen(names.login, names.node) }, copyButton, pasteButton, smaller, sizeText, larger, keysToggle);
  const note = el("p", { class: "muted small term-note", role: "status" });
  const bannerSlot = el("div", { class: "term-banner" });
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
  const help = el("p", { class: "muted small term-help" }, text.leaveHelp, " ", text.endHelp);
  const page = el("div", { class: "term-page" }, crumbs([{ text: text.crumb, href: "#/terminal" }, { text: names.login + "@" + names.node }]), el("div", { class: "term-shell" }, statusBar, tools, note, bannerSlot, frame, keyBar), help);

  replace(ctx.main, page);
  ctx.setTitle(names.login + "@" + names.node);

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

  function paintFont() {
    sizeText.textContent = text.fontSize(FONT_SIZES[fontIndex]);
    smaller.disabled = fontIndex === 0;
    larger.disabled = fontIndex === FONT_SIZES.length - 1;
  }

  function paintState(kind, label) {
    replace(stateSlot, badge(kind, label));
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
    if (terminal !== null && !disposed) {
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

  function sendUser(data) {
    if (connection === null) {
      return;
    }
    if (connection.sendInput(data) && note.textContent !== "") {
      say("");
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

  function paintTime() {
    if (connection !== null) {
      timeText.textContent = text.clock(connection.elapsedMs() / 1000);
    }
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

  function showEnded(info) {
    const entry = text.causes[info.cause] || text.causes.lost;
    const title = typeof entry[0] === "function" ? entry[0](names.login, names.node) : entry[0];
    let body = typeof entry[1] === "function" ? entry[1](names.login, names.node) : entry[1];
    if (info.cause === "exit") {
      const exit = info.exit || { status: null, signal: null };
      body = exit.signal !== null ? text.exitSignal(exit.signal) : exit.status !== null ? text.exitCode(exit.status) : entry[1];
    }
    if (info.cause === "busy" && info.retryAfter) {
      body = body + " " + text.retryIn(info.retryAfter);
    }
    const kind = CAUSE_KINDS[entry[2]] || "info";
    const actions = [];
    if (!NO_RETRY_CAUSES.has(info.cause)) {
      actions.push(button(info.wasReady && info.cause !== "lost" ? text.reconnect : S.retry, { kind: "primary", onClick: () => reconnect() }));
    }
    if (OTHER_LOGIN_CAUSES.has(info.cause)) {
      actions.push(linkButton(text.chooseOtherLogin, "#/terminal?node=" + encodeSegment(node)));
    } else if (info.cause !== "account_failed") {
      actions.push(linkButton(text.chooseOther, "#/terminal"));
    }
    const extra = [];
    if (info.cause !== "disabled" && info.wasReady) {
      extra.push(el("p", { class: "muted small", text: text.reconnectNote }));
    }
    if (info.sessionId) {
      extra.push(el("p", { class: "muted small" }, text.sessionId + ": ", el("span", { class: "mono", text: info.sessionId })));
    }
    const shown = banner(kind, title, body, ...actions);
    if (typeof info.reference === "string") {
      shown.querySelector(".banner-body > p").after(referenceLine(info.reference));
    }
    replace(bannerSlot, shown, ...extra);
    paintState(kind === "info" ? "off" : kind, !info.wasReady ? text.states.notOpened : info.cause === "unavailable" || info.cause === "lost" ? text.states.lost : text.states.ended);
    disconnect.hidden = true;
    const focusTarget = bannerSlot.querySelector(".btn-primary");
    if (focusTarget) {
      focusTarget.focus({ preventScroll: true });
    }
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
          paintState("info", text.states.starting);
        } else if (phase === "connecting") {
          paintState("info", text.states.connecting);
        } else if (phase === "ready") {
          replace(bannerSlot);
          paintState("ok", text.states.ready);
          terminal.options.disableStdin = false;
          startTicker();
          focusTerminal();
        }
      }),
      onAccountProgress: live(() => {
        paintState("info", text.states.creatingAccount);
        replace(bannerSlot, banner("info", text.creating.title(names.login, names.node), text.creating.body));
      }),
      onAccountCreated: live(({ home }) => {
        const dismiss = button(text.created.dismiss, { small: true, onClick: dismissBanner });
        const detail = home === null ? text.created.body(names.login, names.node) : text.created.bodyHome(names.login, names.node, clean(home));
        const created = banner("info", text.created.title, detail, dismiss);
        created.querySelector(".banner-icon").replaceChildren(icon("check"));
        replace(bannerSlot, created);
      }),
      onOutput: live((bytes) => writer.write(bytes)),
      onLatency: live((ms) => {
        latencyItem.hidden = false;
        latencyValue.textContent = text.latencyValue(Math.round(ms));
      }),
      onBlocked: live((reason) => say(reason === "too_large" ? text.pasteTooLarge : text.inputBlocked)),
      onEnd: live((info) => {
        stopTicker();
        paintTime();
        if (terminal !== null) {
          terminal.options.disableStdin = true;
        }
        if (info.cause === "disabled") {
          ctx.connect.markTerminal(false);
        }
        showEnded(info);
      }),
    };
  }

  async function begin() {
    generation += 1;
    const mine = generation;
    replace(bannerSlot);
    say("");
    latencyItem.hidden = true;
    timeText.textContent = text.clock(0);
    disconnect.hidden = false;
    paintState("info", text.states.starting);
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
      api: ctx.api,
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
    return created;
  }

  function reconnect() {
    if (disposed) {
      return;
    }
    modifiers.clear();
    begin().then(() => {
      if (!disposed) {
        ctx.announce(text.newSession);
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
    window.removeEventListener("beforeunload", closeNow);
    window.removeEventListener("pagehide", closeNow);
    document.removeEventListener("visibilitychange", onVisibility);
    host.removeEventListener("paste", onPaste, true);
    disposeTerminal();
  }

  window.addEventListener("beforeunload", closeNow);
  window.addEventListener("pagehide", closeNow);
  document.addEventListener("visibilitychange", onVisibility);
  host.addEventListener("paste", onPaste, true);
  stopObserving = terminalHooks.observeResize(frame, scheduleFit);
  ctx.onCleanup(dispose);
  paintFont();
  begin();
}
