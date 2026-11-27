import { clampSize } from "./fit.js";

export const SUBPROTOCOL = "jaunt-terminal.v1";
export const TICKET_PREFIX = "jaunt-ticket.";
export const TICKET_PATH = "/v1/web/terminal/ticket";
export const SOCKET_PATH = "/v1/web/terminal";
export const PING_INTERVAL_MS = 20000;
export const RECENT_INPUT_MS = 10000;
export const DEAD_PEER_MS = 60000;
export const NORMAL_TICK_MS = 30000;
export const NORMAL_TICKS_BEFORE_VERDICT = 2;
export const MAX_INPUT_FRAME = 65536;
export const MAX_BUFFERED_BYTES = 1048576;

const MAX_CONTROL_TEXT = 4096;
const MAX_SIGNAL_LENGTH = 32;
const OPEN = 1;
const TICKET_SHAPE = /^[A-Za-z0-9._~-]{16,128}$/;
const SESSION_ID_SHAPE = /^[A-Za-z0-9._-]{1,128}$/;
const SIGNAL_SHAPE = /^[A-Za-z0-9_+-]+$/;
const ERROR_CODES = new Set(["denied", "unavailable", "limit", "revoked", "timeout", "account_refused", "account_failed", "no_account"]);
const REFERENCE_SHAPE = /^H-[0-9A-F]{8}$/;
const ACCOUNT_STAGE = "account";
const MAX_HOME_CHARS = 256;

export function realHooks() {
  return {
    createSocket: (url, protocols) => new WebSocket(url, protocols),
    base: () => globalThis.location.href,
    isHidden: () => Boolean(globalThis.document && globalThis.document.hidden),
    clock: {
      now: () => Date.now(),
      setInterval: (callback, ms) => globalThis.setInterval(callback, ms),
      clearInterval: (id) => globalThis.clearInterval(id),
      setTimeout: (callback, ms) => globalThis.setTimeout(callback, ms),
      clearTimeout: (id) => globalThis.clearTimeout(id),
    },
  };
}

export function socketUrl(base, { node, login, cols, rows }) {
  const url = new URL(SOCKET_PATH, base);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.search = "";
  url.hash = "";
  url.searchParams.set("node", node);
  url.searchParams.set("login", login);
  url.searchParams.set("cols", String(cols));
  url.searchParams.set("rows", String(rows));
  return url.toString();
}

export function ticketCause(error) {
  const status = error && typeof error.status === "number" ? error.status : -1;
  if (status === 401) {
    return "expired";
  }
  if (status === 403) {
    return "denied";
  }
  if (status === 404) {
    return "disabled";
  }
  if (status === 400) {
    return "invalid";
  }
  if (status === 429) {
    return error.code === "limit" ? "limit" : "busy";
  }
  if (status === 0) {
    return "network";
  }
  return "unavailable";
}

function closeCause({ code, exit, errorCode, ready }) {
  if (exit !== null) {
    return "exit";
  }
  if (errorCode !== null) {
    return errorCode;
  }
  if (code === 4001) {
    return "revoked";
  }
  if (code === 4002) {
    return "idle";
  }
  if (code === 1000 || code === 4003) {
    return "closed";
  }
  if (code === 1001 || code === 1011) {
    return "unavailable";
  }
  if (code === 1008) {
    return "policy";
  }
  if (code === 1009) {
    return "too_large";
  }
  return ready ? "lost" : "connect_failed";
}

function readReference(message) {
  return typeof message.ref === "string" && REFERENCE_SHAPE.test(message.ref) ? message.ref : null;
}

function readHome(message) {
  if (typeof message.home !== "string" || message.home === "") {
    return null;
  }
  return message.home.length > MAX_HOME_CHARS ? message.home.slice(0, MAX_HOME_CHARS) + "…" : message.home;
}

function readExit(message) {
  const status = Number.isInteger(message.status) ? message.status : null;
  const signal = typeof message.signal === "string" && message.signal.length <= MAX_SIGNAL_LENGTH && SIGNAL_SHAPE.test(message.signal) ? message.signal : null;
  return { status, signal };
}

export function createConnection({ api, node, login, size, hooks = realHooks(), handlers }) {
  const { clock } = hooks;
  const encoder = new TextEncoder();
  let socket = null;
  let phase = "idle";
  let ready = false;
  let ended = false;
  let exit = null;
  let errorCode = null;
  let reference = null;
  let sessionId = null;
  let pingTimer = null;
  let pingSentAt = null;
  let lastInputAt = null;
  let readyAt = null;
  let endedAt = null;
  let sentSize = null;
  let lastInboundAt = null;
  let lastTickAt = null;
  let normalTicks = 0;

  function setPhase(next) {
    phase = next;
    if (handlers.onPhase) {
      handlers.onPhase(next);
    }
  }

  function stopPing() {
    if (pingTimer !== null) {
      clock.clearInterval(pingTimer);
      pingTimer = null;
    }
  }

  function closeSocket() {
    if (socket !== null && socket.readyState <= OPEN) {
      try {
        socket.close(1000, "");
      } catch {
        return;
      }
    }
  }

  function finish(cause, extra = {}) {
    if (ended) {
      return;
    }
    ended = true;
    endedAt = clock.now();
    ready = false;
    stopPing();
    closeSocket();
    phase = "ended";
    handlers.onEnd({ cause, exit, reference, sessionId, wasReady: readyAt !== null, retryAfter: extra.retryAfter || null, closeCode: extra.closeCode === undefined ? null : extra.closeCode });
  }

  function sendText(payload) {
    if (socket !== null && socket.readyState === OPEN) {
      socket.send(JSON.stringify(payload));
    }
  }

  function sendResize(cols, rows) {
    if (!ready || ended) {
      return false;
    }
    const next = clampSize({ cols, rows });
    if (sentSize !== null && sentSize.cols === next.cols && sentSize.rows === next.rows) {
      return false;
    }
    sentSize = next;
    sendText({ t: "resize", cols: next.cols, rows: next.rows });
    return true;
  }

  function hidden() {
    return typeof hooks.isHidden === "function" && hooks.isHidden();
  }

  function tick() {
    const now = clock.now();
    const onTime = now - lastTickAt <= NORMAL_TICK_MS;
    lastTickAt = now;
    normalTicks = !hidden() && onTime ? normalTicks + 1 : 0;
    if (normalTicks >= NORMAL_TICKS_BEFORE_VERDICT && now - lastInboundAt >= DEAD_PEER_MS) {
      finish("lost");
      return;
    }
    pingSentAt = now;
    sendText({ t: "ping" });
  }

  function onReady(message) {
    if (ready || ended) {
      return;
    }
    ready = true;
    readyAt = clock.now();
    sessionId = typeof message.session_id === "string" && SESSION_ID_SHAPE.test(message.session_id) ? message.session_id : null;
    lastInboundAt = readyAt;
    lastTickAt = readyAt;
    normalTicks = 0;
    pingTimer = clock.setInterval(tick, PING_INTERVAL_MS);
    setPhase("ready");
    if (message.account_created === true && handlers.onAccountCreated) {
      handlers.onAccountCreated({ home: readHome(message) });
    }
    const current = size();
    if (current !== null) {
      sendResize(current.cols, current.rows);
    }
  }

  function onControl(text) {
    if (text.length > MAX_CONTROL_TEXT) {
      return;
    }
    let message;
    try {
      message = JSON.parse(text);
    } catch {
      return;
    }
    if (message === null || typeof message !== "object" || Array.isArray(message)) {
      return;
    }
    if (message.t === "ready") {
      onReady(message);
    } else if (message.t === "progress") {
      if (message.stage === ACCOUNT_STAGE && !ready && !ended && handlers.onAccountProgress) {
        handlers.onAccountProgress();
      }
    } else if (message.t === "exit") {
      exit = readExit(message);
    } else if (message.t === "error") {
      if (typeof message.code === "string" && ERROR_CODES.has(message.code)) {
        errorCode = message.code;
        reference = readReference(message);
      }
    } else if (message.t === "pong") {
      if (pingSentAt !== null && handlers.onLatency) {
        handlers.onLatency(Math.max(0, clock.now() - pingSentAt));
      }
      pingSentAt = null;
    }
  }

  function onMessage(event) {
    if (ended) {
      return;
    }
    lastInboundAt = clock.now();
    if (typeof event.data === "string") {
      onControl(event.data);
    } else if (event.data instanceof ArrayBuffer) {
      handlers.onOutput(new Uint8Array(event.data));
    }
  }

  function onOpen() {
    if (ended) {
      return;
    }
    if (socket.protocol !== SUBPROTOCOL) {
      finish("protocol");
    }
  }

  function onClose(event) {
    if (ended) {
      return;
    }
    const code = event && Number.isInteger(event.code) ? event.code : 1006;
    finish(closeCause({ code, exit, errorCode, ready }), { closeCode: code });
  }

  function openSocket(ticket) {
    const wanted = clampSize(size() || { cols: 80, rows: 24 });
    sentSize = wanted;
    try {
      socket = hooks.createSocket(socketUrl(hooks.base(), { node, login, cols: wanted.cols, rows: wanted.rows }), [SUBPROTOCOL, TICKET_PREFIX + ticket]);
      socket.binaryType = "arraybuffer";
    } catch {
      finish("connect_failed");
      return;
    }
    socket.addEventListener("open", onOpen);
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose);
  }

  async function start() {
    if (phase !== "idle") {
      return;
    }
    setPhase("starting");
    let reply;
    try {
      reply = await api.post(TICKET_PATH, { node, login });
    } catch (error) {
      finish(ticketCause(error), { retryAfter: error && error.retryAfter });
      return;
    }
    if (ended) {
      return;
    }
    if (!reply || typeof reply.ticket !== "string" || !TICKET_SHAPE.test(reply.ticket)) {
      finish("protocol");
      return;
    }
    setPhase("connecting");
    openSocket(reply.ticket);
  }

  function sendInput(data, { user = true } = {}) {
    if (!ready || ended || socket === null || socket.readyState !== OPEN) {
      return false;
    }
    const bytes = typeof data === "string" ? encoder.encode(data) : data;
    if (bytes.length === 0) {
      return true;
    }
    if (bytes.length > MAX_BUFFERED_BYTES || socket.bufferedAmount + bytes.length > MAX_BUFFERED_BYTES) {
      if (handlers.onBlocked) {
        handlers.onBlocked(bytes.length > MAX_BUFFERED_BYTES ? "too_large" : "busy");
      }
      return false;
    }
    for (let offset = 0; offset < bytes.length; offset += MAX_INPUT_FRAME) {
      socket.send(bytes.subarray(offset, offset + MAX_INPUT_FRAME));
    }
    if (user) {
      lastInputAt = clock.now();
    }
    return true;
  }

  return {
    start,
    sendInput,
    sendResize,
    close: () => finish("user"),
    resume() {
      if (ready && !ended) {
        lastInboundAt = clock.now();
      }
    },
    phase: () => phase,
    isReady: () => ready,
    sessionId: () => sessionId,
    recentInput: () => lastInputAt !== null && clock.now() - lastInputAt < RECENT_INPUT_MS,
    elapsedMs: () => (readyAt === null ? 0 : (endedAt === null ? clock.now() : endedAt) - readyAt),
  };
}
