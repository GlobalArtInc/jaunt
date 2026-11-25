export const REPLY_LIMIT = 16;
export const REPLY_WINDOW_MS = 1000;

const ESC = "\u001b";
const PRIMARY_ATTRIBUTES = ESC + "[?1;2c";
const SECONDARY_ATTRIBUTES = ESC + "[>0;276;0c";
const STATUS_OK = ESC + "[0n";

function firstParam(params) {
  const first = Array.isArray(params[0]) ? params[0][0] : params[0];
  return typeof first === "number" ? first : 0;
}

export function createReplyBudget(now, limit = REPLY_LIMIT, windowMs = REPLY_WINDOW_MS) {
  let windowStart = null;
  let used = 0;
  return () => {
    const current = now();
    if (windowStart === null || current - windowStart >= windowMs || current < windowStart) {
      windowStart = current;
      used = 0;
    }
    if (used >= limit) {
      return false;
    }
    used += 1;
    return true;
  };
}

export function installReplyPolicy(terminal, { send, now }) {
  const allowed = createReplyBudget(now);
  const reply = (text) => {
    if (allowed()) {
      send(text);
    }
    return true;
  };
  const swallow = () => true;
  const { parser } = terminal;
  parser.registerCsiHandler({ final: "c" }, (params) => (firstParam(params) === 0 ? reply(PRIMARY_ATTRIBUTES) : true));
  parser.registerCsiHandler({ prefix: ">", final: "c" }, (params) => (firstParam(params) === 0 ? reply(SECONDARY_ATTRIBUTES) : true));
  parser.registerCsiHandler({ final: "n" }, (params) => {
    const request = firstParam(params);
    if (request === 5) {
      return reply(STATUS_OK);
    }
    if (request === 6) {
      return reply(cursorReport(terminal, ""));
    }
    return true;
  });
  parser.registerCsiHandler({ prefix: "?", final: "n" }, (params) => (firstParam(params) === 6 ? reply(cursorReport(terminal, "?")) : true));
  parser.registerCsiHandler({ final: "t" }, swallow);
  parser.registerCsiHandler({ intermediates: "$", final: "p" }, swallow);
  parser.registerCsiHandler({ prefix: "?", intermediates: "$", final: "p" }, swallow);
  parser.registerDcsHandler({ intermediates: "$", final: "q" }, swallow);
}

function cursorReport(terminal, marker) {
  const active = terminal.buffer.active;
  return ESC + "[" + marker + (active.cursorY + 1) + ";" + (active.cursorX + 1) + "R";
}
