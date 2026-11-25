export const MAX_PIECE = 2048;
export const MAX_PENDING = 64;
export const FALLBACK_SIZE = { cols: 500, rows: 200 };

const INTRODUCER = /\u001b\[|\u009b/g;
const DELETE = /\u007f/g;
const PRIVATE_MARKERS = "<=>?";
const COUNT_LIMITS = { S: "rows", T: "rows", L: "rows", M: "rows", Z: "cols", b: "area", "@": "cols", P: "cols", X: "cols" };
export const MAX_REPEAT = 16384;
export const LIMITED_FINALS = Object.keys(COUNT_LIMITS);

function dimension(size, axis) {
  const value = size && Number.isFinite(size[axis]) && size[axis] > 0 ? Math.floor(size[axis]) : FALLBACK_SIZE[axis];
  return Math.max(1, value);
}

export function countLimit(final, size) {
  const axis = COUNT_LIMITS[final];
  if (axis === undefined) {
    return null;
  }
  if (axis === "area") {
    return Math.min(dimension(size, "rows") * dimension(size, "cols"), MAX_REPEAT);
  }
  return dimension(size, axis);
}

function firstParam(params) {
  const first = Array.isArray(params[0]) ? params[0][0] : params[0];
  return typeof first === "number" ? first : 0;
}

export function installCountLimits(terminal) {
  const size = () => ({ cols: terminal.cols, rows: terminal.rows });
  for (const final of LIMITED_FINALS) {
    terminal.parser.registerCsiHandler({ final }, (params) => firstParam(params) > countLimit(final, size()));
  }
}

function exceeds(digits, limit) {
  const trimmed = digits.replace(/^0+/, "");
  return trimmed.length > 7 || Number(trimmed) > limit;
}

function isDigit(code) {
  return code >= 0x30 && code <= 0x39;
}

function readBody(input, start) {
  if (start >= input.length) {
    return { kind: "incomplete" };
  }
  if (PRIVATE_MARKERS.includes(input[start])) {
    return { kind: "skip", end: start + 1 };
  }
  let cursor = start;
  while (cursor < input.length && isDigit(input.charCodeAt(cursor))) {
    cursor += 1;
  }
  const digitsEnd = cursor;
  while (cursor < input.length) {
    const code = input.charCodeAt(cursor);
    if (isDigit(code) || code === 0x3b || code === 0x3a) {
      cursor += 1;
    } else {
      break;
    }
  }
  if (cursor >= input.length) {
    return { kind: "incomplete" };
  }
  const code = input.charCodeAt(cursor);
  if (code >= 0x40 && code <= 0x7e) {
    return { kind: "csi", digitsStart: start, digitsEnd, final: input[cursor], end: cursor + 1 };
  }
  return { kind: "skip", end: cursor };
}

export function clampCounts(input, size) {
  let out = "";
  let cursor = 0;
  INTRODUCER.lastIndex = 0;
  for (;;) {
    const match = INTRODUCER.exec(input);
    if (match === null) {
      break;
    }
    const bodyStart = match.index + match[0].length;
    const body = readBody(input, bodyStart);
    if (body.kind === "incomplete") {
      if (input.length - match.index <= MAX_PENDING) {
        return { text: out + input.slice(cursor, match.index), pending: input.slice(match.index) };
      }
      INTRODUCER.lastIndex = bodyStart;
    } else if (body.kind === "csi") {
      const limit = body.digitsEnd > body.digitsStart ? countLimit(body.final, size) : null;
      if (limit !== null && exceeds(input.slice(body.digitsStart, body.digitsEnd), limit)) {
        out += input.slice(cursor, body.digitsStart) + String(limit);
        cursor = body.digitsEnd;
      }
      INTRODUCER.lastIndex = body.end;
    } else {
      INTRODUCER.lastIndex = body.end;
    }
  }
  if (input.length > cursor && input.endsWith("\u001b")) {
    return { text: out + input.slice(cursor, -1), pending: "\u001b" };
  }
  return { text: out + input.slice(cursor), pending: "" };
}

export function splitPieces(text, max = MAX_PIECE) {
  const pieces = [];
  let offset = 0;
  while (offset < text.length) {
    let end = Math.min(offset + max, text.length);
    if (end < text.length) {
      const last = text.charCodeAt(end - 1);
      if (last >= 0xd800 && last <= 0xdbff) {
        end -= 1;
      }
    }
    pieces.push(text.slice(offset, end));
    offset = end;
  }
  return pieces;
}

export function createOutputGuard(sizeOf) {
  let pending = "";
  return {
    pieces(text) {
      const scanned = clampCounts(pending + text.replace(DELETE, ""), sizeOf());
      pending = scanned.pending;
      return splitPieces(scanned.text);
    },
    flush() {
      const rest = pending;
      pending = "";
      return rest;
    },
    hasPending: () => pending !== "",
    reset() {
      pending = "";
    },
  };
}
