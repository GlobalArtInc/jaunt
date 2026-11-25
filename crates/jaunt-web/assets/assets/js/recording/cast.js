export const CAST_LIMITS = Object.freeze({
  maxBytes: 64 * 1024 * 1024,
  maxLineChars: 1024 * 1024,
  maxHeaderChars: 64 * 1024,
  maxEvents: 2_000_000,
  maxCols: 500,
  maxRows: 200,
  maxSeconds: 10_000_000,
});

const DEFAULT_COLS = 80;
const DEFAULT_ROWS = 24;
const RESIZE = /^(\d{1,4})x(\d{1,4})$/;

export class CastError extends Error {
  constructor(code) {
    super("cast error " + code);
    this.name = "CastError";
    this.code = code;
  }
}

function wellFormed(text) {
  return typeof text.isWellFormed === "function" && !text.isWellFormed() ? text.toWellFormed() : text;
}

function withoutDelete(text) {
  return text.includes("\u007f") ? text.replaceAll("\u007f", "") : text;
}

function dimension(value, fallback, max) {
  if (!Number.isInteger(value) || value < 1) {
    return fallback;
  }
  return Math.min(value, max);
}

function readHeader(line, limits) {
  if (line.length > limits.maxHeaderChars) {
    throw new CastError("bad_header");
  }
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new CastError("bad_header");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) || parsed.version !== 2) {
    throw new CastError("bad_header");
  }
  return {
    version: 2,
    cols: dimension(parsed.width, DEFAULT_COLS, limits.maxCols),
    rows: dimension(parsed.height, DEFAULT_ROWS, limits.maxRows),
  };
}

export class CastParser {
  constructor(limits = CAST_LIMITS) {
    this.limits = limits;
    this.decoder = new TextDecoder("utf-8", { fatal: false });
    this.pending = "";
    this.discarding = false;
    this.header = null;
    this.times = [];
    this.codes = [];
    this.data = [];
    this.bytes = 0;
    this.skipped = 0;
    this.ignored = 0;
    this.hasInput = false;
    this.lastTime = 0;
  }

  push(chunk) {
    this.bytes += chunk.byteLength;
    if (this.bytes > this.limits.maxBytes) {
      throw new CastError("too_large");
    }
    this.consume(this.decoder.decode(chunk, { stream: true }));
  }

  consume(text) {
    let start = 0;
    while (start <= text.length) {
      const newline = text.indexOf("\n", start);
      const end = newline === -1 ? text.length : newline;
      const piece = text.slice(start, end);
      if (this.discarding) {
        if (newline !== -1) {
          this.discarding = false;
        }
      } else if (this.pending.length + piece.length > this.limits.maxLineChars) {
        this.pending = "";
        this.skipped += 1;
        this.discarding = newline === -1;
      } else if (newline === -1) {
        this.pending += piece;
      } else {
        const line = this.pending + piece;
        this.pending = "";
        this.line(line);
      }
      if (newline === -1) {
        break;
      }
      start = newline + 1;
    }
  }

  line(raw) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (line === "") {
      return;
    }
    if (this.header === null) {
      this.header = readHeader(line, this.limits);
      return;
    }
    this.event(line);
  }

  event(line) {
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      this.skipped += 1;
      return;
    }
    if (!Array.isArray(parsed) || parsed.length < 3) {
      this.skipped += 1;
      return;
    }
    const [time, code, data] = parsed;
    if (typeof time !== "number" || !Number.isFinite(time) || time < 0 || time > this.limits.maxSeconds || typeof code !== "string" || typeof data !== "string") {
      this.skipped += 1;
      return;
    }
    if (code === "o") {
      this.store(time, code, withoutDelete(wellFormed(data)));
    } else if (code === "i") {
      this.store(time, code, wellFormed(data));
    } else if (code === "r") {
      const match = RESIZE.exec(data);
      if (match === null || Number(match[1]) < 1 || Number(match[2]) < 1) {
        this.skipped += 1;
        return;
      }
      const cols = Math.min(Number(match[1]), this.limits.maxCols);
      const rows = Math.min(Number(match[2]), this.limits.maxRows);
      this.store(time, "r", cols + "x" + rows);
    } else {
      this.ignored += 1;
    }
  }

  store(time, code, data) {
    if (this.times.length >= this.limits.maxEvents) {
      throw new CastError("too_large");
    }
    const at = Math.max(time, this.lastTime);
    this.lastTime = at;
    this.times.push(at);
    this.codes.push(code);
    this.data.push(data);
    if (code === "i") {
      this.hasInput = true;
    }
  }

  finish() {
    this.consume(this.decoder.decode());
    if (this.pending !== "" && !this.discarding) {
      const last = this.pending;
      this.pending = "";
      this.line(last);
    }
    if (this.header === null) {
      throw new CastError("bad_header");
    }
    return {
      header: this.header,
      times: this.times,
      codes: this.codes,
      data: this.data,
      count: this.times.length,
      skipped: this.skipped,
      ignored: this.ignored,
      hasInput: this.hasInput,
      bytes: this.bytes,
      duration: this.times.length === 0 ? 0 : this.times[this.times.length - 1],
    };
  }
}

export function parseCastBytes(bytes, limits = CAST_LIMITS) {
  const parser = new CastParser(limits);
  parser.push(bytes);
  return parser.finish();
}

export async function readCast(stream, { limits = CAST_LIMITS, signal } = {}) {
  const parser = new CastParser(limits);
  const reader = stream.getReader();
  try {
    for (;;) {
      if (signal && signal.aborted) {
        throw new CastError("aborted");
      }
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      parser.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  }
  return parser.finish();
}
