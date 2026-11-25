export const SPEEDS = Object.freeze([0.5, 1, 2, 4, 8]);
export const IDLE_CAP_SECONDS = 2;

const MIN_TICK_MS = 16;
const MAX_TICK_MS = 250;
const MAX_EVENTS_PER_TICK = 5000;
const FLUSH_CHARS = 256 * 1024;
const INPUT_ON = "\u001b[7m";
const INPUT_OFF = "\u001b[27m";

export const realClock = {
  now: () => Date.now(),
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (id) => clearTimeout(id),
};

export function renderInput(data) {
  let out = "";
  for (const char of data) {
    const code = char.codePointAt(0);
    if (code < 0x20) {
      out += "^" + String.fromCharCode(code ^ 0x40);
    } else if (code === 0x7f) {
      out += "^?";
    } else if (code >= 0x80 && code <= 0x9f) {
      out += "�";
    } else {
      out += char;
    }
  }
  return out === "" ? "" : INPUT_ON + out + INPUT_OFF;
}

export function buildTimeline(cast, { showInput, compressIdle }) {
  const ids = [];
  const at = [];
  const raw = [];
  let previous = 0;
  let effective = 0;
  for (let index = 0; index < cast.count; index += 1) {
    if (cast.codes[index] === "i" && !showInput) {
      continue;
    }
    const gap = cast.times[index] - previous;
    effective += compressIdle ? Math.min(gap, IDLE_CAP_SECONDS) : gap;
    previous = cast.times[index];
    ids.push(index);
    at.push(effective);
    raw.push(cast.times[index]);
  }
  return { ids, at, raw, count: ids.length, total: at.length === 0 ? 0 : at[at.length - 1] };
}

export function createDriver({ cast, sink, clock = realClock, showInput = false, compressIdle = true, speed = 1 }) {
  const listeners = new Set();
  const options = { showInput, compressIdle };
  let timeline = buildTimeline(cast, options);
  let next = 0;
  let position = 0;
  let playing = false;
  let ended = false;
  let rate = SPEEDS.includes(speed) ? speed : 1;
  let timer = null;
  let baseMs = 0;
  let basePosition = 0;
  let disposed = false;

  function emit() {
    for (const listener of listeners) {
      listener(snapshot());
    }
  }

  function snapshot() {
    return { status: playing ? "playing" : ended ? "ended" : "paused", position, duration: timeline.total, speed: rate };
  }

  function applyUntil(limit, budget = Infinity) {
    const parts = [];
    let size = 0;
    let applied = 0;
    const flush = () => {
      if (parts.length > 0) {
        sink.write(parts.join(""));
        parts.length = 0;
        size = 0;
      }
    };
    while (next < timeline.count && timeline.at[next] <= limit && applied < budget) {
      const id = timeline.ids[next];
      const code = cast.codes[id];
      if (code === "r") {
        flush();
        const [cols, rows] = cast.data[id].split("x").map(Number);
        sink.resize(cols, rows);
      } else {
        const text = code === "i" ? renderInput(cast.data[id]) : cast.data[id];
        parts.push(text);
        size += text.length;
        if (size >= FLUSH_CHARS) {
          flush();
        }
      }
      next += 1;
      applied += 1;
    }
    flush();
    return applied;
  }

  function reset() {
    sink.reset(cast.header.cols, cast.header.rows);
    next = 0;
    position = 0;
  }

  function clearTimer() {
    if (timer !== null) {
      clock.clearTimeout(timer);
      timer = null;
    }
  }

  function currentTarget() {
    const elapsed = ((clock.now() - baseMs) * rate) / 1000;
    return Math.min(timeline.total, basePosition + Math.max(0, elapsed));
  }

  function schedule() {
    clearTimer();
    let delay = MAX_TICK_MS;
    if (next < timeline.count) {
      delay = Math.min(MAX_TICK_MS, Math.max(MIN_TICK_MS, ((timeline.at[next] - position) * 1000) / rate));
    }
    timer = clock.setTimeout(tick, delay);
  }

  function tick() {
    timer = null;
    if (!playing || disposed) {
      return;
    }
    const target = currentTarget();
    const applied = applyUntil(target, MAX_EVENTS_PER_TICK);
    if (applied === MAX_EVENTS_PER_TICK && next < timeline.count && timeline.at[next] <= target) {
      position = next > 0 ? timeline.at[next - 1] : 0;
      baseMs = clock.now();
      basePosition = position;
    } else {
      position = target;
    }
    if (next >= timeline.count && position >= timeline.total) {
      playing = false;
      ended = true;
      emit();
      return;
    }
    emit();
    schedule();
  }

  function settle() {
    if (playing) {
      const target = currentTarget();
      applyUntil(target);
      position = target;
    }
  }

  function seek(seconds) {
    if (disposed) {
      return;
    }
    const target = Math.min(timeline.total, Math.max(0, Number.isNaN(seconds) ? 0 : seconds));
    if (next > 0 && timeline.at[next - 1] > target) {
      reset();
    }
    applyUntil(target);
    position = target;
    ended = false;
    if (playing) {
      if (next >= timeline.count && position >= timeline.total) {
        playing = false;
        ended = true;
        clearTimer();
      } else {
        baseMs = clock.now();
        basePosition = position;
        schedule();
      }
    } else if (position >= timeline.total && timeline.count > 0) {
      ended = true;
    }
    emit();
  }

  function play() {
    if (disposed || playing) {
      return;
    }
    if (ended || (timeline.count > 0 && position >= timeline.total)) {
      seek(0);
    }
    playing = true;
    ended = false;
    baseMs = clock.now();
    basePosition = position;
    tick();
  }

  function pause() {
    if (!playing) {
      return;
    }
    settle();
    playing = false;
    clearTimer();
    emit();
  }

  function rebuild() {
    const lastRaw = next > 0 ? timeline.raw[next - 1] : -1;
    timeline = buildTimeline(cast, options);
    let count = 0;
    while (count < timeline.count && timeline.raw[count] <= lastRaw) {
      count += 1;
    }
    reset();
    position = count > 0 ? timeline.at[count - 1] : 0;
    applyUntil(position);
    ended = false;
    if (playing) {
      baseMs = clock.now();
      basePosition = position;
      schedule();
    }
    emit();
  }

  reset();

  return {
    play,
    pause,
    toggle: () => (playing ? pause() : play()),
    restart() {
      seek(0);
      play();
    },
    seek,
    skip: (seconds) => seek(position + seconds),
    setSpeed(value) {
      if (!SPEEDS.includes(value) || disposed) {
        return;
      }
      settle();
      rate = value;
      if (playing) {
        baseMs = clock.now();
        basePosition = position;
        schedule();
      }
      emit();
    },
    setShowInput(value) {
      options.showInput = Boolean(value);
      rebuild();
    },
    setCompressIdle(value) {
      options.compressIdle = Boolean(value);
      rebuild();
    },
    snapshot,
    onChange(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    dispose() {
      disposed = true;
      playing = false;
      clearTimer();
      listeners.clear();
    },
  };
}
