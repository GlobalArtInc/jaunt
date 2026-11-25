export const MIN_COLS = 2;
export const MAX_COLS = 500;
export const MIN_ROWS = 1;
export const MAX_ROWS = 200;

function clamp(value, low, high) {
  return Math.min(Math.max(value, low), high);
}

export function cellSize(terminal) {
  const element = terminal && terminal.element;
  const screen = element && typeof element.querySelector === "function" ? element.querySelector(".xterm-screen") : null;
  if (!screen || !terminal.cols || !terminal.rows) {
    return null;
  }
  const box = screen.getBoundingClientRect();
  if (!(box.width > 0) || !(box.height > 0)) {
    return null;
  }
  return { width: box.width / terminal.cols, height: box.height / terminal.rows };
}

function scrollbarWidth(terminal) {
  const viewport = terminal.element && terminal.element.querySelector ? terminal.element.querySelector(".xterm-viewport") : null;
  if (!viewport) {
    return 0;
  }
  return Math.max(0, viewport.offsetWidth - viewport.clientWidth);
}

export function fitSize(host, terminal) {
  const cell = cellSize(terminal);
  if (cell === null) {
    return null;
  }
  const width = host.clientWidth - scrollbarWidth(terminal);
  const height = host.clientHeight;
  if (!(width > 0) || !(height > 0)) {
    return null;
  }
  return {
    cols: clamp(Math.floor(width / cell.width), MIN_COLS, MAX_COLS),
    rows: clamp(Math.floor(height / cell.height), MIN_ROWS, MAX_ROWS),
  };
}

export function clampSize(size) {
  return { cols: clamp(Math.floor(size.cols), MIN_COLS, MAX_COLS), rows: clamp(Math.floor(size.rows), MIN_ROWS, MAX_ROWS) };
}
