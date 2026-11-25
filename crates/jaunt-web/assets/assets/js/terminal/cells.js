import { cellSize } from "./fit.js";

export const MAX_MARKS = 6;
export const DEFAULT_CELL_UNITS = 8;
export const ATLAS_BUDGET = 492;

const limitedStores = new WeakSet();
const limitedHandlers = new WeakSet();
const limitedPainters = new WeakSet();
let printing = null;

export class UnsafeTerminalError extends Error {
  constructor(reason) {
    super("the terminal cannot start safely: " + reason);
    this.name = "UnsafeTerminalError";
    this.code = "unsafe_terminal";
  }
}

export function isUnsafeTerminalError(error) {
  return Boolean(error) && error.code === "unsafe_terminal";
}

function pixelRatio(scope) {
  const ratio = Number(scope.devicePixelRatio);
  return ratio > 0 ? ratio : 1;
}

function growth(terminal, largestFont) {
  if (largestFont === undefined) {
    return 1;
  }
  const current = Number(terminal && terminal.options ? terminal.options.fontSize : Number.NaN);
  return current > 0 && largestFont > 0 ? Math.max(1, largestFont / current) : Number.NaN;
}

export function cellUnitsLimit(terminal, { largestFont, scope = globalThis } = {}) {
  return () => {
    const cell = cellSize(terminal);
    const scale = growth(terminal, largestFont);
    if (cell === null || !(scale >= 1)) {
      return DEFAULT_CELL_UNITS;
    }
    return Math.floor(ATLAS_BUDGET / (Math.ceil(cell.width * scale * pixelRatio(scope)) + 1));
  };
}

function deviceCellWidth(render) {
  const dimensions = render && render.dimensions;
  return dimensions && dimensions.device && dimensions.device.cell ? dimensions.device.cell.width : undefined;
}

export function paintUnitsLimit(terminal) {
  return () => {
    const width = deviceCellWidth(terminal._core._renderService);
    if (width === 0) {
      return Number.POSITIVE_INFINITY;
    }
    return width > 0 ? Math.floor(ATLAS_BUDGET / (width + 1)) : DEFAULT_CELL_UNITS;
  };
}

function codePoints(text) {
  let count = 0;
  for (let index = 0; index < text.length; index += text.codePointAt(index) > 0xffff ? 2 : 1) {
    count += 1;
  }
  return count;
}

export function cellAccepts(content, code, units) {
  const grown = content.length + (code > 0xffff ? 2 : 1);
  if (!(grown <= units)) {
    return false;
  }
  return codePoints(content) <= MAX_MARKS;
}

export function fittedContent(content, units) {
  let kept = "";
  for (const point of content) {
    if (kept === "" || cellAccepts(kept, point.codePointAt(0), units)) {
      kept += point;
    }
  }
  return kept;
}

function currentUnits() {
  return printing === null ? DEFAULT_CELL_UNITS : printing.units();
}

function limitCellStore(store) {
  if (limitedStores.has(store)) {
    return;
  }
  const append = store.addCodepointToCell;
  store.addCodepointToCell = function addCodepointToCell(index, code, width) {
    const before = this.getString(index);
    if (cellAccepts(before, code, currentUnits())) {
      append.call(this, index, code, width);
      return;
    }
    if (!width || this.getWidth(index) === width || codePoints(before) < 2) {
      return;
    }
    append.call(this, index, code, width);
    const cell = this.loadCell(index, {});
    cell.combinedData = before;
    this.setCell(index, cell);
  };
  limitedStores.add(store);
}

function printPath(terminal) {
  const core = terminal && terminal._core;
  const handler = core && core._inputHandler;
  const parser = handler && handler._parser;
  if (!handler || typeof handler.print !== "function" || !parser || typeof parser._printHandler !== "function") {
    throw new UnsafeTerminalError("the print path of the terminal library was not found");
  }
  if (Object.hasOwn(handler, "print") && !limitedHandlers.has(handler)) {
    throw new UnsafeTerminalError("the print path of the terminal library is already replaced");
  }
  const lines = core.buffers && core.buffers.normal && core.buffers.normal.lines;
  const line = lines && typeof lines.get === "function" ? lines.get(0) : null;
  const store = line ? Object.getPrototypeOf(line) : null;
  const methods = ["addCodepointToCell", "getString", "getWidth", "isCombined", "loadCell", "setCell"];
  if (!store || !methods.every((name) => typeof store[name] === "function")) {
    throw new UnsafeTerminalError("the cell store of the terminal library was not found");
  }
  return { handler, parser, store };
}

function printsThroughHandler(handler, parser) {
  let reached = false;
  handler.print = function probe() {
    reached = this === handler;
  };
  try {
    parser._printHandler(new Uint32Array(0), 0, 0);
  } finally {
    handler.print = Object.getPrototypeOf(handler).print;
  }
  return reached;
}

export function installCellLimit(terminal, unitsLimit = cellUnitsLimit(terminal)) {
  const { handler, parser, store } = printPath(terminal);
  if (limitedHandlers.has(handler)) {
    return;
  }
  if (!printsThroughHandler(handler, parser)) {
    throw new UnsafeTerminalError("the parser of the terminal library does not print through its handler");
  }
  limitCellStore(store);
  const print = handler.print;
  const session = {
    known: null,
    units() {
      if (this.known === null) {
        this.known = unitsLimit();
      }
      return this.known;
    },
  };
  handler.print = function guardedPrint(data, start, end) {
    const outer = printing;
    session.known = null;
    printing = session;
    try {
      return print.call(this, data, start, end);
    } finally {
      printing = outer;
    }
  };
  limitedHandlers.add(handler);
}

function paintPath(terminal) {
  const core = terminal && terminal._core;
  const render = core && core._renderService;
  const debouncer = render && render._renderDebouncer;
  if (!render || typeof render._renderRows !== "function" || !debouncer || typeof debouncer._renderCallback !== "function") {
    throw new UnsafeTerminalError("the paint path of the terminal library was not found");
  }
  if (Object.hasOwn(render, "_renderRows") && !limitedPainters.has(render)) {
    throw new UnsafeTerminalError("the paint path of the terminal library is already replaced");
  }
  if (typeof deviceCellWidth(render) !== "number") {
    throw new UnsafeTerminalError("the cell size of the terminal renderer was not found");
  }
  const buffer = core.buffer;
  if (!buffer || typeof buffer.ydisp !== "number" || !buffer.lines || typeof buffer.lines.get !== "function") {
    throw new UnsafeTerminalError("the screen buffer of the terminal library was not found");
  }
  return { core, render, debouncer };
}

function paintsThroughService(render, debouncer) {
  let reached = false;
  render._renderRows = function probe() {
    reached = this === render;
  };
  try {
    debouncer._renderCallback(0, -1);
  } finally {
    render._renderRows = Object.getPrototypeOf(render)._renderRows;
  }
  return reached;
}

function trimRows(core, start, end, units) {
  const buffer = core.buffer;
  for (let row = start; row <= end; row += 1) {
    const line = buffer.lines.get(buffer.ydisp + row);
    if (!line) {
      continue;
    }
    for (let index = 0; index < line.length; index += 1) {
      if (!line.isCombined(index)) {
        continue;
      }
      const content = line.getString(index);
      const kept = fittedContent(content, units);
      if (kept !== content) {
        const cell = line.loadCell(index, {});
        cell.combinedData = kept;
        line.setCell(index, cell);
      }
    }
  }
}

export function installPaintLimit(terminal, unitsAtPaint = paintUnitsLimit(terminal)) {
  const { core, render, debouncer } = paintPath(terminal);
  if (limitedPainters.has(render)) {
    return;
  }
  if (!paintsThroughService(render, debouncer)) {
    throw new UnsafeTerminalError("the renderer of the terminal library does not paint through its service");
  }
  const paint = render._renderRows;
  render._renderRows = function guardedPaint(start, end) {
    trimRows(core, start, end, unitsAtPaint());
    return paint.call(this, start, end);
  };
  limitedPainters.add(render);
}
