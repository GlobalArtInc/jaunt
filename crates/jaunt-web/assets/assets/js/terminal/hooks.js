import { createGuardedWriter, createInteractiveTerminal, loadTerminalLibraries } from "../recording/terminal.js";
import { realHooks } from "./connection.js";

function observeResize(element, callback) {
  if (typeof ResizeObserver === "function") {
    const observer = new ResizeObserver(() => callback());
    observer.observe(element);
    return () => observer.disconnect();
  }
  window.addEventListener("resize", callback);
  return () => window.removeEventListener("resize", callback);
}

export const terminalHooks = {
  loadLibraries: () => loadTerminalLibraries(),
  createTerminal: (options) => createInteractiveTerminal(options),
  createWriter: (terminal, timers) => createGuardedWriter(terminal, timers),
  connection: realHooks(),
  observeResize,
  clipboard: () => (typeof navigator !== "undefined" && navigator.clipboard ? navigator.clipboard : null),
  prefersKeyBar: () => typeof window.matchMedia === "function" && window.matchMedia("(pointer: coarse), (max-width: 760px)").matches,
};
