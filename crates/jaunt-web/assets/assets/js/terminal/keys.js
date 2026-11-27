const ESC = "\u001b";
const ARROWS = { ArrowUp: "A", ArrowDown: "B", ArrowRight: "C", ArrowLeft: "D" };
const CONTROL_PUNCTUATION = { "@": 0x00, "[": 0x1b, "\\": 0x1c, "]": 0x1d, "^": 0x1e, _: 0x1f, "?": 0x7f, " ": 0x00 };

export const KEY_BAR = [
  { id: "esc", kind: "key", key: "Escape" },
  { id: "tab", kind: "key", key: "Tab" },
  { id: "ctrl", kind: "modifier" },
  { id: "alt", kind: "modifier" },
  { id: "pipe", kind: "char", key: "|" },
  { id: "tilde", kind: "char", key: "~" },
  { id: "slash", kind: "char", key: "/" },
  { id: "up", kind: "key", key: "ArrowUp" },
  { id: "down", kind: "key", key: "ArrowDown" },
  { id: "left", kind: "key", key: "ArrowLeft" },
  { id: "right", kind: "key", key: "ArrowRight" },
  { id: "dash", kind: "char", key: "-" },
  { id: "pgup", kind: "key", key: "PageUp" },
  { id: "pgdn", kind: "key", key: "PageDown" },
];

function controlOf(char) {
  if (char.length !== 1) {
    return null;
  }
  const code = char.charCodeAt(0);
  if ((code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a)) {
    return String.fromCharCode(code & 0x1f);
  }
  if (Object.hasOwn(CONTROL_PUNCTUATION, char)) {
    return String.fromCharCode(CONTROL_PUNCTUATION[char]);
  }
  return null;
}

export function createModifiers() {
  const state = { ctrl: false, alt: false };
  const listeners = new Set();
  const notify = () => {
    for (const listener of listeners) {
      listener({ ...state });
    }
  };
  return {
    state: () => ({ ...state }),
    toggle(name) {
      state[name] = !state[name];
      notify();
    },
    clear() {
      if (state.ctrl || state.alt) {
        state.ctrl = false;
        state.alt = false;
        notify();
      }
    },
    onChange(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    applyToText(text) {
      if (!state.ctrl && !state.alt) {
        return text;
      }
      const characters = Array.from(text);
      if (characters.length !== 1) {
        return text;
      }
      let head = characters[0];
      if (state.ctrl) {
        const control = controlOf(head);
        if (control !== null) {
          head = control;
        }
      }
      if (state.alt && head !== "") {
        head = ESC + head;
      }
      this.clear();
      return head;
    },
  };
}

export function keySequence(key, { applicationCursor = false, ctrl = false, alt = false } = {}) {
  const modifier = 1 + (alt ? 2 : 0) + (ctrl ? 4 : 0);
  if (Object.hasOwn(ARROWS, key)) {
    const final = ARROWS[key];
    if (modifier > 1) {
      return ESC + "[1;" + modifier + final;
    }
    return ESC + (applicationCursor ? "O" : "[") + final;
  }
  if (key === "PageUp" || key === "PageDown") {
    const code = key === "PageUp" ? "5" : "6";
    return ESC + "[" + code + (modifier > 1 ? ";" + modifier : "") + "~";
  }
  if (key === "Escape") {
    return alt ? ESC + ESC : ESC;
  }
  if (key === "Tab") {
    return alt ? ESC + "\t" : "\t";
  }
  return null;
}

const PASTE_CONTROLS = /[\u001b\u0080-\u009f]/g;

export function sanitizePaste(text) {
  return String(text).replace(PASTE_CONTROLS, "");
}
