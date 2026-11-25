import { el, uniqueId } from "./dom.js";
import { S } from "./strings.js";
import { genericMessage } from "./errors.js";
import { button, errorLine } from "./ui.js";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

const open = new Set();

export function closeRouteDialogs() {
  for (const dialog of Array.from(open)) {
    if (dialog.dismissable) {
      dialog.close();
    }
  }
}

function focusableIn(container) {
  return Array.from(container.querySelectorAll(FOCUSABLE)).filter((node) => !node.closest("[hidden]"));
}

export function openDialog({ title, body, footer, danger, drawer, dismissable = true, onClose }) {
  const opener = document.activeElement;
  const titleId = uniqueId("dialog-title");
  const heading = el("h2", { id: titleId, text: title });
  const header = el("header", {}, heading);
  const modal = el(
    "div",
    { class: "modal" + (danger ? " danger" : ""), role: "dialog", "aria-modal": "true", "aria-labelledby": titleId, tabindex: "-1" },
    header,
    el("div", { class: "body" }, body),
  );
  if (footer) {
    modal.appendChild(el("footer", {}, ...footer));
  }
  const scrim = el("div", { class: "scrim" + (drawer ? " drawer" : "") }, modal);
  const hidden = [];
  for (const sibling of Array.from(document.body.children)) {
    if (!sibling.hasAttribute("inert")) {
      sibling.setAttribute("inert", "");
      sibling.setAttribute("aria-hidden", "true");
      hidden.push(sibling);
    }
  }
  let closed = false;

  function close() {
    if (closed) {
      return;
    }
    closed = true;
    open.delete(handle);
    scrim.remove();
    for (const sibling of hidden) {
      sibling.removeAttribute("inert");
      sibling.removeAttribute("aria-hidden");
    }
    if (onClose) {
      onClose();
    }
    if (opener && opener.isConnected && typeof opener.focus === "function") {
      opener.focus();
    }
  }

  if (dismissable) {
    header.appendChild(button(S.close, { small: true, onClick: close }));
    scrim.addEventListener("mousedown", (event) => {
      if (event.target === scrim) {
        close();
      }
    });
  }

  scrim.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && dismissable) {
      event.preventDefault();
      event.stopPropagation();
      close();
      return;
    }
    if (event.key !== "Tab") {
      return;
    }
    const items = focusableIn(modal);
    if (items.length === 0) {
      event.preventDefault();
      modal.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && (active === first || active === modal || !modal.contains(active))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !modal.contains(active))) {
      event.preventDefault();
      first.focus();
    }
  });

  document.body.appendChild(scrim);
  const preferred = modal.querySelector("[data-autofocus]");
  const first = preferred || focusableIn(modal)[0] || modal;
  first.focus();
  const handle = { close, modal, scrim, dismissable, isOpen: () => !closed };
  open.add(handle);
  return handle;
}

export function openConfirm({ title, intro, effects, danger, confirmLabel, cancelLabel, typed, check, onConfirm, onError, onDone }) {
  const errorSlot = el("div", {});
  const children = [];
  if (intro) {
    children.push(el("p", {}, intro));
  }
  if (effects && effects.length > 0) {
    children.push(el("ul", { class: "effects" }, effects.map((line) => el("li", {}, line))));
  }
  let typedInput = null;
  let checkInput = null;
  if (typed) {
    typedInput = el("input", { type: "text", id: uniqueId("confirm-typed"), autocomplete: "off", spellcheck: "false", autocapitalize: "off", "data-autofocus": "" });
    children.push(
      el("div", { class: "field" }, el("label", { for: typedInput.id, text: typed.label }), typedInput),
    );
  }
  if (check) {
    checkInput = el("input", { type: "checkbox", id: uniqueId("confirm-check") });
    children.push(el("div", { class: "check" }, checkInput, el("label", { for: checkInput.id, text: check.label })));
  }
  children.push(errorSlot);
  const confirm = button(confirmLabel, { kind: danger ? "danger" : "primary", disabled: Boolean(typed || check) });
  const cancel = button(cancelLabel || S.cancel, { onClick: () => dialog.close() });
  const dialog = openDialog({ title, body: children, footer: [cancel, confirm], danger });

  function satisfied() {
    const typedOk = !typedInput || typedInput.value === typed.expected;
    const checkOk = !checkInput || checkInput.checked;
    return typedOk && checkOk;
  }

  function sync() {
    confirm.disabled = !satisfied();
  }

  if (typedInput) {
    typedInput.addEventListener("input", sync);
  }
  if (checkInput) {
    checkInput.addEventListener("change", sync);
  }

  confirm.addEventListener("click", async () => {
    if (!satisfied()) {
      return;
    }
    confirm.disabled = true;
    errorSlot.replaceChildren();
    try {
      const result = await onConfirm();
      dialog.close();
      if (onDone) {
        onDone(result);
      }
    } catch (error) {
      const message = (onError && onError(error)) || genericMessage(error);
      errorSlot.replaceChildren(errorLine(message));
      sync();
    }
  });
  return dialog;
}
