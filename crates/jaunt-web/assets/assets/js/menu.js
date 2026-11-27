import { el, uniqueId } from "./dom.js";
import { icon } from "./icons.js";

let current = null;

export function closeOpenMenu() {
  if (current) {
    current.close();
  }
}

function itemNode(entry, close) {
  const role = entry.role || "menuitem";
  const checkable = role === "menuitemradio" || role === "menuitemcheckbox";
  const children = [];
  if (checkable) {
    children.push(el("span", { class: "menu-check" }, entry.checked ? icon("check", { size: "sm" }) : null));
  } else if (entry.icon) {
    children.push(el("span", { class: "menu-icon" }, icon(entry.icon, { size: "sm" })));
  }
  children.push(el("span", { class: "menu-text" }, el("span", { class: "menu-label", text: entry.text }), entry.hint ? el("span", { class: "menu-hint", text: entry.hint }) : null));
  const props = {
    class: "menu-item" + (entry.danger ? " menu-danger" : ""),
    role,
    tabindex: "-1",
    "aria-disabled": entry.disabled ? "true" : null,
    "aria-checked": checkable ? (entry.checked ? "true" : "false") : null,
  };
  const node = entry.href && !entry.disabled ? el("a", { ...props, href: entry.href }, ...children) : el("button", { ...props, type: "button" }, ...children);
  node.addEventListener("click", (event) => {
    if (entry.disabled) {
      event.preventDefault();
      return;
    }
    close({ restoreFocus: !entry.href });
    if (entry.onSelect) {
      entry.onSelect(event);
    }
  });
  return node;
}

function keepInView(popup) {
  const box = popup.getBoundingClientRect();
  const width = document.documentElement.clientWidth;
  if (box.width === 0) {
    return;
  }
  if (box.right > width - 8) {
    popup.classList.add("menu-end");
  } else if (box.left < 8) {
    popup.classList.remove("menu-end");
  }
}

export function menuButton({ content, ariaLabel, className, items, align, onOpen, disabled }) {
  const host = el("div", { class: "menu-host" });
  const menuId = uniqueId("menu");
  const trigger = el(
    "button",
    {
      type: "button",
      class: className || "btn",
      "aria-haspopup": "menu",
      "aria-expanded": "false",
      "aria-controls": menuId,
      "aria-label": ariaLabel || null,
      disabled,
    },
    ...content,
  );
  let popup = null;
  const handle = { element: host, button: trigger, isOpen: () => popup !== null, open, close, setDisabled };
  host.appendChild(trigger);

  function setDisabled(value) {
    trigger.disabled = Boolean(value);
  }

  function focusables() {
    return popup ? Array.from(popup.querySelectorAll('[role^="menuitem"]')) : [];
  }

  function focusAt(index) {
    const list = focusables();
    if (list.length === 0) {
      return;
    }
    list[(index + list.length) % list.length].focus();
  }

  function onKey(event) {
    const list = focusables();
    const index = list.indexOf(document.activeElement);
    if (event.key === "ArrowDown") {
      event.preventDefault();
      focusAt(index + 1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      focusAt(index === -1 ? -1 : index - 1);
    } else if (event.key === "Home") {
      event.preventDefault();
      focusAt(0);
    } else if (event.key === "End") {
      event.preventDefault();
      focusAt(-1);
    } else if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      close({ restoreFocus: true });
    } else if (event.key === "Tab") {
      close({ restoreFocus: false });
    }
  }

  function onOutside(event) {
    if (popup && !host.contains(event.target)) {
      close({ restoreFocus: false });
    }
  }

  function open({ focus = "first" } = {}) {
    if (popup || trigger.disabled) {
      return;
    }
    closeOpenMenu();
    if (onOpen) {
      onOpen();
    }
    const entries = items();
    popup = el(
      "div",
      { class: "menu" + (align === "end" ? " menu-end" : ""), id: menuId, role: "menu", "aria-label": ariaLabel || trigger.textContent.trim() },
      entries.map((entry) => {
        if (entry.type === "separator") {
          return el("div", { class: "menu-sep", role: "separator" });
        }
        if (entry.type === "info") {
          return el("div", { class: "menu-info", role: "presentation" }, icon("info", { size: "sm" }), el("span", {}, el("strong", { text: entry.title }), " ", entry.text));
        }
        if (entry.type === "heading") {
          return el("div", { class: "menu-heading", role: "presentation", text: entry.text });
        }
        return itemNode(entry, close);
      }),
    );
    popup.addEventListener("keydown", onKey);
    host.appendChild(popup);
    keepInView(popup);
    trigger.setAttribute("aria-expanded", "true");
    document.addEventListener("mousedown", onOutside);
    document.addEventListener("focusin", onOutside);
    current = handle;
    if (focus === "last") {
      focusAt(-1);
    } else if (focus === "first") {
      focusAt(0);
    }
  }

  function close({ restoreFocus = false } = {}) {
    if (!popup) {
      return;
    }
    popup.remove();
    popup = null;
    trigger.setAttribute("aria-expanded", "false");
    document.removeEventListener("mousedown", onOutside);
    document.removeEventListener("focusin", onOutside);
    if (current === handle) {
      current = null;
    }
    if (restoreFocus && trigger.isConnected) {
      trigger.focus();
    }
  }

  trigger.addEventListener("click", () => {
    if (popup) {
      close({ restoreFocus: true });
    } else {
      open({ focus: "first" });
    }
  });
  trigger.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      open({ focus: "first" });
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      open({ focus: "last" });
    } else if (event.key === "Escape" && popup) {
      event.preventDefault();
      event.stopPropagation();
      close({ restoreFocus: true });
    }
  });
  return handle;
}
