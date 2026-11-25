import { el, uniqueId } from "../dom.js";
import { icon } from "../icons.js";
import { menuButton } from "../menu.js";
import { genericMessage } from "../errors.js";
import { timeWithSeconds } from "../format.js";
import { S } from "../strings.js";
import { banner, button, dataTable, errorLine, loadMoreBar } from "../ui.js";

export function filterBar({ label, placeholder, value, advanced, advancedOpen, advancedLabel, onSubmit, onReset }) {
  const input = el("input", {
    type: "search",
    class: "search-input",
    value: value || "",
    placeholder,
    "aria-label": label,
    autocomplete: "off",
    spellcheck: "false",
    maxlength: "128",
  });
  const advancedId = uniqueId("advanced");
  const toggle = el("input", { type: "checkbox", role: "switch", class: "switch-input", checked: Boolean(advancedOpen), "aria-controls": advancedId });
  const panel = el(
    "div",
    { class: "advanced", id: advancedId, hidden: !advancedOpen, role: "group", "aria-label": advancedLabel || S.advanced },
    advanced,
    el("div", { class: "actions" }, button(S.apply, { kind: "primary", type: "submit" }), button(S.reset, { onClick: onReset })),
  );
  const form = el(
    "form",
    { class: "filters", role: "search", novalidate: true },
    el(
      "div",
      { class: "searchbar" },
      el("span", { class: "search-field" }, icon("search"), input),
      el("label", { class: "switch-field" }, toggle, el("span", { class: "switch-track", "aria-hidden": "true" }), el("span", { class: "switch-text", text: S.advanced })),
    ),
    panel,
  );
  toggle.addEventListener("change", () => {
    panel.hidden = !toggle.checked;
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      onSubmit();
    }
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    onSubmit();
  });
  return { element: form, input, toggle, panel };
}

export function toolbar(start, end) {
  return el("div", { class: "toolbar" }, el("div", { class: "toolbar-group" }, ...start), el("div", { class: "toolbar-group toolbar-end" }, ...end));
}

export function iconButton({ name, label, onClick, pressed, id }) {
  return el(
    "button",
    { type: "button", class: "icon-btn", "aria-label": label, "aria-pressed": pressed === undefined ? null : String(Boolean(pressed)), id, on: onClick ? { click: onClick } : {} },
    icon(name),
  );
}

export function dropdown({ label, items, align, className, icon: iconName }) {
  return menuButton({
    className: className || "btn btn-menu",
    align,
    content: [iconName ? icon(iconName, { size: "sm" }) : null, el("span", { class: "btn-text", text: label }), icon("chevronDown", { size: "sm" })],
    items,
  });
}

export function radioItems(options, current, onChoose) {
  return options.map(([value, text]) => ({ text, role: "menuitemradio", checked: value === current, onSelect: () => onChoose(value) }));
}

export function pagedTable({ caption, columns, toRow, renderItems, fetchPage, empty, onLoaded }) {
  const host = el("div", {});
  const tableSlot = el("div", {});
  const errorSlot = el("div", {});
  let items = [];
  let next = null;
  let busy = false;
  let stamp = "";
  const bar = loadMoreBar({ hasMore: false, onMore: () => more() });
  host.append(tableSlot, errorSlot, bar.element);

  function paint() {
    if (items.length === 0) {
      tableSlot.replaceChildren(empty());
    } else {
      tableSlot.replaceChildren(renderItems ? renderItems(items, next !== null) : dataTable({ caption, columns, rows: items.map(toRow) }));
    }
    paintBar();
  }

  function paintBar() {
    const status = items.length === 0 ? "" : S.showing(items.length, next !== null) + (stamp ? " \u00b7 " + stamp : "");
    bar.update({ hasMore: next !== null, status, busy });
  }

  async function load(reset = true) {
    if (busy) {
      return;
    }
    busy = true;
    paintBar();
    errorSlot.replaceChildren();
    try {
      const page = await fetchPage(reset ? null : next);
      items = reset ? page.items : items.concat(page.items);
      next = page.next || null;
      stamp = S.updated(timeWithSeconds(Math.floor(Date.now() / 1000)));
      if (onLoaded) {
        onLoaded(page, items);
      }
    } finally {
      busy = false;
      paintBar();
    }
    paint();
  }

  async function more() {
    try {
      await load(false);
    } catch (error) {
      errorSlot.replaceChildren(errorLine(genericMessage(error)));
    }
  }

  return { element: host, load, repaint: paint, items: () => items, hasMore: () => next !== null };
}

let flash = null;

export function setFlash(kind, text) {
  flash = { kind, text };
}

export function takeFlash() {
  const current = flash;
  flash = null;
  return current ? banner(current.kind, current.text) : null;
}

export function emptyState(heading, body, extra, iconName) {
  return el(
    "div",
    { class: "empty" },
    el("div", { class: "empty-head" }, icon(iconName || "database", { size: "lg" }), el("h2", { text: heading })),
    body ? el("p", { text: body }) : null,
    extra || null,
  );
}

export function splitLabels(text) {
  return text.split(/\s+/).filter((part) => part !== "");
}

export function timeFilterField(label, id, value) {
  const input = el("input", { type: "datetime-local", id, value: value || "" });
  return el("div", { class: "field" }, el("label", { for: id, text: label }), input);
}
