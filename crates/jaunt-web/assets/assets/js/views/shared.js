import { el } from "../dom.js";
import { genericMessage } from "../errors.js";
import { timeWithSeconds } from "../format.js";
import { S } from "../strings.js";
import { banner, button, dataTable, errorLine, loadMoreBar } from "../ui.js";

export function filterBar(fields, { onSubmit, onReset }) {
  const form = el(
    "form",
    { class: "filters", role: "search", novalidate: true },
    fields,
    el("div", { class: "actions" }, button(S.apply, { kind: "primary", type: "submit" }), button(S.reset, { onClick: onReset })),
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    onSubmit();
  });
  return form;
}

export function pagedTable({ caption, columns, toRow, fetchPage, empty, onLoaded }) {
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
      tableSlot.replaceChildren(dataTable({ caption, columns, rows: items.map(toRow) }));
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

  return { element: host, load, items: () => items };
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

export function emptyState(heading, body, extra) {
  return el("div", { class: "empty" }, el("h2", { text: heading }), body ? el("p", { text: body }) : null, extra || null);
}

export function splitLabels(text) {
  return text.split(/\s+/).filter((part) => part !== "");
}

export function timeFilterField(label, id, value) {
  const input = el("input", { type: "datetime-local", id, value: value || "" });
  return el("div", { class: "field" }, el("label", { for: id, text: label }), input);
}
