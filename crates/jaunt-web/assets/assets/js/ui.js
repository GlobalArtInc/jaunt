import { el, uniqueId } from "./dom.js";
import { clean } from "./format.js";
import { icon } from "./icons.js";
import { S } from "./strings.js";

const BADGE_KINDS = new Set(["ok", "off", "warn", "danger", "info", "live", "plain"]);

export function badge(kind, text) {
  const safeKind = BADGE_KINDS.has(kind) ? kind : "plain";
  return el("span", { class: "badge b-" + safeKind, text });
}

export function button(text, { kind, small, onClick, type, disabled, id } = {}) {
  const classes = ["btn"];
  if (kind) {
    classes.push("btn-" + kind);
  }
  if (small) {
    classes.push("btn-sm");
  }
  return el("button", { type: type || "button", class: classes.join(" "), disabled, id, on: onClick ? { click: onClick } : {} }, text);
}

export function linkButton(text, href, { kind, small } = {}) {
  const classes = ["btn"];
  if (kind) {
    classes.push("btn-" + kind);
  }
  if (small) {
    classes.push("btn-sm");
  }
  return el("a", { class: classes.join(" "), href }, text);
}

export function banner(kind, title, body, ...actions) {
  const parts = [el("p", {}, el("span", { class: "banner-title", text: title }), body ? " " : null, body || null)];
  if (actions.length > 0) {
    parts.push(el("div", { class: "actions" }, ...actions));
  }
  return el(
    "div",
    { class: "banner banner-" + kind, role: kind === "danger" || kind === "warn" ? "alert" : "status" },
    el("span", { class: "banner-icon" }, icon(kind === "info" ? "info" : "alert")),
    el("div", { class: "banner-body" }, ...parts),
  );
}

export function chips(labels, hrefFor) {
  const entries = labels && typeof labels === "object" ? Object.entries(labels) : [];
  if (entries.length === 0) {
    return el("span", { class: "muted small", text: S.none });
  }
  return el(
    "span",
    { class: "chips" },
    entries.map(([key, value]) => {
      const inner = [el("span", { class: "k", text: clean(key) + ":" }), " ", clean(value)];
      if (hrefFor) {
        return el("a", { class: "chip chip-link", href: hrefFor(key, value) }, ...inner);
      }
      return el("span", { class: "chip" }, ...inner);
    }),
  );
}

export function field({ label, control, hint, id, error, wide }) {
  const controlId = id || control.id || uniqueId("f");
  control.id = controlId;
  const parts = [el("label", { for: controlId, text: label }), control];
  if (hint) {
    const hintId = controlId + "-hint";
    parts.push(el("span", { class: "field-hint", id: hintId, text: hint }));
    control.setAttribute("aria-describedby", hintId);
  }
  if (error) {
    parts.push(error);
  }
  return el("div", { class: wide ? "field wide" : "field" }, ...parts);
}

export function textInput({ value, placeholder, name, type, autocomplete, inputmode, maxlength, extraClass } = {}) {
  return el("input", {
    type: type || "text",
    name,
    value: value || "",
    placeholder,
    autocomplete: autocomplete || "off",
    inputmode,
    maxlength,
    class: extraClass,
    spellcheck: "false",
  });
}

export function selectInput(options, value) {
  const select = el(
    "select",
    {},
    options.map(([optionValue, text]) => el("option", { value: optionValue, text })),
  );
  select.value = value || options[0][0];
  return select;
}

export function errorLine(text) {
  return el("p", { class: "inline-error", role: "alert", text });
}

export function dataTable({ caption, columns, rows }) {
  const head = el("tr", {}, columns.map((column) => el("th", { scope: "col", class: column.className, text: column.label })));
  const body = rows.map((cells) =>
    el(
      "tr",
      {},
      cells.map((cell, index) => {
        const column = columns[index];
        const attributes = { class: column.className, data: { label: column.label } };
        return index === 0
          ? el("th", { ...attributes, scope: "row", class: ["cell-primary", column.className].filter(Boolean).join(" ") }, cell)
          : el("td", attributes, cell);
      }),
    ),
  );
  return el(
    "div",
    { class: "table-wrap" },
    el("table", { class: "data" }, el("caption", { class: "visually-hidden", text: caption }), el("thead", {}, head), el("tbody", {}, body)),
  );
}

export function facts(entries) {
  const list = el("dl", { class: "kv" });
  for (const [term, value, options] of entries) {
    if (value === null || value === undefined || value === "") {
      continue;
    }
    list.appendChild(el("dt", { text: term }));
    list.appendChild(el("dd", { class: options && options.mono ? "mono" : null }, value));
  }
  return list;
}

export function fingerprint(text) {
  return el("span", { class: "fp mono", text: clean(text) });
}

export function panel(title, content, ...headerActions) {
  const header = el("header", {}, el("h2", { text: title }), ...headerActions);
  return el("section", { class: "panel", "aria-label": title }, header, el("div", { class: "body" }, content));
}

export function pageHead(title, { sub, actions } = {}) {
  return el(
    "div",
    { class: "page-head" },
    el("h1", {}, title, sub ? el("span", { class: "sub", text: sub }) : null),
    actions ? el("div", { class: "actions" }, ...actions) : null,
  );
}

export function crumbs(items) {
  const nodes = [];
  items.forEach((item, index) => {
    if (index > 0) {
      nodes.push(" / ");
    }
    nodes.push(item.href ? el("a", { href: item.href, text: item.text }) : el("span", { text: item.text }));
  });
  return el("nav", { class: "crumbs", "aria-label": "Breadcrumb" }, ...nodes);
}

export function loadMoreBar({ hasMore, onMore, status }) {
  const bar = el("div", { class: "load-more" });
  const more = button(S.loadMore, { onClick: onMore });
  more.hidden = !hasMore;
  const label = el("span", { class: "muted small", role: "status", text: status || "" });
  bar.append(label, more);
  return {
    element: bar,
    update({ hasMore: nextHasMore, status: nextStatus, busy }) {
      more.hidden = !nextHasMore;
      more.disabled = Boolean(busy);
      label.textContent = nextStatus || "";
    },
  };
}
