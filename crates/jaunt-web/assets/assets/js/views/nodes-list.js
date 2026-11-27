import { el, replace } from "../dom.js";
import { openDialog } from "../dialog.js";
import { clean, recentAgo, time, untilOrSince } from "../format.js";
import { icon } from "../icons.js";
import { S } from "../strings.js";
import { banner, button, errorLine, field, linkButton, pageHead, textInput } from "../ui.js";
import { certificateCell, nodeHref, stateBadges } from "./node-parts.js";
import { dropdown, emptyState, filterBar, iconButton, pagedTable, radioItems, splitLabels, takeFlash, toolbar } from "./shared.js";

const LABEL_PATTERN = /^[^:\s]+:\S+$/;
const MAX_LABEL_FILTERS = 16;
const MAX_LABEL_MENU = 60;
const COLLAPSED_LABELS = 3;
const NODES = "/v1/admin/nodes";
const LOGIN_FILTER_FROM = 6;
const VIEW_KEY = "jaunt-nodes-view";
const SORT_VALUES = ["name", "name-desc", "recent"];

export function readViewMode() {
  try {
    return localStorage.getItem(VIEW_KEY) === "list" ? "list" : "grid";
  } catch {
    return "grid";
  }
}

function writeViewMode(mode) {
  try {
    localStorage.setItem(VIEW_KEY, mode);
  } catch {
    return;
  }
}

function compareNames(left, right) {
  return String(left.name).localeCompare(String(right.name), "en", { numeric: true, sensitivity: "base" });
}

export function sortNodes(items, sort) {
  const copy = items.slice();
  if (sort === "name-desc") {
    return copy.sort((left, right) => compareNames(right, left));
  }
  if (sort === "recent") {
    const since = (node) => (node.connected && typeof node.connected_since === "number" ? node.connected_since : -1);
    return copy.sort((left, right) => since(right) - since(left) || compareNames(left, right));
  }
  return copy.sort(compareNames);
}

function labelEntries(labels) {
  return labels && typeof labels === "object" ? Object.entries(labels) : [];
}

function labelChip(key, value) {
  return el("span", { class: "chip" }, el("span", { class: "k", text: clean(key) + ":" }), " ", clean(value));
}

function labelRow(labels, { expanded, locked = false }) {
  const entries = labelEntries(labels);
  if (entries.length === 0) {
    return null;
  }
  const row = el("div", { class: "chips label-row-chips" });
  let open = expanded;

  function paint() {
    const hidden = Math.max(0, entries.length - COLLAPSED_LABELS);
    const shown = open || locked ? entries : entries.slice(0, COLLAPSED_LABELS);
    const children = shown.map(([key, value]) => labelChip(key, value));
    if (hidden > 0 && !locked) {
      const toggle = el("button", { type: "button", class: "link-btn", "aria-expanded": open ? "true" : "false", text: open ? S.nodes.fewerLabels : S.nodes.moreLabels(hidden) });
      toggle.addEventListener("click", () => {
        open = !open;
        paint();
        const next = row.querySelector(".link-btn");
        if (next) {
          next.focus();
        }
      });
      children.push(toggle);
    }
    replace(row, children);
  }

  paint();
  return row;
}

function certificateWarning(certificates) {
  if (!certificates || certificates.state !== "delivered") {
    return null;
  }
  const lines = [
    [S.nodes.certTls, certificates.x509_expires_at],
    [S.nodes.certSsh, certificates.ssh_host_expires_at],
  ]
    .map(([name, seconds]) => ({ name, ...untilOrSince(seconds, Date.now()) }))
    .filter((entry) => entry.urgency === "expired" || entry.urgency === "soon");
  if (lines.length === 0) {
    return null;
  }
  const worst = lines.find((entry) => entry.urgency === "expired") || lines[0];
  const mark = worst.urgency === "expired" ? "✕ " : "▲ ";
  return el("p", { class: "node-warning " + (worst.urgency === "expired" ? "text-danger" : "text-warn"), text: mark + worst.name + ": " + worst.text });
}

async function copyCommand(ctx, command) {
  try {
    await navigator.clipboard.writeText(command);
    ctx.announce(S.nodes.copied);
  } catch {
    const handle = openDialog({
      title: S.nodes.copyTitle,
      body: [el("p", { text: S.nodes.copyBody }), el("pre", { class: "command", text: command })],
      footer: [button(S.close, { onClick: () => handle.close() })],
    });
  }
}

export function openPair(ctx, node, login) {
  const target = ctx.connect.target(node);
  if (target !== null && target.connected && target.logins.includes(login) && !ctx.workspace.atLimit()) {
    ctx.workspace.open({ node, login });
    ctx.navigate("/terminal");
    return;
  }
  ctx.navigate("/terminal", { node, login });
}

function orderedLogins(logins, used) {
  const withUse = logins.filter((login) => used.has(login)).sort((left, right) => used.get(right) - used.get(left));
  return [...withUse, ...logins.filter((login) => !used.has(login))];
}

function loginEntries(ctx, node, filter, menu) {
  const connect = ctx.connect;
  const logins = connect.loginsFor(node.name);
  const entries = [];
  if (connect.createsAccounts(node.name)) {
    entries.push({ type: "info", title: S.nodes.createsAccountsTitle(clean(node.name)), text: S.nodes.createsAccountsText });
  }
  entries.push({ type: "heading", text: S.nodes.menuHeading });
  if (logins.length === 0) {
    entries.push({ text: S.nodes.noLoginItem, disabled: true, hint: S.nodes.noLogins });
  } else {
    if (!node.connected) {
      entries.push({ type: "note", text: S.nodes.offlineNote(clean(node.name)) });
    }
    const used = connect.lastUsed(node.name);
    const wanted = filter.query.trim().toLowerCase();
    const shown = orderedLogins(logins, used).filter((login) => wanted === "" || login.toLowerCase().includes(wanted));
    const items = shown.map((login) => ({
      text: login,
      mono: true,
      icon: "terminal",
      disabled: !node.connected,
      onSelect: () => openPair(ctx, node.name, login),
      meta: used.has(login) ? S.nodes.lastUsed(recentAgo(used.get(login), Date.now())) : null,
    }));
    if (logins.length >= LOGIN_FILTER_FROM) {
      entries.push({
        type: "search",
        label: S.nodes.filterLogins,
        placeholder: S.nodes.filterLogins,
        value: filter.query,
        onInput: (value) => {
          filter.query = value;
          menu.current.refresh();
        },
      });
      entries.push({ type: "scroll", entries: items });
      if (items.length === 0) {
        entries.push({ type: "note", text: S.nodes.noLoginMatch });
      }
    } else {
      entries.push(...items);
    }
    if (logins.length === 1) {
      entries.push({ type: "note", text: S.nodes.oneLogin });
    }
  }
  const hidden = connect.hiddenLoginsFor(node.name);
  if (hidden.length > 0) {
    entries.push({ type: "note", before: S.nodes.hiddenBefore, names: hidden.map(clean), after: S.nodes.hiddenAfter });
  }
  return entries;
}

function connectEntries(ctx, node, filter, menu) {
  const connect = ctx.connect;
  const logins = connect.loginsFor(node.name);
  const entries = [];
  if (logins) {
    entries.push(...loginEntries(ctx, node, filter, menu));
  } else {
    entries.push({ text: S.nodes.openTerminal, icon: "terminal", disabled: true, hint: connect.hasTargets() ? S.nodes.noLogins : connect.terminalEnabled() === false ? S.nodes.openTerminalOff : S.nodes.openTerminalUnknown });
  }
  entries.push({ type: "separator" });
  const only = logins && logins.length === 1 ? logins[0] : undefined;
  const command = connect.command(node.name, only);
  if (command === null) {
    entries.push({ text: S.nodes.copySsh, icon: "copy", disabled: true, hint: S.nodes.copyUnavailable });
  } else {
    entries.push({
      text: only ? S.nodes.copySshAs(only) : S.nodes.copySsh,
      icon: "copy",
      hint: only ? null : S.nodes.copySshHint(S.nodes.loginPlaceholder),
      onSelect: () => copyCommand(ctx, command),
    });
  }
  entries.push({ type: "separator" });
  entries.push({ text: S.nodes.details, icon: "info", href: nodeHref(node.id) });
  return entries;
}

function connectMenu(ctx, node) {
  if (node.state !== "active") {
    return linkButton(S.nodes.details, nodeHref(node.id), { small: true });
  }
  const filter = { query: "" };
  const holder = { current: null };
  const menu = dropdown({
    label: S.nodes.connect,
    className: "btn btn-menu btn-connect",
    align: "end",
    items: () => connectEntries(ctx, node, filter, holder),
    onOpen: () => {
      filter.query = "";
    },
  });
  holder.current = menu;
  menu.button.setAttribute("aria-label", S.nodes.connectLabel(clean(node.name)));
  return menu.element;
}

function pinButton(ctx, node, onToggle) {
  if (!ctx.connect.canPin(node.name)) {
    return null;
  }
  const pinned = ctx.connect.isPinned(node.name);
  const name = clean(node.name);
  return el(
    "button",
    { type: "button", class: "icon-btn pin-btn", "aria-pressed": String(pinned), "aria-label": pinned ? S.nodes.unpin(name) : S.nodes.pin(name), data: { pin: node.name }, on: { click: () => onToggle(node) } },
    icon("pin"),
  );
}

function recentSection(ctx) {
  const pairs = ctx.connect.recent();
  if (pairs.length === 0) {
    return null;
  }
  return el(
    "section",
    { "aria-labelledby": "recent-heading" },
    el("div", { class: "section-head" }, el("h2", { id: "recent-heading" }, icon("clock", { size: "sm" }), S.nodes.recentHeading), el("span", { class: "sub", text: S.nodes.recentSub })),
    el(
      "ul",
      { class: "recent-row" },
      pairs.map((pair) => {
        const open = el(
          "button",
          { type: "button", class: "btn recent-btn", "aria-label": S.nodes.recentOpen(clean(pair.login), clean(pair.node)) },
          icon("terminal", { size: "sm" }),
          el("span", { class: "mono", text: clean(pair.login) + "@" + clean(pair.node) }),
          el("span", { class: "when", text: recentAgo(pair.lastAt, Date.now()) }),
        );
        open.addEventListener("click", () => openPair(ctx, pair.node, pair.login));
        return el("li", {}, open);
      }),
    ),
  );
}

function nodeCard(ctx, node, onToggle) {
  return el(
    "article",
    { class: "node-card" + (node.revoked ? " is-revoked" : "") },
    el("span", { class: "node-icon" }, icon("server", { size: "lg" })),
    el("a", { class: "node-name", href: nodeHref(node.id), title: clean(node.name), text: clean(node.name) }),
    el("div", { class: "node-actions" }, pinButton(ctx, node, onToggle), connectMenu(ctx, node)),
    el(
      "div",
      { class: "node-body" },
      el("p", { class: "node-type" }, icon("server", { size: "sm" }), el("span", { text: S.nodes.typeSsh }), stateBadges(node)),
      certificateWarning(node.certificates),
      labelRow(node.labels, { expanded: false }),
    ),
  );
}

function nodeListRow(ctx, node, expanded, onToggle) {
  const connected = node.connected && node.connected_since ? S.nodes.connectedSince(time(node.connected_since)) : null;
  return el(
    "article",
    { class: "node-row" + (node.revoked ? " is-revoked" : "") },
    el("span", { class: "node-icon" }, icon("server", { size: "lg" })),
    el("div", { class: "node-main" }, el("a", { class: "node-name", href: nodeHref(node.id), title: clean(node.name), text: clean(node.name) }), el("p", { class: "muted small mono node-host", text: clean(node.hostname) })),
    el("div", { class: "node-kind" }, el("p", { class: "node-type" }, icon("server", { size: "sm" }), el("span", { text: S.nodes.typeSsh })), stateBadges(node)),
    el(
      "div",
      { class: "node-meta small" },
      connected ? el("p", { text: connected }) : null,
      node.agent_version ? el("p", { text: S.nodes.agentVersion(clean(node.agent_version)) }) : null,
      certificateCell(node.certificates),
    ),
    el("div", { class: "node-actions" }, pinButton(ctx, node, onToggle), connectMenu(ctx, node)),
    el("div", { class: "node-labels" }, labelRow(node.labels, { expanded, locked: expanded })),
  );
}

function pendingPanel(count) {
  return el(
    "section",
    { class: "surface-card", "aria-label": S.nodes.pendingHeading },
    emptyState(
      count > 0 ? S.nodes.banner(count) : S.nodes.pendingNone,
      S.nodes.pendingBody,
      el("div", { class: "actions center" }, linkButton(S.nodes.enterCode, "#/approve", { kind: "primary" })),
      "clock",
    ),
  );
}

function tabs(pending, onPending) {
  const count = Number.isInteger(pending) && pending > 0 ? pending : 0;
  return el(
    "nav",
    { class: "tabs", "aria-label": S.nodes.tabsLabel },
    el("a", { class: "tab", href: "#/nodes", "aria-current": onPending ? null : "page", text: S.nodes.tabAll }),
    el("a", { class: "tab", href: "#/nodes?tab=pending", "aria-current": onPending ? "page" : null }, S.nodes.tabPending, count > 0 ? el("span", { class: "nav-count", text: String(count) }) : null),
  );
}

async function pendingView(ctx) {
  const flash = takeFlash();
  const heading = pageHead(S.nodes.heading, { actions: [linkButton(S.nodes.approve, "#/approve", { kind: "primary" })] });
  replace(ctx.main, flash, heading, tabs(ctx.navCount("nodes"), true));
  const page = await ctx.api.get(NODES, { limit: 1 });
  if (!ctx.isCurrent()) {
    return;
  }
  const count = Number.isInteger(page.pending_enrolments) ? page.pending_enrolments : 0;
  ctx.setNavCount("nodes", count);
  replace(ctx.main, flash, heading, tabs(count, true), pendingPanel(count));
}

export async function nodesView(ctx) {
  if (ctx.query.get("tab") === "pending") {
    await pendingView(ctx);
    return;
  }
  const state = ctx.query.get("state") === "removed" ? "removed" : "active";
  const prefix = ctx.query.get("q") || "";
  const labels = ctx.query.getAll("label");
  const sort = SORT_VALUES.includes(ctx.query.get("sort")) ? ctx.query.get("sort") : "name";
  const filtered = state !== "active" || prefix !== "" || labels.length > 0;
  let mode = readViewMode();
  let labelsExpanded = true;

  function go(overrides) {
    const next = { state, q: prefix, label: labels, sort, ...overrides };
    ctx.navigate("/nodes", { state: next.state === "active" ? "" : next.state, q: next.q, label: next.label, sort: next.sort === "name" ? "" : next.sort });
  }

  const filterError = el("div", { role: "alert" });
  const labelInput = textInput({ value: labels.join(" "), placeholder: "env:prod team:web" });
  const search = filterBar({
    label: S.nodes.searchLabel,
    placeholder: S.nodes.searchPlaceholder,
    value: prefix,
    advancedOpen: labels.length > 0,
    advancedLabel: S.nodes.advanced,
    advanced: [field({ label: S.nodes.advancedLabels, control: labelInput, hint: S.nodes.labelsHint, wide: true })],
    onSubmit: () => {
      const wanted = splitLabels(labelInput.value);
      if (wanted.length > MAX_LABEL_FILTERS) {
        filterError.replaceChildren(errorLine(S.nodes.tooManyLabels));
        return;
      }
      if (wanted.some((entry) => !LABEL_PATTERN.test(entry))) {
        filterError.replaceChildren(errorLine(S.nodes.invalidFilter.invalid_label));
        return;
      }
      filterError.replaceChildren();
      go({ q: search.input.value.trim(), label: wanted });
    },
    onReset: () => ctx.navigate("/nodes", {}),
  });

  const stateMenu = dropdown({
    label: S.nodes.stateButton(state === "active" ? S.nodes.stateActive : S.nodes.stateRemoved),
    items: () => radioItems([["active", S.nodes.stateActive], ["removed", S.nodes.stateRemoved]], state, (value) => go({ state: value })),
  });
  const labelsMenu = dropdown({
    label: labels.length > 0 ? S.nodes.labelsButtonActive(labels.length) : S.nodes.labelsButton,
    items: () => {
      const known = new Set(labels);
      for (const node of table.items()) {
        for (const [key, value] of labelEntries(node.labels)) {
          if (known.size < MAX_LABEL_MENU) {
            known.add(key + ":" + value);
          }
        }
      }
      const options = Array.from(known).sort();
      if (options.length === 0) {
        return [{ type: "heading", text: S.nodes.labelsMenuNone }];
      }
      const full = labels.length >= MAX_LABEL_FILTERS;
      return [
        { type: "heading", text: S.nodes.labelsMenuHeading },
        ...(table.hasMore() ? [{ type: "heading", text: S.nodes.labelsMenuPartial }] : []),
        ...options.map((option) => {
          const active = labels.includes(option);
          return {
            text: clean(option),
            role: "menuitemcheckbox",
            checked: active,
            disabled: full && !active,
            onSelect: () => go({ label: active ? labels.filter((entry) => entry !== option) : [...labels, option] }),
          };
        }),
      ];
    },
  });
  const sortLabels = { name: S.nodes.sorts.nameAsc, "name-desc": S.nodes.sorts.nameDesc, recent: S.nodes.sorts.recent };
  const sortMenu = dropdown({
    label: sortLabels[sort],
    icon: "sort",
    align: "end",
    items: () => radioItems(SORT_VALUES.map((value) => [value, sortLabels[value]]), sort, (value) => go({ sort: value })),
  });
  sortMenu.button.setAttribute("aria-label", S.nodes.sortLabel + ": " + sortLabels[sort]);

  const gridButton = iconButton({ name: "grid", label: S.nodes.viewGrid, pressed: mode === "grid", onClick: () => setMode("grid") });
  const listButton = iconButton({ name: "rows", label: S.nodes.viewList, pressed: mode === "list", onClick: () => setMode("list") });
  const collapseButton = button("", {
    small: true,
    kind: "ghost",
    onClick: () => {
      labelsExpanded = !labelsExpanded;
      paintCollapse();
      table.repaint();
    },
  });
  const refreshButton = iconButton({ name: "refresh", label: S.nodes.refreshList, onClick: () => reload() });

  function paintCollapse() {
    collapseButton.textContent = labelsExpanded ? S.nodes.collapseLabels : S.nodes.expandLabels;
    collapseButton.hidden = mode !== "list";
  }

  function setMode(next) {
    mode = next;
    writeViewMode(next);
    gridButton.setAttribute("aria-pressed", String(next === "grid"));
    listButton.setAttribute("aria-pressed", String(next === "list"));
    paintCollapse();
    table.repaint();
  }

  const bannerSlot = el("div", {});
  const heading = el("div", {});
  const sortNote = el("p", { class: "muted small sort-note", hidden: true, text: S.nodes.sortNote });
  const tabSlot = el("div", {});

  const table = pagedTable({
    caption: S.nodes.heading,
    columns: [],
    renderItems: (items, more) => {
      sortNote.hidden = !(more && sort !== "name");
      const sorted = sortNodes(items, sort);
      const make = (list) => (mode === "list" ? el("div", { class: "node-list" }, list.map((node) => nodeListRow(ctx, node, labelsExpanded, togglePin))) : el("div", { class: "node-grid" }, list.map((node) => nodeCard(ctx, node, togglePin))));
      const pinned = state === "active" ? sorted.filter((node) => ctx.connect.isPinned(node.name)) : [];
      const rest = pinned.length === 0 ? sorted : sorted.filter((node) => !ctx.connect.isPinned(node.name));
      return el(
        "div",
        {},
        !filtered ? recentSection(ctx) : null,
        pinned.length > 0 ? [el("div", { class: "section-head" }, el("h2", {}, icon("pin", { size: "sm" }), S.nodes.pinnedHeading), el("span", { class: "sub", text: S.nodes.pinnedSub(pinned.length) })), make(pinned)] : null,
        pinned.length > 0 && rest.length > 0 ? el("div", { class: "section-head" }, el("h2", { text: S.nodes.allHeading })) : null,
        rest.length > 0 ? make(rest) : null,
      );
    },
    empty: () =>
      filtered
        ? emptyState(S.nodes.emptyFiltered, null, null, "server")
        : emptyState(S.nodes.emptyHeading, S.nodes.emptyBody, el("pre", { text: S.nodes.emptyCommand(location.origin) }), "server"),
    fetchPage: async (cursor) => {
      const page = await ctx.api.get(NODES, { state, q: prefix, label: labels, limit: 50, cursor });
      return { items: page.nodes, next: page.next, pending: page.pending_enrolments };
    },
    onLoaded: (page, items) => {
      const pending = Number.isInteger(page.pending) ? page.pending : 0;
      ctx.setNavCount("nodes", pending);
      replace(heading, pageHead(S.nodes.heading, { sub: S.nodes.shown(items.length), actions: [linkButton(S.nodes.approve, "#/approve", { kind: "primary" })] }));
      replace(tabSlot, tabs(pending, false));
      replace(
        bannerSlot,
        pending > 0 ? banner("info", S.nodes.banner(pending), S.nodes.bannerBody, linkButton(S.nodes.enterCode, "#/approve", { kind: "primary", small: true })) : null,
      );
    },
  });

  async function togglePin(node) {
    const next = !ctx.connect.isPinned(node.name);
    const name = clean(node.name);
    try {
      await ctx.connect.setPinned(node.name, next);
    } catch (error) {
      if (error.status === 401) {
        return;
      }
      filterError.replaceChildren(errorLine(error.status === 0 ? S.failure.network : error.status === 409 ? S.nodes.pinLimit : S.nodes.pinFailed));
      return;
    }
    if (!ctx.isCurrent()) {
      return;
    }
    filterError.replaceChildren();
    table.repaint();
    ctx.announce(next ? S.nodes.pinnedDone(name) : S.nodes.unpinnedDone(name));
    const again = Array.from(ctx.main.querySelectorAll("[data-pin]")).find((button) => button.getAttribute("data-pin") === node.name);
    if (again) {
      again.focus();
    }
  }

  async function reload() {
    try {
      await table.load();
    } catch (error) {
      if (error.status === 401) {
        return;
      }
      filterError.replaceChildren(errorLine(S.nodes.loadFailed));
    }
  }

  ctx.connect.load().then(() => {
    if (ctx.isCurrent() && table.items().length > 0) {
      table.repaint();
    }
  });
  paintCollapse();
  replace(heading, pageHead(S.nodes.heading, { actions: [linkButton(S.nodes.approve, "#/approve", { kind: "primary" })] }));
  replace(tabSlot, tabs(ctx.navCount("nodes"), false));
  replace(
    ctx.main,
    takeFlash(),
    heading,
    bannerSlot,
    tabSlot,
    search.element,
    filterError,
    toolbar(
      [stateMenu.element, labelsMenu.element],
      [refreshButton, collapseButton, el("div", { class: "view-toggle", role: "group", "aria-label": S.nodes.viewLabel }, gridButton, listButton), sortMenu.element],
    ),
    sortNote,
    el("section", { class: "results", "aria-label": S.nodes.heading }, table.element),
  );
  try {
    await table.load();
  } catch (error) {
    if (error.status === 422 && S.nodes.invalidFilter[error.code]) {
      filterError.replaceChildren(errorLine(S.nodes.invalidFilter[error.code]));
      table.element.replaceChildren();
      return;
    }
    throw error;
  }
}
