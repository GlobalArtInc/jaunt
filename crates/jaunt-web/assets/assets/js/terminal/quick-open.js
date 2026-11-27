import { el, replace, uniqueId } from "../dom.js";
import { clean, recentAgo } from "../format.js";
import { icon } from "../icons.js";
import { S } from "../strings.js";
import { badge, button } from "../ui.js";
import { createsAccountsBadge } from "../views/node-parts.js";

const MAX_QUERY = 128;
const MAX_SHOWN = 200;

function matches(target, query) {
  if (query === "") {
    return true;
  }
  const haystack = [target.node, ...Object.entries(target.labels).map(([key, value]) => key + ":" + value + " " + key + "=" + value)].join(" ").toLowerCase();
  return haystack.includes(query);
}

export function orderedTargets(targets, query) {
  const wanted = query.trim().toLowerCase();
  const found = targets.filter((target) => matches(target, wanted));
  return [...found.filter((target) => target.pinned), ...found.filter((target) => !target.pinned)];
}

export function recentChoices(recent, targets, query) {
  const wanted = query.trim().toLowerCase();
  const byNode = new Map(targets.map((target) => [target.node, target]));
  return recent
    .filter((pair) => byNode.has(pair.node) && byNode.get(pair.node).logins.includes(pair.login))
    .filter((pair) => wanted === "" || (pair.login + "@" + pair.node).toLowerCase().includes(wanted))
    .map((pair) => ({ ...pair, connected: byNode.get(pair.node).connected }));
}

export function createQuickOpen({ connect, now, count, max, preselect, inline, onOpen, onCancel }) {
  const text = S.terminal.quick;
  const wanted = preselect && preselect.node ? connect.target(preselect.node) : null;
  const state = { query: "", node: wanted ? wanted.node : null, login: null };
  if (wanted) {
    state.login = preselect.login && wanted.logins.includes(preselect.login) ? preselect.login : wanted.logins.length === 1 ? wanted.logins[0] : null;
  }
  const limited = max !== null && count >= max;
  const live = el("p", { class: "visually-hidden", role: "status" });
  const search = el("input", { type: "search", class: "search-input search-solo", placeholder: text.searchPlaceholder, "aria-label": text.searchLabel, autocomplete: "off", spellcheck: "false", maxlength: String(MAX_QUERY) });
  const recentSlot = el("section", {});
  const nodesSlot = el("section", { "aria-labelledby": uniqueId("quick-nodes") });
  const staleNote = el("p", { class: "muted small", role: "status", hidden: true, text: text.loadFailed });
  const countText = el("span", { class: "muted small grow", text: text.count(count, max) });
  const primary = button(text.openWaiting, { kind: "primary", disabled: true, onClick: () => submit() });
  const cancel = button(text.cancel, { onClick: () => onCancel() });
  const footer = inline ? [countText, primary] : [countText, cancel, primary];
  const body = el("div", { class: "quick-body" }, el("label", { class: "search-field" }, el("span", { class: "visually-hidden", text: text.searchLabel }), icon("search"), search), staleNote, recentSlot, nodesSlot, live);

  function targetsNow() {
    return connect.targets();
  }

  function selectedTarget() {
    return state.node === null ? null : connect.target(state.node);
  }

  function ready() {
    const target = selectedTarget();
    return !limited && target !== null && target.connected && state.login !== null && target.logins.includes(state.login);
  }

  function paintFooter() {
    const target = selectedTarget();
    const ok = ready();
    primary.textContent = ok ? text.openAs(clean(state.login), clean(target.node)) : text.openWaiting;
    primary.disabled = !ok;
    countText.textContent = limited ? text.atLimit(max) : text.count(count, max);
  }

  function submit() {
    if (!ready()) {
      return;
    }
    onOpen(state.node, state.login);
  }

  function recentRow(pair) {
    const open = button(text.open, { kind: "primary", small: true, disabled: limited || !pair.connected, onClick: () => onOpen(pair.node, pair.login) });
    open.setAttribute("aria-label", text.open + " " + clean(pair.login) + "@" + clean(pair.node));
    return el(
      "li",
      { class: "quick-row" + (pair.connected ? "" : " is-off") },
      el("span", { class: "name mono", text: clean(pair.login) + "@" + clean(pair.node) }),
      el("span", { class: "muted small", text: pair.connected ? recentAgo(pair.lastAt, now()) : text.recentOffline }),
      open,
    );
  }

  function paintRecent() {
    const pairs = recentChoices(connect.recent(), targetsNow(), state.query);
    if (pairs.length === 0) {
      replace(recentSlot);
      recentSlot.hidden = true;
      return;
    }
    recentSlot.hidden = false;
    const headingId = uniqueId("quick-recent");
    recentSlot.setAttribute("aria-labelledby", headingId);
    replace(recentSlot, el("h3", { id: headingId, text: text.recent }), el("ul", { class: "quick-list" }, pairs.map(recentRow)));
  }

  function toggleLogins(target) {
    if (state.node === target.node) {
      state.node = null;
      state.login = null;
    } else {
      state.node = target.node;
      state.login = target.logins.length === 1 ? target.logins[0] : null;
      live.textContent = text.nodeChosen(clean(target.node));
    }
    paintNodes();
    paintFooter();
    if (state.node !== null) {
      const first = nodesSlot.querySelector('input[name="quick-login"]:checked') || nodesSlot.querySelector('input[name="quick-login"]');
      if (first) {
        first.focus();
      }
    } else {
      const again = Array.from(nodesSlot.querySelectorAll("[data-node]")).find((node) => node.getAttribute("data-node") === target.node);
      if (again) {
        again.focus();
      }
    }
  }

  function loginList(target) {
    const options = target.logins.map((login) => {
      const input = el("input", { type: "radio", name: "quick-login", value: login, checked: state.login === login });
      input.addEventListener("change", () => {
        state.login = login;
        paintFooter();
      });
      return el("li", {}, el("label", { class: "pick-login" }, input, el("span", { class: "mono", text: login })));
    });
    return el(
      "div",
      { class: "logins" },
      target.createsAccounts ? el("div", { class: "menu-info" }, icon("info", { size: "sm" }), el("span", {}, el("strong", { text: text.createsAccountsTitle(clean(target.node)) }), " ", text.createsAccountsText)) : null,
      target.logins.length === 0
        ? el("p", { class: "muted small", text: text.loginNone })
        : el("fieldset", {}, el("legend", { text: text.loginsLegend(clean(target.node)) }), el("ul", { class: "plain pick-logins" }, options)),
      target.logins.length === 1 ? el("p", { class: "muted small", text: text.loginOnly(clean(target.logins[0])) }) : null,
      target.hiddenLogins.length > 0
        ? el("p", { class: "muted small" }, text.hiddenBefore, target.hiddenLogins.map((name, index) => [index > 0 ? ", " : null, el("span", { class: "mono", text: clean(name) })]), text.hiddenAfter)
        : null,
    );
  }

  function nodeRow(target) {
    const open = state.node === target.node;
    const panelId = uniqueId("quick-logins");
    const toggle = button(open ? text.hideLogins : text.chooseLogin, { small: true, onClick: () => toggleLogins(target) });
    toggle.setAttribute("aria-expanded", String(open));
    toggle.setAttribute("aria-controls", panelId);
    toggle.setAttribute("data-node", target.node);
    const logins = open && target.connected ? loginList(target) : null;
    if (logins) {
      logins.id = panelId;
    }
    return el(
      "li",
      { class: "quick-row" + (open && target.connected ? " is-open" : "") + (target.connected ? "" : " is-off") },
      target.pinned ? el("span", { class: "muted small" }, icon("pin", { size: "sm" }), el("span", { class: "visually-hidden", text: text.pinnedWord })) : null,
      el("span", { class: "name", text: clean(target.node) }),
      target.connected ? badge("ok", text.online) : badge("off", text.offline),
      target.connected && target.createsAccounts ? createsAccountsBadge() : null,
      target.connected ? toggle : el("span", { class: "muted small", text: text.offlineHint }),
      logins,
    );
  }

  function paintNodes() {
    const targets = targetsNow();
    const shown = orderedTargets(targets, state.query).slice(0, MAX_SHOWN);
    const headingId = uniqueId("quick-nodes-heading");
    nodesSlot.setAttribute("aria-labelledby", headingId);
    replace(
      nodesSlot,
      el("h3", { id: headingId, text: text.nodes }),
      shown.length === 0 ? el("p", { class: "muted", text: targets.length === 0 ? text.noNodes : text.noMatch }) : el("ul", { class: "quick-list" }, shown.map(nodeRow)),
    );
  }

  function paintAll() {
    paintRecent();
    paintNodes();
    paintFooter();
  }

  search.addEventListener("input", () => {
    state.query = search.value;
    paintRecent();
    paintNodes();
  });
  search.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
    }
  });

  paintAll();

  return {
    body,
    footer,
    focus() {
      if (state.node !== null) {
        const chosen = nodesSlot.querySelector('input[name="quick-login"]:checked') || nodesSlot.querySelector('input[name="quick-login"]');
        if (chosen) {
          chosen.focus();
          return;
        }
      }
      search.focus();
    },
    refresh() {
      const target = state.node === null ? null : connect.target(state.node);
      if (target === null) {
        state.node = null;
        state.login = null;
      } else if (state.login !== null && !target.logins.includes(state.login)) {
        state.login = null;
      }
      staleNote.hidden = connect.targetsError() === null;
      paintAll();
    },
    state: () => ({ ...state }),
  };
}
