import { el, replace } from "../dom.js";
import { isSafeLogin } from "../connect.js";
import { clean } from "../format.js";
import { genericMessage } from "../errors.js";
import { icon } from "../icons.js";
import { S } from "../strings.js";
import { openSession } from "../terminal/screen.js";
import { badge, banner, button, chips, pageHead } from "../ui.js";
import { createsAccountsBadge } from "./node-parts.js";
import { emptyState } from "./shared.js";

const TARGETS = "/v1/web/terminal/targets";
const MAX_TARGETS = 2000;
const MAX_LABELS = 32;
const MAX_LOGINS = 32;
const MAX_SHOWN = 200;
const MAX_QUERY = 128;

function readLabels(value) {
  const labels = {};
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [key, item] of Object.entries(value).slice(0, MAX_LABELS)) {
      if (typeof item === "string") {
        labels[key] = item;
      }
    }
  }
  return labels;
}

export function readTargets(body) {
  if (!Array.isArray(body)) {
    return null;
  }
  const seen = new Set();
  const targets = [];
  for (const entry of body.slice(0, MAX_TARGETS)) {
    if (!entry || typeof entry.node !== "string" || entry.node === "" || seen.has(entry.node) || !Array.isArray(entry.logins)) {
      continue;
    }
    seen.add(entry.node);
    targets.push({
      node: entry.node,
      labels: readLabels(entry.labels),
      connected: entry.connected === true,
      logins: entry.logins.filter(isSafeLogin).slice(0, MAX_LOGINS),
      createsAccounts: entry.creates_accounts === true,
    });
  }
  return targets;
}

function stepList(current) {
  return el(
    "ol",
    { class: "step-list", "aria-label": S.terminal.stepWord },
    S.terminal.steps.map((label, index) => {
      const number = index + 1;
      const done = number < current;
      return el(
        "li",
        { class: done ? "done" : null, "aria-current": number === current ? "step" : null },
        el("span", { class: "num", text: done ? S.terminal.stepDone : String(number) }),
        el("span", { text: label }),
      );
    }),
  );
}

function matches(target, query) {
  if (query === "") {
    return true;
  }
  const haystack = [target.node, ...Object.entries(target.labels).map(([key, value]) => key + ":" + value + " " + key + "=" + value)].join(" ").toLowerCase();
  return haystack.includes(query);
}

function failure(ctx, error, retry) {
  replace(ctx.main, pageHead(S.terminal.heading), banner("danger", S.terminal.loadFailed, genericMessage(error)), el("div", { class: "actions" }, button(S.retry, { kind: "primary", onClick: retry })));
}

export async function terminalView(ctx) {
  replace(ctx.main, pageHead(S.terminal.heading), el("p", { class: "muted", role: "status", text: S.terminal.loading }));
  let targets;
  try {
    targets = readTargets(await ctx.api.get(TARGETS));
  } catch (error) {
    if (!ctx.isCurrent()) {
      return;
    }
    if (error.status === 404) {
      ctx.connect.markTerminal(false);
      replace(ctx.main, pageHead(S.terminal.heading), el("section", { class: "surface-card", "aria-label": S.terminal.heading }, emptyState(S.terminal.disabledTitle, S.terminal.disabledBody, null, "terminal")));
      return;
    }
    if (error.status === 401) {
      return;
    }
    failure(ctx, error, () => ctx.reload());
    return;
  }
  if (!ctx.isCurrent()) {
    return;
  }
  ctx.connect.markTerminal(true);
  if (targets === null) {
    failure(ctx, { status: 500 }, () => ctx.reload());
    return;
  }
  renderPicker(ctx, targets);
}

function renderPicker(ctx, targets) {
  if (targets.length === 0) {
    replace(
      ctx.main,
      pageHead(S.terminal.heading),
      el(
        "section",
        { class: "surface-card", "aria-label": S.terminal.heading },
        emptyState(S.terminal.emptyTitle, S.terminal.emptyBody, el("div", { class: "actions center" }, button(S.terminal.refresh, { onClick: () => ctx.reload() })), "terminal"),
      ),
    );
    return;
  }
  const byNode = new Map(targets.map((target) => [target.node, target]));
  const wantedNode = ctx.query.get("node");
  const wantedLogin = ctx.query.get("login");
  const state = { node: null, login: null, query: "" };
  const initial = wantedNode ? byNode.get(wantedNode) : null;
  if (initial && initial.connected) {
    state.node = initial.node;
    if (wantedLogin !== null) {
      if (initial.logins.includes(wantedLogin)) {
        state.login = wantedLogin;
      }
    } else if (initial.logins.length === 1) {
      state.login = initial.logins[0];
    }
  }

  const live = el("p", { class: "visually-hidden", role: "status" });
  const host = el("div", { class: "guided term-picker" });
  const steps = el("div", {});
  const loginSlot = el("div", {});
  const openSlot = el("div", {});
  const search = el("input", { type: "search", class: "search-input search-solo", "aria-label": S.terminal.searchLabel, placeholder: S.terminal.searchPlaceholder, autocomplete: "off", spellcheck: "false", maxlength: String(MAX_QUERY) });
  const countLine = el("p", { class: "muted small", role: "status" });
  const list = el("ul", { class: "pick-grid", "aria-label": S.terminal.nodeList });

  function currentStep() {
    if (state.node === null) {
      return 1;
    }
    return state.login === null ? 2 : 3;
  }

  function paintSteps() {
    replace(steps, stepList(currentStep()));
  }

  function paintNodes() {
    const query = state.query.trim().toLowerCase();
    const found = targets.filter((target) => matches(target, query));
    const shown = found.slice(0, MAX_SHOWN);
    replace(
      list,
      shown.map((target) => nodeOption(target)),
    );
    countLine.textContent = found.length === 0 ? S.terminal.noMatch : S.terminal.matches(shown.length, found.length);
  }

  function nodeOption(target) {
    const selected = state.node === target.node;
    const input = el("input", { type: "radio", name: "terminal-node", value: target.node, checked: selected, disabled: !target.connected });
    input.addEventListener("change", () => choose(target));
    return el(
      "li",
      {},
      el(
        "label",
        { class: "pick-card" + (selected ? " is-selected" : "") + (target.connected ? "" : " is-off") },
        input,
        el(
          "span",
          { class: "pick-body" },
          el("span", { class: "pick-name", text: clean(target.node) }),
          target.connected ? badge("ok", S.terminal.connectedState) : badge("off", S.terminal.offlineState),
          target.connected && target.createsAccounts ? createsAccountsBadge() : null,
          chips(target.labels),
          target.connected ? null : el("span", { class: "muted small", text: S.terminal.offlineHint }),
        ),
      ),
    );
  }

  function markSelected() {
    for (const card of list.querySelectorAll(".pick-card")) {
      card.classList.toggle("is-selected", card.querySelector("input").checked);
    }
  }

  function choose(target) {
    state.node = target.node;
    state.login = target.logins.length === 1 ? target.logins[0] : null;
    live.textContent = S.terminal.nodeChosen(clean(target.node));
    markSelected();
    paintLogins();
    paintOpen();
    paintSteps();
  }

  function paintLogins() {
    const target = state.node === null ? null : byNode.get(state.node);
    if (target === null) {
      replace(loginSlot, el("p", { class: "muted", text: S.terminal.loginWaiting }));
      return;
    }
    if (target.logins.length === 0) {
      replace(loginSlot, el("p", { class: "muted", text: S.terminal.loginNone }));
      return;
    }
    const options = target.logins.map((login) => {
      const input = el("input", { type: "radio", name: "terminal-login", value: login, checked: state.login === login });
      input.addEventListener("change", () => {
        state.login = login;
        paintOpen();
        paintSteps();
      });
      return el("li", {}, el("label", { class: "pick-login" }, input, el("span", { class: "mono", text: login })));
    });
    replace(
      loginSlot,
      el("fieldset", {}, el("legend", { text: S.terminal.loginLegend }), el("ul", { class: "plain pick-logins" }, options)),
      target.createsAccounts ? el("p", { class: "muted small", text: S.terminal.createsAccountsHelp }) : null,
      target.logins.length === 1 ? el("p", { class: "muted small", text: S.terminal.loginOnly(target.logins[0]) }) : null,
    );
  }

  function paintOpen() {
    const ready = state.node !== null && state.login !== null;
    const start = button(S.terminal.open, { kind: "primary", disabled: !ready, onClick: () => begin() });
    replace(
      openSlot,
      el("p", { class: ready ? "" : "muted", text: ready ? S.terminal.openSummary(clean(state.login), clean(state.node)) : S.terminal.openWaiting }),
      el("div", { class: "actions" }, start),
    );
  }

  function begin() {
    if (state.node === null || state.login === null) {
      return;
    }
    openSession(ctx, { node: state.node, login: state.login });
  }

  search.addEventListener("input", () => {
    state.query = search.value;
    paintNodes();
  });

  paintSteps();
  paintNodes();
  paintLogins();
  paintOpen();

  const refresh = button(S.terminal.refresh, { onClick: () => ctx.reload() });
  replace(
    ctx.main,
    el("div", { class: "page-head" }, el("h1", {}, S.terminal.heading, el("span", { class: "sub", text: S.terminal.intro }))),
    host,
    live,
  );
  replace(
    host,
    steps,
    banner("info", S.terminal.notice),
    el("section", { class: "card", "aria-labelledby": "term-step-node" }, el("h2", { id: "term-step-node", text: S.terminal.nodesHeading }), el("div", { class: "toolbar" }, el("div", { class: "toolbar-group grow" }, el("span", { class: "search-field" }, icon("search"), search)), el("div", { class: "toolbar-group" }, refresh)), countLine, list),
    el("section", { class: "card", "aria-labelledby": "term-step-login" }, el("h2", { id: "term-step-login", text: S.terminal.loginHeading }), loginSlot),
    el("section", { class: "card", "aria-labelledby": "term-step-open" }, el("h2", { id: "term-step-open", text: S.terminal.openHeading }), openSlot),
  );
}
