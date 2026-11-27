import { el, replace, encodeSegment } from "../dom.js";
import { ago, bytes, clean, parseUtcInput, singleLine, span, time } from "../format.js";
import { openConfirm } from "../dialog.js";
import { S } from "../strings.js";
import { badge, button, crumbs, errorLine, facts, field, pageHead, panel, textInput } from "../ui.js";
import { icon } from "../icons.js";
import { dropdown, emptyState, filterBar, pagedTable, radioItems, takeFlash, timeFilterField, toolbar } from "./shared.js";
import { recordingPanel } from "./recording.js";
import { openRevokeDialog } from "./revocations.js";

const SESSIONS = "/v1/admin/sessions";
const REFRESH_MS = 15000;
const STATES = ["routed", "active", "ended"];
const ORIGINS = ["web", "ssh"];
const MAX_REASON = 200;
const ORIGIN_ICONS = { web: "terminal", ssh: "key" };

function stateBadge(state) {
  if (state === "active") {
    return badge("live", S.sessions.stateActive);
  }
  if (state === "routed") {
    return badge("info", S.sessions.stateRouted);
  }
  if (state === "ended") {
    return badge("off", S.sessions.stateEnded);
  }
  return badge("plain", clean(state));
}

function outcome(session) {
  if (session.state === "active") {
    return S.sessions.live;
  }
  if (session.state === "routed") {
    return S.sessions.waiting;
  }
  const parts = [];
  if (session.end_reason) {
    parts.push(clean(session.end_reason));
  }
  if (Number.isInteger(session.exit_status)) {
    parts.push("exit " + session.exit_status);
  }
  return parts.length > 0 ? parts.join(" · ") : S.none;
}

function sessionHref(id) {
  return "#/sessions/" + encodeSegment(id);
}

function originChip(origin) {
  if (!ORIGINS.includes(origin)) {
    return S.none;
  }
  return el("span", { class: "chip" }, icon(ORIGIN_ICONS[origin], { size: "sm" }), S.sessions.origins[origin]);
}

function shortUser(session) {
  const whole = clean(session.user_email || session.user_id);
  const at = whole.indexOf("@");
  return at > 0 ? whole.slice(0, at) : whole;
}

function openTerminateDialog(ctx, session, onDone) {
  const id = clean(String(session.id).slice(0, 8));
  const reason = el("input", { type: "text", maxlength: String(MAX_REASON), autocomplete: "off", spellcheck: "true" });
  const who = shortUser(session);
  const node = clean(session.node_name || session.node_id);
  const rows = [
    [S.sessions.terminateFacts.user, clean(session.user_email || session.user_id)],
    [S.sessions.terminateFacts.node, node],
    [S.sessions.terminateFacts.login, clean(session.login), { mono: true }],
    [S.sessions.terminateFacts.origin, ORIGINS.includes(session.origin) ? S.sessions.origins[session.origin] : null],
    [S.sessions.terminateFacts.started, S.sessions.terminateStarted(time(session.created_at), ago(session.created_at, Date.now()))],
  ];
  openConfirm({
    title: S.sessions.terminateTitle(id),
    effects: S.sessions.terminateEffects(who, node),
    extra: { before: [facts(rows)], after: [field({ label: S.sessions.terminateReason, control: reason })] },
    danger: true,
    closeButton: false,
    focusCancel: true,
    confirmLabel: S.sessions.terminateConfirm,
    onConfirm: async () => {
      const text = singleLine(reason.value);
      await ctx.api.post(SESSIONS + "/" + encodeURIComponent(session.id) + "/terminate", text === "" ? {} : { reason: text });
    },
    onError: (error) => S.sessions.terminateErrors[error.status],
    onDone,
  });
}

function nodeCell(ctx, session) {
  const name = clean(session.node_name || session.node_id);
  return ctx.can("nodes.approve") && session.node_id ? el("a", { href: "#/nodes/" + encodeSegment(session.node_id), text: name }) : name;
}

export async function sessionsView(ctx) {
  const values = {
    state: STATES.includes(ctx.query.get("state")) ? ctx.query.get("state") : "",
    user: ctx.query.get("user") || "",
    node: ctx.query.get("node") || "",
    login: ctx.query.get("login") || "",
    origin: ORIGINS.includes(ctx.query.get("origin")) ? ctx.query.get("origin") : "",
    from: ctx.query.get("from") || "",
    to: ctx.query.get("to") || "",
  };
  const filtered = Object.values(values).some((value) => value !== "");

  const nodeInput = textInput({ value: values.node, maxlength: 128 });
  const loginInput = textInput({ value: values.login, maxlength: 128 });
  const fromField = timeFilterField(S.sessions.filterFrom, "sessions-from", values.from);
  const toField = timeFilterField(S.sessions.filterTo, "sessions-to", values.to);
  const filterError = el("div", { role: "alert" });
  const status = el("div", {});
  const stateNames = { "": S.sessions.any, routed: S.sessions.stateRouted, active: S.sessions.stateActive, ended: S.sessions.stateEnded };
  const originNames = { "": S.sessions.any, web: S.sessions.origins.web, ssh: S.sessions.origins.ssh };

  function go(overrides) {
    const next = { ...values, ...overrides };
    ctx.navigate("/sessions", next);
  }

  function apply() {
    const from = fromField.querySelector("input").value;
    const to = toField.querySelector("input").value;
    if ((from !== "" && parseUtcInput(from) === null) || (to !== "" && parseUtcInput(to) === null)) {
      filterError.replaceChildren(errorLine(S.sessions.invalidTime));
      return;
    }
    filterError.replaceChildren();
    go({ user: search.input.value.trim(), node: nodeInput.value.trim(), login: loginInput.value.trim(), from, to });
  }

  const table = pagedTable({
    caption: S.sessions.heading,
    columns: [
      { label: S.sessions.colSession },
      { label: S.sessions.colState },
      { label: S.sessions.colOrigin, className: "cell-origin" },
      { label: S.sessions.colUser },
      { label: S.sessions.colNode },
      { label: S.sessions.colLogin },
      { label: S.sessions.colStarted, className: "cell-time cell-wrap" },
      { label: S.sessions.colEnded, className: "cell-time cell-wrap" },
      { label: S.sessions.colOutcome },
      { label: S.sessions.colActions, className: "row-actions" },
    ],
    toRow: (session) => [
      el("a", { class: "mono name", href: sessionHref(session.id), text: clean(String(session.id).slice(0, 8)) }),
      stateBadge(session.state),
      originChip(session.origin),
      clean(session.user_email || session.user_id),
      nodeCell(ctx, session),
      el("span", { class: "mono", text: clean(session.login) }),
      time(session.created_at),
      session.ended_at ? time(session.ended_at) : S.none,
      outcome(session),
      session.state === "active" && ctx.can("sessions.terminate") ? terminateButton(session) : null,
    ],
    empty: () => emptyState(filtered ? S.sessions.empty : S.sessions.emptyAll, null, null, "pulse"),
    fetchPage: async (cursor) => {
      const from = parseUtcInput(values.from);
      const to = parseUtcInput(values.to);
      const page = await ctx.api.get(SESSIONS, { state: values.state, origin: values.origin, user: values.user, node: values.node, login: values.login, from, to, limit: 50, cursor });
      return { items: page.sessions, next: page.next };
    },
    onLoaded: (_page, items) => {
      const live = items.filter((session) => session.state === "active").length;
      replace(status, el("span", { class: "sub muted small", text: S.sessions.liveCount(live) }));
    },
  });

  function terminateButton(session) {
    const id = clean(String(session.id).slice(0, 8));
    const control = button(S.sessions.terminate, {
      small: true,
      kind: "danger-outline",
      onClick: () =>
        openTerminateDialog(ctx, session, async () => {
          await refresh();
          ctx.announce(S.sessions.terminateDone(id));
        }),
    });
    control.setAttribute("aria-label", S.sessions.terminateLabel(id));
    return control;
  }

  async function refresh() {
    try {
      filterError.replaceChildren();
      await table.load();
    } catch (error) {
      if (error.status === 401) {
        return;
      }
      filterError.replaceChildren(errorLine(error.status === 422 || error.status === 400 ? S.sessions.invalidFilter : S.failure.body));
    }
  }

  let timer = null;
  function schedule() {
    timer = setTimeout(async () => {
      timer = null;
      if (!document.hidden) {
        await refresh();
      }
      if (autoBox.checked && ctx.isCurrent()) {
        schedule();
      }
    }, REFRESH_MS);
  }
  const autoBox = el("input", { type: "checkbox", id: "sessions-auto" });
  autoBox.addEventListener("change", () => {
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
    if (autoBox.checked) {
      schedule();
    }
  });
  ctx.onCleanup(() => {
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
  });

  const search = filterBar({
    label: S.sessions.searchLabel,
    placeholder: S.sessions.search,
    value: values.user,
    advancedOpen: values.node !== "" || values.login !== "" || values.from !== "" || values.to !== "",
    advanced: [field({ label: S.sessions.filterNode, control: nodeInput }), field({ label: S.sessions.filterLogin, control: loginInput }), fromField, toField],
    onSubmit: apply,
    onReset: () => ctx.navigate("/sessions", {}),
  });
  const stateMenu = dropdown({
    label: S.sessions.stateButton(stateNames[values.state]),
    items: () => radioItems(Object.entries(stateNames), values.state, (value) => go({ state: value })),
  });
  const originMenu = dropdown({
    label: S.sessions.originButton(originNames[values.origin]),
    items: () => radioItems(Object.entries(originNames), values.origin, (value) => go({ origin: value })),
  });
  const refreshButton = el("button", { type: "button", class: "btn btn-menu", on: { click: refresh } }, icon("refresh", { size: "sm" }), el("span", { class: "btn-text", text: S.sessions.refresh }));
  const autoField = el("div", { class: "check" }, autoBox, el("label", { for: "sessions-auto", text: S.sessions.auto }));
  replace(
    ctx.main,
    pageHead(S.sessions.heading),
    search.element,
    filterError,
    toolbar([stateMenu.element, originMenu.element, status], [refreshButton]),
    autoField,
    el("section", { class: "results", "aria-label": S.sessions.heading }, table.element),
  );
  try {
    await table.load();
  } catch (error) {
    if (error.status === 422 || error.status === 400) {
      filterError.replaceChildren(errorLine(S.sessions.invalidFilter));
      return;
    }
    throw error;
  }
}

export async function sessionView(ctx) {
  const [id] = ctx.params;
  const session = await ctx.api.get(SESSIONS + "/" + encodeURIComponent(id));
  if (!ctx.isCurrent()) {
    return;
  }
  ctx.setTitle(S.sessions.detailTitle + " " + clean(String(session.id).slice(0, 8)));
  const actions = [];
  if (ctx.can("revocations.write") && session.user_id) {
    actions.push(
      button(S.sessions.revokeUser, {
        kind: "danger-outline",
        onClick: () => openRevokeDialog(ctx, { kind: "user", subject: session.user_id, display: clean(session.user_email || session.user_id), onDone: () => ctx.reload() }),
      }),
    );
  }
  const entries = [
    [S.sessions.id, clean(session.id), { mono: true }],
    [S.sessions.colState, stateBadge(session.state)],
    [S.sessions.colOrigin, ORIGINS.includes(session.origin) ? S.sessions.origins[session.origin] : null],
    [S.sessions.user, clean(session.user_email || session.user_id)],
    [S.sessions.userId, session.user_email ? clean(session.user_id) : null, { mono: true }],
    [S.sessions.node, nodeCell(ctx, session)],
    [S.sessions.login, clean(session.login), { mono: true }],
    [S.sessions.client, session.client_addr ? clean(session.client_addr) : null, { mono: true }],
    [S.sessions.created, time(session.created_at)],
    [S.sessions.authorized, session.authorized_at ? time(session.authorized_at) : null],
    [S.sessions.ended, session.ended_at ? time(session.ended_at) : null],
    [S.sessions.reason, session.end_reason ? clean(session.end_reason) : null],
    [S.sessions.exit, Number.isInteger(session.exit_status) ? String(session.exit_status) : null],
    [S.sessions.bytesIn, bytes(session.bytes_in)],
    [S.sessions.bytesOut, bytes(session.bytes_out)],
    [S.sessions.serial, session.serial === undefined || session.serial === null ? null : clean(session.serial), { mono: true }],
    [S.sessions.expires, session.expires_at ? time(session.expires_at) : null],
    [S.sessions.maxDuration, Number.isInteger(session.max_duration_secs) ? span(session.max_duration_secs) : null],
  ];
  replace(
    ctx.main,
    crumbs([{ text: S.sessions.detailCrumb, href: "#/sessions" }, { text: clean(String(session.id).slice(0, 8)) }]),
    takeFlash(),
    pageHead(S.sessions.detailTitle + " " + clean(String(session.id).slice(0, 8)), { actions }),
    panel(S.sessions.facts, facts(entries)),
    recordingPanel(ctx, session),
  );
}
