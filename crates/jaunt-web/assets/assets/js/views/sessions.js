import { el, replace, encodeSegment } from "../dom.js";
import { bytes, clean, parseUtcInput, span, time } from "../format.js";
import { S } from "../strings.js";
import { badge, banner, button, crumbs, errorLine, facts, field, pageHead, panel, selectInput, textInput } from "../ui.js";
import { emptyState, filterBar, pagedTable, takeFlash, timeFilterField } from "./shared.js";
import { openRevokeDialog } from "./revocations.js";

const SESSIONS = "/v1/admin/sessions";
const REFRESH_MS = 15000;
const STATES = ["routed", "active", "ended"];

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
    from: ctx.query.get("from") || "",
    to: ctx.query.get("to") || "",
  };
  const filtered = Object.values(values).some((value) => value !== "");

  const stateSelect = selectInput([["", S.sessions.any], ["routed", S.sessions.stateRouted], ["active", S.sessions.stateActive], ["ended", S.sessions.stateEnded]], values.state);
  const userInput = textInput({ value: values.user, maxlength: 128 });
  const nodeInput = textInput({ value: values.node, maxlength: 128 });
  const loginInput = textInput({ value: values.login, maxlength: 128 });
  const fromField = timeFilterField(S.sessions.filterFrom, "sessions-from", values.from);
  const toField = timeFilterField(S.sessions.filterTo, "sessions-to", values.to);
  const filterError = el("div", { role: "alert" });
  const status = el("div", {});

  function apply() {
    const from = fromField.querySelector("input").value;
    const to = toField.querySelector("input").value;
    if ((from !== "" && parseUtcInput(from) === null) || (to !== "" && parseUtcInput(to) === null)) {
      filterError.replaceChildren(errorLine(S.sessions.invalidTime));
      return;
    }
    filterError.replaceChildren();
    ctx.navigate("/sessions", { state: stateSelect.value, user: userInput.value.trim(), node: nodeInput.value.trim(), login: loginInput.value.trim(), from, to });
  }

  const table = pagedTable({
    caption: S.sessions.heading,
    columns: [
      { label: S.sessions.colSession },
      { label: S.sessions.colState },
      { label: S.sessions.colUser },
      { label: S.sessions.colNode },
      { label: S.sessions.colLogin },
      { label: S.sessions.colStarted, className: "cell-time" },
      { label: S.sessions.colEnded, className: "cell-time" },
      { label: S.sessions.colOutcome },
      { label: S.sessions.colBytes },
    ],
    toRow: (session) => [
      el("a", { class: "mono name", href: sessionHref(session.id), text: clean(String(session.id).slice(0, 8)) }),
      stateBadge(session.state),
      clean(session.user_email || session.user_id),
      nodeCell(ctx, session),
      el("span", { class: "mono", text: clean(session.login) }),
      time(session.created_at),
      session.ended_at ? time(session.ended_at) : S.none,
      outcome(session),
      bytes(session.bytes_in) + " / " + bytes(session.bytes_out),
    ],
    empty: () => emptyState(filtered ? S.sessions.empty : S.sessions.emptyAll),
    fetchPage: async (cursor) => {
      const from = parseUtcInput(values.from);
      const to = parseUtcInput(values.to);
      const page = await ctx.api.get(SESSIONS, { state: values.state, user: values.user, node: values.node, login: values.login, from, to, limit: 50, cursor });
      return { items: page.sessions, next: page.next };
    },
    onLoaded: (_page, items) => {
      const live = items.filter((session) => session.state === "active").length;
      replace(status, el("span", { class: "sub muted small", text: S.sessions.liveCount(live) }));
    },
  });

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

  const filters = filterBar(
    [
      field({ label: S.sessions.filterState, control: stateSelect }),
      field({ label: S.sessions.filterUser, control: userInput }),
      field({ label: S.sessions.filterNode, control: nodeInput }),
      field({ label: S.sessions.filterLogin, control: loginInput }),
      fromField,
      toField,
      filterError,
    ],
    { onSubmit: apply, onReset: () => ctx.navigate("/sessions", {}) },
  );
  const controls = el(
    "div",
    { class: "load-more" },
    button(S.sessions.refresh, { onClick: refresh }),
    el("div", { class: "check" }, autoBox, el("label", { for: "sessions-auto", text: S.sessions.auto })),
  );
  replace(ctx.main, pageHead(S.sessions.heading, { sub: "" }), status, el("section", { class: "panel", "aria-label": S.sessions.heading }, filters, controls, table.element));
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
    [S.sessions.recordingState, session.recording ? clean(typeof session.recording === "string" ? session.recording : session.recording.state) : null],
  ];
  replace(
    ctx.main,
    crumbs([{ text: S.sessions.detailCrumb, href: "#/sessions" }, { text: clean(String(session.id).slice(0, 8)) }]),
    takeFlash(),
    pageHead(S.sessions.detailTitle + " " + clean(String(session.id).slice(0, 8)), { actions }),
    panel(S.sessions.facts, facts(entries)),
    banner("info", S.sessions.recordingTitle + ".", S.sessions.recordingNote),
  );
}
