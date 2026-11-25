import { el, replace } from "../dom.js";
import { openDialog } from "../dialog.js";
import { clean, parseUtcInput, rfc3339, timeWithSeconds } from "../format.js";
import { S } from "../strings.js";
import { button, errorLine, facts, field, pageHead, textInput } from "../ui.js";
import { emptyState, filterBar, pagedTable, timeFilterField } from "./shared.js";

const AUDIT = "/v1/admin/audit";

function eventTime(event) {
  const millis = Date.parse(event.time);
  return Number.isNaN(millis) ? clean(event.time) : timeWithSeconds(Math.floor(millis / 1000));
}

function fieldValue(value) {
  if (typeof value === "string") {
    return clean(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }
  if (typeof value === "boolean") {
    return value ? S.yes : S.no;
  }
  return S.none;
}

export function openEventDrawer(event) {
  const names = S.audit.envelope;
  const envelope = [
    [names.id, clean(event.id), { mono: true }],
    [names.type, clean(event.type), { mono: true }],
    [names.time, eventTime(event)],
    [names.actor, clean(event.actor), { mono: true }],
    [names.node, event.node ? clean(event.node) : null, { mono: true }],
    [names.session_id, event.session_id ? clean(event.session_id) : null, { mono: true }],
    [names.policy_hash, event.policy_hash ? clean(event.policy_hash) : null, { mono: true }],
  ];
  const rows = Object.entries(event.fields && typeof event.fields === "object" ? event.fields : {})
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([key, value]) => [clean(key), fieldValue(value), { mono: true }]);
  openDialog({
    title: S.audit.drawerTitle,
    drawer: true,
    body: [facts(envelope), el("h3", { text: S.audit.fields }), rows.length > 0 ? facts(rows) : el("p", { class: "muted", text: S.audit.noFields })],
    footer: null,
  });
}

export async function auditView(ctx) {
  const values = {
    type: ctx.query.get("type") || "",
    actor: ctx.query.get("actor") || "",
    node: ctx.query.get("node") || "",
    session: ctx.query.get("session") || "",
    from: ctx.query.get("from") || "",
    to: ctx.query.get("to") || "",
  };
  const typeInput = textInput({ value: values.type, maxlength: 64, placeholder: "login." });
  const actorInput = textInput({ value: values.actor, maxlength: 128 });
  const nodeInput = textInput({ value: values.node, maxlength: 128 });
  const sessionInput = textInput({ value: values.session, maxlength: 128 });
  const fromField = timeFilterField(S.audit.filterFrom, "audit-from", values.from);
  const toField = timeFilterField(S.audit.filterTo, "audit-to", values.to);
  const filterError = el("div", { role: "alert" });

  function apply() {
    const from = fromField.querySelector("input").value;
    const to = toField.querySelector("input").value;
    if ((from !== "" && parseUtcInput(from) === null) || (to !== "" && parseUtcInput(to) === null)) {
      filterError.replaceChildren(errorLine(S.audit.invalid.invalid_time));
      return;
    }
    filterError.replaceChildren();
    ctx.navigate("/audit", { type: typeInput.value.trim(), actor: actorInput.value.trim(), node: nodeInput.value.trim(), session: sessionInput.value.trim(), from, to });
  }

  const table = pagedTable({
    caption: S.audit.heading,
    columns: [
      { label: S.audit.colTime, className: "cell-time" },
      { label: S.audit.colType },
      { label: S.audit.colActor },
      { label: S.audit.colNode },
      { label: S.audit.colSession },
      { label: S.audit.colDetails, className: "row-actions" },
    ],
    toRow: (event) => [
      eventTime(event),
      el("span", { class: "mono", text: clean(event.type) }),
      el("span", { class: "mono", text: clean(event.actor) }),
      event.node ? el("span", { class: "mono", text: clean(event.node) }) : S.none,
      event.session_id ? el("span", { class: "mono", text: clean(event.session_id) }) : S.none,
      button(S.audit.details, { small: true, onClick: () => openEventDrawer(event) }),
    ],
    empty: () => emptyState(S.audit.empty),
    fetchPage: async (cursor) => {
      const from = parseUtcInput(values.from);
      const to = parseUtcInput(values.to);
      const page = await ctx.api.get(AUDIT, {
        type: values.type,
        actor: values.actor,
        node: values.node,
        session: values.session,
        from: from === null ? null : rfc3339(from),
        to: to === null ? null : rfc3339(to),
        limit: 50,
        cursor,
      });
      return { items: page.events, next: page.next_cursor };
    },
  });

  const filters = filterBar(
    [
      field({ label: S.audit.filterType, control: typeInput }),
      field({ label: S.audit.filterActor, control: actorInput }),
      field({ label: S.audit.filterNode, control: nodeInput }),
      field({ label: S.audit.filterSession, control: sessionInput }),
      fromField,
      toField,
      filterError,
    ],
    { onSubmit: apply, onReset: () => ctx.navigate("/audit", {}) },
  );
  replace(ctx.main, pageHead(S.audit.heading), el("section", { class: "panel", "aria-label": S.audit.heading }, filters, table.element));
  try {
    await table.load();
  } catch (error) {
    const message = error.status === 400 && S.audit.invalid[error.code];
    if (message) {
      filterError.replaceChildren(errorLine(message));
      return;
    }
    throw error;
  }
}
