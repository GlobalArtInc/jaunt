import { el, replace, uniqueId } from "../dom.js";
import { openConfirm, openDialog } from "../dialog.js";
import { genericMessage } from "../errors.js";
import { clean, time } from "../format.js";
import { S } from "../strings.js";
import { badge, button, errorLine, field, pageHead, textInput } from "../ui.js";
import { emptyState, pagedTable, setFlash, takeFlash } from "./shared.js";

const REVOCATIONS = "/v1/admin/revocations";
const KINDS = ["user", "serial", "node"];
const CLOSES_SESSIONS = new Set(["user", "node"]);

function kindName(kind) {
  return S.revocations.kinds[kind] || clean(kind);
}

export function openRevokeDialog(ctx, { kind, subject, display, onDone }) {
  const fixed = Boolean(kind && subject);
  let chosenKind = kind || "user";
  const host = el("div", {});
  let dialog = null;

  function finish(result) {
    dialog.close();
    const created = result && result.created !== false;
    const count = result && Number.isInteger(result.terminated_sessions) ? result.terminated_sessions : 0;
    setFlash(created ? "info" : "warn", created ? S.revocations.created(count) : S.revocations.already);
    if (onDone) {
      onDone(result);
    }
  }

  function showForm(values) {
    const kindControls = KINDS.map((value) => {
      const radio = el("input", { type: "radio", name: "kind", value, checked: value === chosenKind, id: uniqueId("kind") });
      return el("label", { for: radio.id }, radio, " " + kindName(value));
    });
    const subjectInput = textInput({ value: values.subject, maxlength: 128 });
    const subjectLabel = el("label", { for: "revoke-subject", text: S.revocations.subjectLabel[chosenKind] });
    subjectInput.id = "revoke-subject";
    const subjectHint = el("span", { class: "field-hint", text: S.revocations.subjectHint[chosenKind] });
    const reasonInput = el("textarea", { id: "revoke-reason", maxlength: "512", rows: "3" });
    reasonInput.value = values.reason;
    const error = el("div", {});
    const subjectNode = fixed
      ? el("div", { class: "field" }, el("span", { class: "label", text: S.revocations.subjectLabel[chosenKind] }), el("span", { class: "mono", text: display || subject }))
      : el("div", { class: "field" }, subjectLabel, subjectInput, subjectHint);
    if (!fixed) {
      for (const radio of kindControls) {
        radio.querySelector("input").addEventListener("change", (event) => {
          chosenKind = event.target.value;
          subjectLabel.textContent = S.revocations.subjectLabel[chosenKind];
          subjectHint.textContent = S.revocations.subjectHint[chosenKind];
        });
      }
    }
    const review = button(S.revocations.review, {
      kind: "danger-outline",
      onClick: () => {
        const subjectValue = fixed ? subject : subjectInput.value.trim();
        const reasonValue = reasonInput.value.trim();
        if (subjectValue === "") {
          error.replaceChildren(errorLine(S.revocations.subjectMissing));
          subjectInput.setAttribute("aria-invalid", "true");
          subjectInput.focus();
          return;
        }
        if (reasonValue === "") {
          error.replaceChildren(errorLine(S.revocations.reasonMissing));
          reasonInput.setAttribute("aria-invalid", "true");
          reasonInput.focus();
          return;
        }
        showReview({ subject: subjectValue, reason: reasonValue });
      },
    });
    replace(
      host,
      fixed ? null : el("fieldset", { class: "field" }, el("legend", { text: S.revocations.whoTo }), el("div", { class: "row" }, kindControls)),
      subjectNode,
      el("div", { class: "field" }, el("label", { for: "revoke-reason", text: S.revocations.reasonLabel }), reasonInput),
      error,
      el("div", { class: "actions" }, review, button(S.cancel, { onClick: () => dialog.close() })),
      el("p", { class: "muted small", text: S.revocations.reviewHint }),
    );
    (fixed ? reasonInput : subjectInput).focus();
  }

  function showReview({ subject: subjectValue, reason }) {
    const needsCheck = CLOSES_SESSIONS.has(chosenKind);
    const target = fixed ? display || subjectValue : clean(subjectValue);
    const error = el("div", {});
    const checkbox = needsCheck ? el("input", { type: "checkbox", id: "revoke-understand" }) : null;
    const confirm = button(S.revocations.confirm, { kind: "danger", disabled: needsCheck });
    if (checkbox) {
      checkbox.addEventListener("change", () => {
        confirm.disabled = !checkbox.checked;
      });
    }
    confirm.addEventListener("click", async () => {
      confirm.disabled = true;
      error.replaceChildren();
      try {
        const result = await ctx.api.post(REVOCATIONS, { kind: chosenKind, subject: subjectValue, reason });
        finish(result);
      } catch (failure) {
        error.replaceChildren(errorLine(reviewError(failure)));
        confirm.disabled = needsCheck && !checkbox.checked;
      }
    });
    replace(
      host,
      el("p", {}, el("strong", { text: kindName(chosenKind) + " " }), el("span", { class: "mono", text: target })),
      el("ul", { class: "effects" }, S.revocations.effects[chosenKind].map((line) => el("li", { text: line }))),
      el("p", { class: "small muted", text: S.revocations.audit(clean(reason)) }),
      checkbox ? el("div", { class: "check" }, checkbox, el("label", { for: "revoke-understand", text: S.revocations.understand })) : null,
      error,
      el("div", { class: "actions" }, button(S.revocations.back, { onClick: () => showForm({ subject: subjectValue, reason }) }), confirm),
    );
    host.querySelector("button").focus();
  }

  dialog = openDialog({ title: S.revocations.create, body: host, danger: true });
  showForm({ subject: subject || "", reason: "" });
  return dialog;
}

function reviewError(error) {
  if (error.status === 404 && error.code === "unknown_subject") {
    return S.revocations.unknownSubject;
  }
  if (error.status === 400) {
    return S.revocations.invalid;
  }
  return genericMessage(error);
}

function openLift(ctx, revocation) {
  const target = clean(revocation.subject);
  openConfirm({
    title: S.revocations.liftTitle(target),
    effects: [...(S.revocations.liftEffects[revocation.kind] || []), S.revocations.liftAudit],
    confirmLabel: S.revocations.liftConfirm,
    onConfirm: () => ctx.api.del(REVOCATIONS + "/" + encodeURIComponent(revocation.id)),
    onError: (error) => (error.status === 404 ? S.revocations.liftGone : null),
    onDone: () => {
      setFlash("info", S.revocations.lifted);
      ctx.navigate("/revocations", {});
    },
  });
}

export async function revocationsView(ctx) {
  const canWrite = ctx.can("revocations.write");
  const columns = [
    { label: S.revocations.colKind },
    { label: S.revocations.colTarget },
    { label: S.revocations.colReason },
    { label: S.revocations.colBy },
    { label: S.revocations.colSince, className: "cell-time" },
  ];
  if (canWrite) {
    columns.push({ label: S.revocations.colActions, className: "row-actions" });
  }
  const table = pagedTable({
    caption: S.revocations.heading,
    columns,
    toRow: (revocation) => {
      const row = [
        badge(revocation.kind === "node" ? "warn" : "danger", kindName(revocation.kind)),
        el("span", { class: "mono", text: clean(revocation.subject) }),
        clean(revocation.reason),
        clean(revocation.created_by),
        time(revocation.created_at),
      ];
      if (canWrite) {
        row.push(button(S.revocations.lift, { small: true, onClick: () => openLift(ctx, revocation) }));
      }
      return row;
    },
    empty: () => emptyState(S.revocations.empty),
    fetchPage: async (cursor) => {
      const page = await ctx.api.get(REVOCATIONS, { limit: 50, after: cursor });
      return { items: page.revocations, next: page.next };
    },
  });
  const actions = canWrite ? [button(S.revocations.create, { kind: "primary", onClick: () => openRevokeDialog(ctx, { onDone: () => ctx.navigate("/revocations", {}) }) })] : [];
  replace(ctx.main, takeFlash(), pageHead(S.revocations.heading, { actions }), el("section", { class: "panel", "aria-label": S.revocations.heading }, table.element));
  await table.load();
}
