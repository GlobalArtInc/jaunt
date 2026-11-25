import { el, replace, uniqueId, encodeSegment } from "../dom.js";
import { openConfirm } from "../dialog.js";
import { genericMessage } from "../errors.js";
import { clean, span, time, untilOrSince } from "../format.js";
import { S } from "../strings.js";
import { banner, button, crumbs, errorLine, facts, field, fingerprint, linkButton } from "../ui.js";

const MAX_TIMER_MS = 2147483647;

function stepList(current) {
  return el(
    "ol",
    { class: "step-list", "aria-label": S.approve.stepWord },
    S.approve.steps.map((label, index) => {
      const number = index + 1;
      const done = number < current;
      return el(
        "li",
        { class: done ? "done" : null, "aria-current": number === current ? "step" : null },
        el("span", { class: "num", text: done ? "✓" : String(number) }),
        el("span", { text: label }),
      );
    }),
  );
}

function labelEditor(initial) {
  const rows = el("div", { class: "label-rows" });
  const error = el("div", { role: "alert" });

  function labelRow(key, value) {
    const keyInput = el("input", { type: "text", value: key, "aria-label": S.approve.labelKey, autocomplete: "off", spellcheck: "false", maxlength: "128" });
    const valueInput = el("input", { type: "text", value, "aria-label": S.approve.labelValue, autocomplete: "off", spellcheck: "false", maxlength: "128" });
    const row = el(
      "div",
      { class: "label-row" },
      keyInput,
      el("span", { class: "eq", "aria-hidden": "true", text: "=" }),
      valueInput,
      button(S.approve.labelRemove(clean(key)).split(" ")[0], {
        kind: "ghost",
        onClick: () => {
          row.remove();
          addKey.focus();
        },
      }),
    );
    row.querySelector("button").setAttribute("aria-label", S.approve.labelRemove(clean(key)));
    return row;
  }

  for (const [key, value] of Object.entries(initial || {})) {
    rows.appendChild(labelRow(String(key), String(value)));
  }
  const addKey = el("input", { type: "text", placeholder: S.approve.labelKey, "aria-label": S.approve.labelKey, autocomplete: "off", spellcheck: "false", maxlength: "128" });
  const addValue = el("input", { type: "text", placeholder: S.approve.labelValue, "aria-label": S.approve.labelValue, autocomplete: "off", spellcheck: "false", maxlength: "128" });
  const add = button(S.approve.labelAdd, {
    onClick: () => {
      error.replaceChildren();
      const key = addKey.value.trim();
      const value = addValue.value.trim();
      if (key === "" && value === "") {
        addKey.focus();
        return;
      }
      if (key === "" || value === "") {
        error.replaceChildren(errorLine(S.approve.labelIncomplete));
        return;
      }
      rows.appendChild(labelRow(key, value));
      addKey.value = "";
      addValue.value = "";
      addKey.focus();
    },
  });
  const addRow = el("div", { class: "label-row" }, addKey, el("span", { class: "eq", "aria-hidden": "true", text: "=" }), addValue, add);

  function read() {
    error.replaceChildren();
    const labels = {};
    const entries = Array.from(rows.querySelectorAll(".label-row")).map((row) => {
      const inputs = row.querySelectorAll("input");
      return [inputs[0].value.trim(), inputs[1].value.trim()];
    });
    const pendingKey = addKey.value.trim();
    const pendingValue = addValue.value.trim();
    if (pendingKey !== "" || pendingValue !== "") {
      entries.push([pendingKey, pendingValue]);
    }
    for (const [key, value] of entries) {
      if (key === "" || value === "") {
        error.replaceChildren(errorLine(S.approve.labelIncomplete));
        return null;
      }
      if (Object.prototype.hasOwnProperty.call(labels, key)) {
        error.replaceChildren(errorLine(S.approve.labelDuplicate));
        return null;
      }
      labels[key] = value;
    }
    return labels;
  }

  return { element: el("div", {}, rows, addRow, error), read };
}

function lookupMessage(error) {
  if (error.status === 422) {
    return S.approve.wrongCode;
  }
  if (error.status === 409 && error.code === "enrolment_rejected") {
    return S.approve.rejected;
  }
  if (error.status === 409 && error.code === "already_approved") {
    return S.approve.alreadyApproved;
  }
  return genericMessage(error);
}

export async function approveView(ctx) {
  const host = el("div", { class: "guided" });
  replace(ctx.main, crumbs([{ text: S.approve.crumbNodes, href: "#/nodes" }, { text: S.approve.crumb }]), host);
  let timers = [];
  let preview = null;
  let intent = null;

  function clearTimers() {
    for (const timer of timers) {
      clearTimeout(timer);
    }
    timers = [];
  }
  ctx.onCleanup(clearTimers);

  function show(step, ...children) {
    clearTimers();
    replace(host, stepList(step), ...children);
    const target = host.querySelector("[data-autofocus]") || host.querySelector("h1");
    if (target) {
      target.setAttribute("tabindex", target.getAttribute("tabindex") || "-1");
      target.focus();
    }
  }

  async function refreshPending() {
    try {
      const page = await ctx.api.get("/v1/admin/nodes", { limit: 1 });
      ctx.setNavCount("nodes", Number.isInteger(page.pending_enrolments) ? page.pending_enrolments : 0);
    } catch (error) {
      ctx.setNavCount("nodes", Math.max(0, (ctx.navCount("nodes") || 0) - 1));
    }
  }

  function showCode(message) {
    preview = null;
    intent = null;
    const input = el("input", {
      type: "text",
      class: "code-input",
      autocomplete: "off",
      autocapitalize: "characters",
      spellcheck: "false",
      inputmode: "text",
      maxlength: "32",
      "data-autofocus": "",
    });
    const errorSlot = el("div", { role: "alert" }, typeof message === "string" ? errorLine(message) : null);
    const submit = button(S.approve.continue, { kind: "primary", type: "submit" });
    const form = el(
      "form",
      { novalidate: true },
      field({ label: S.approve.codeLabel, control: input, hint: S.approve.codeHint }),
      errorSlot,
      el("div", { class: "actions" }, submit, linkButton(S.cancel, "#/nodes")),
    );

    let countdown = null;
    function stopCountdown() {
      if (countdown !== null) {
        clearTimeout(countdown);
        countdown = null;
      }
    }
    ctx.onCleanup(stopCountdown);

    function startCountdown(seconds) {
      stopCountdown();
      const until = Date.now() + seconds * 1000;
      submit.disabled = true;
      const tick = () => {
        const left = Math.ceil((until - Date.now()) / 1000);
        if (left > 0) {
          errorSlot.replaceChildren(errorLine(S.approve.rateLimited(left)));
          countdown = setTimeout(tick, 1000);
        } else {
          countdown = null;
          errorSlot.replaceChildren(el("p", { class: "muted", role: "status", text: S.approve.rateReady }));
          submit.disabled = false;
        }
      };
      tick();
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (submit.disabled) {
        return;
      }
      const code = input.value.trim();
      if (code === "") {
        errorSlot.replaceChildren(errorLine(S.approve.codeEmpty));
        input.setAttribute("aria-invalid", "true");
        input.focus();
        return;
      }
      input.removeAttribute("aria-invalid");
      errorSlot.replaceChildren();
      submit.disabled = true;
      try {
        const result = await ctx.api.post("/v1/admin/enrolments/lookup", { code });
        if (!ctx.isCurrent()) {
          return;
        }
        input.value = "";
        preview = result;
        intent = result.intent;
        showCheck();
      } catch (error) {
        if (!ctx.isCurrent()) {
          return;
        }
        if (error.status === 429 && error.retryAfter) {
          startCountdown(error.retryAfter);
          return;
        }
        errorSlot.replaceChildren(errorLine(lookupMessage(error)));
        submit.disabled = false;
        input.focus();
      }
    });

    show(
      1,
      el(
        "section",
        { class: "card" },
        el("h1", { text: S.approve.codeHeading }),
        el("p", { text: S.approve.codeBody }),
        form,
      ),
      el("p", { class: "muted small", text: S.approve.lost }),
    );
  }

  function showIntentExpired() {
    intent = null;
    show(
      1,
      el(
        "section",
        { class: "card" },
        el("h1", { text: S.approve.codeHeading }),
        banner("warn", S.approve.intentExpired),
        button(S.approve.startAgain, { kind: "primary", onClick: showCode }),
      ),
    );
  }

  function showCheck() {
    const enrolment = preview.enrolment;
    const name = clean(enrolment.name);
    const expiry = untilOrSince(enrolment.expires_at, Date.now());
    const errorSlot = el("div", { role: "alert" });
    const editor = labelEditor(enrolment.labels);
    const entries = [
      [S.approve.name, el("strong", { class: "mono", text: name })],
      [S.approve.hostname, clean(enrolment.hostname), { mono: true }],
      [S.approve.source, clean(enrolment.peer_addr), { mono: true }],
      [S.approve.sourceNetwork, enrolment.source_network ? clean(enrolment.source_network) : null, { mono: true }],
      [S.approve.agent, enrolment.agent_version ? clean(enrolment.agent_version) : null, { mono: true }],
      [S.approve.tlsKey, enrolment.tls_key_sha256 ? fingerprint(enrolment.tls_key_sha256) : null],
      [S.approve.hostKey, enrolment.ssh_host_key_fingerprint ? fingerprint(enrolment.ssh_host_key_fingerprint) : null],
      [S.approve.requested, time(enrolment.requested_at)],
      [S.approve.expires, time(enrolment.expires_at) + (expiry.urgency === "expired" ? "" : " (" + S.approve.expiresIn(span(enrolment.expires_at - Math.floor(Date.now() / 1000))) + ")")],
    ];
    const approve = button(S.approve.approve(name), { kind: "primary", id: uniqueId("approve") });
    const reject = button(S.approve.reject, { kind: "danger-outline", onClick: openReject });

    approve.addEventListener("click", async () => {
      const labels = editor.read();
      if (labels === null) {
        return;
      }
      approve.disabled = true;
      errorSlot.replaceChildren();
      try {
        const result = await ctx.api.post("/v1/admin/enrolments/" + encodeURIComponent(enrolment.id) + "/approve", { intent, labels });
        if (!ctx.isCurrent()) {
          return;
        }
        intent = null;
        showDone(result);
        refreshPending();
      } catch (error) {
        if (!ctx.isCurrent()) {
          return;
        }
        if (error.status === 422 && error.code === "invalid_intent") {
          showIntentExpired();
          return;
        }
        if (error.status === 409 || error.status >= 500) {
          showCode(approveMessage(error));
          return;
        }
        errorSlot.replaceChildren(errorLine(approveMessage(error)));
        approve.disabled = false;
      }
    });

    function openReject() {
      openConfirm({
        title: S.approve.rejectTitle(name),
        effects: S.approve.rejectEffects,
        danger: true,
        confirmLabel: S.approve.rejectConfirm,
        cancelLabel: S.approve.keep,
        onConfirm: () => ctx.api.post("/v1/admin/enrolments/" + encodeURIComponent(enrolment.id) + "/reject", { intent }),
        onError: (error) => (error.status === 422 && error.code === "invalid_intent" ? S.approve.intentGone : approveMessage(error)),
        onDone: () => {
          intent = null;
          showRejected(name);
          refreshPending();
        },
      });
    }

    show(
      2,
      el(
        "section",
        { class: "card" },
        el("h1", { text: S.approve.checkHeading }),
        el("p", { text: S.approve.checkBody }),
        facts(entries),
      ),
      enrolment.replace_existing || preview.enrolment.replace_existing ? banner("warn", S.approve.replaceTitle(name) + ".", S.approve.replaceBody) : null,
      banner("warn", S.approve.compareTitle + ".", S.approve.compareBody),
      el(
        "section",
        { class: "card" },
        el("h2", { text: S.approve.labelsHeading }),
        el("p", { text: S.approve.labelsBody }),
        editor.element,
        el("p", { class: "muted small", text: S.approve.labelsNote }),
      ),
      el(
        "section",
        { class: "card" },
        errorSlot,
        el("div", { class: "actions" }, approve, button(S.back, { onClick: showCode }), reject),
        el("p", { class: "muted small", text: S.approve.intentLeft(span(Math.max(0, preview.intent_expires_at - Math.floor(Date.now() / 1000)))) }),
      ),
    );
    const wait = Math.min(Math.max(0, preview.intent_expires_at * 1000 - Date.now()), MAX_TIMER_MS);
    timers.push(setTimeout(showIntentExpired, wait));
  }

  function approveMessage(error) {
    if (error.status === 422 && error.code === "invalid_labels") {
      return S.approve.invalidLabels;
    }
    if (error.status === 409) {
      if (error.code === "name_taken") {
        return S.approve.nameTaken;
      }
      if (error.code === "enrolment_rejected") {
        return S.approve.rejected;
      }
      if (error.code === "already_approved") {
        return S.approve.alreadyApproved;
      }
      if (error.code === "enrolment_not_pending") {
        return S.approve.notPending;
      }
    }
    if (error.status === 429 && error.retryAfter) {
      return S.approve.rateLimited(error.retryAfter);
    }
    return genericMessage(error);
  }

  function showDone(result) {
    const nodeName = clean(result.node && result.node.name);
    show(
      3,
      el(
        "section",
        { class: "card" },
        el("h1", { text: S.approve.doneHeading(nodeName) }),
        el("p", { text: S.approve.doneBody }),
        result.replaced ? banner("info", S.approve.doneReplaced(clean(result.replaced.name))) : null,
        el(
          "div",
          { class: "actions" },
          result.node ? linkButton(S.approve.openNode, "#/nodes/" + encodeSegment(result.node.id), { kind: "primary" }) : null,
          button(S.approve.another, { onClick: showCode }),
          linkButton(S.approve.toNodes, "#/nodes"),
        ),
      ),
    );
  }

  function showRejected(name) {
    show(
      3,
      el(
        "section",
        { class: "card" },
        el("h1", { text: S.approve.rejectedHeading(name) }),
        el("div", { class: "actions" }, button(S.approve.another, { kind: "primary", onClick: showCode }), linkButton(S.approve.toNodes, "#/nodes")),
      ),
    );
  }

  showCode();
}
