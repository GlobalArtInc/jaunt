import { clean } from "./format.js";
import { el, replace } from "./dom.js";
import { S } from "./strings.js";
import { button, facts, linkButton } from "./ui.js";

export function genericMessage(error) {
  const status = error && typeof error.status === "number" ? error.status : -1;
  if (status === 0) {
    return S.failure.network;
  }
  if (status === 401) {
    return S.expired.heading + ". " + S.expired.keep;
  }
  if (status === 403) {
    return S.api.forbidden;
  }
  if (status === 404) {
    return S.api.notFound;
  }
  if (status === 409) {
    return S.api.conflict;
  }
  if (status === 429) {
    return S.api.busy;
  }
  if (status >= 500) {
    return S.api.server;
  }
  return S.api.invalid;
}

export function renderForbidden(main, { session, permission, path }) {
  const noRights = !session || !session.permissions || session.permissions.length === 0;
  const lines = [];
  lines.push(el("p", { text: noRights ? S.forbidden.noRights : permission ? S.forbidden.missing(permission) : S.forbidden.server }));
  const entries = [];
  if (session && Array.isArray(session.groups) && session.groups.length > 0) {
    entries.push([S.forbidden.groups, session.groups.map(clean).join(", ")]);
  }
  if (permission) {
    entries.push([S.forbidden.needed, el("code", { text: permission })]);
  }
  if (path) {
    entries.push([S.forbidden.page, clean(path), { mono: true }]);
  }
  replace(
    main,
    el(
      "div",
      { class: "errpage" },
      el("p", { class: "code", text: "HTTP 403" }),
      el("h1", { text: S.forbidden.heading }),
      ...lines,
      facts(entries),
      el("p", { class: "muted small", text: S.forbidden.hint }),
      el("div", { class: "actions" }, linkButton(S.forbidden.toStart, "#/")),
    ),
  );
}

export function renderNotFound(main) {
  replace(
    main,
    el(
      "div",
      { class: "errpage" },
      el("p", { class: "code", text: "HTTP 404" }),
      el("h1", { text: S.notFound.heading }),
      el("p", { text: S.notFound.body }),
      el("div", { class: "actions" }, linkButton(S.forbidden.toStart, "#/")),
    ),
  );
}

export function renderFailure(main, error, retry) {
  replace(
    main,
    el(
      "div",
      { class: "errpage" },
      el("h1", { text: S.failure.heading }),
      el("p", { text: error && error.status === 0 ? S.failure.network : S.failure.body }),
      el("div", { class: "actions" }, retry ? button(S.retry, { kind: "primary", onClick: retry }) : null),
    ),
  );
}

export function renderProblem(ctx, error, retry) {
  if (!ctx.isCurrent()) {
    return;
  }
  if (error && error.status === 403) {
    renderForbidden(ctx.main, { session: ctx.session(), permission: ctx.permission || null, path: ctx.path });
  } else if (error && error.status === 404) {
    renderNotFound(ctx.main);
  } else if (error && error.status === 401) {
    replace(ctx.main, el("div", { class: "errpage" }, el("h1", { text: S.expired.heading }), el("p", { text: S.expired.body })));
  } else {
    renderFailure(ctx.main, error, retry);
  }
}
