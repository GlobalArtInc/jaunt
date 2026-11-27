import { el, replace } from "../dom.js";
import { genericMessage } from "../errors.js";
import { S } from "../strings.js";
import { createQuickOpen } from "../terminal/quick-open.js";
import { banner, button, pageHead } from "../ui.js";
import { emptyState } from "./shared.js";

function failure(ctx, error, retry) {
  replace(ctx.main, pageHead(S.terminal.heading), banner("danger", S.terminal.loadFailed, genericMessage(error)), el("div", { class: "actions" }, button(S.retry, { kind: "primary", onClick: retry })));
}

export async function terminalView(ctx) {
  const workspace = ctx.workspace;
  const hasTabs = workspace.count() > 0;
  if (hasTabs) {
    workspace.setVisible(true);
    replace(ctx.main, el("h1", { class: "visually-hidden", text: S.terminal.workspaceHeading }));
  } else {
    replace(ctx.main, pageHead(S.terminal.heading), el("p", { class: "muted", role: "status", text: S.terminal.loading }));
  }
  ctx.onCleanup(() => workspace.setVisible(false));
  await ctx.connect.refresh();
  if (!ctx.isCurrent()) {
    return;
  }
  if (ctx.connect.terminalEnabled() === false) {
    workspace.setVisible(false);
    replace(ctx.main, pageHead(S.terminal.heading), el("section", { class: "surface-card", "aria-label": S.terminal.heading }, emptyState(S.terminal.disabledTitle, S.terminal.disabledBody, null, "terminal")));
    return;
  }
  const status = ctx.connect.targetsError();
  if (status === 401) {
    return;
  }
  if (status !== null && !hasTabs) {
    failure(ctx, { status }, () => ctx.reload());
    return;
  }
  workspace.setMax(ctx.connect.terminalConfig().maxPerUser);

  const wantedNode = ctx.query.get("node");
  const wantedLogin = ctx.query.get("login");
  let preselect = {};
  if (wantedNode) {
    preselect = { node: wantedNode, login: wantedLogin };
  }

  let inline = null;
  let showing = null;

  function paint(focusSearch) {
    if (!ctx.isCurrent()) {
      return;
    }
    workspace.setVisible(true);
    if (workspace.count() > 0) {
      if (showing !== "workspace") {
        showing = "workspace";
        inline = null;
        replace(ctx.main, el("h1", { class: "visually-hidden", text: S.terminal.workspaceHeading }));
      }
      return;
    }
    if (showing === "inline") {
      return;
    }
    showing = "inline";
    if (ctx.connect.targets().length === 0) {
      replace(
        ctx.main,
        pageHead(S.terminal.heading),
        el("section", { class: "surface-card", "aria-label": S.terminal.heading }, emptyState(S.terminal.emptyTitle, S.terminal.emptyBody, el("div", { class: "actions center" }, button(S.terminal.refresh, { onClick: () => ctx.reload() })), "terminal")),
      );
      return;
    }
    inline = createQuickOpen({
      connect: ctx.connect,
      now: () => Date.now(),
      count: 0,
      max: workspace.max(),
      preselect,
      inline: true,
      onOpen: (node, login) => {
        workspace.open({ node, login });
      },
      onCancel: () => undefined,
    });
    replace(
      ctx.main,
      el("div", { class: "page-head" }, el("h1", {}, S.terminal.heading, el("span", { class: "sub", text: S.terminal.intro }))),
      el("section", { class: "panel quick", "aria-labelledby": "quick-inline-title" }, el("header", {}, el("h2", { id: "quick-inline-title", text: S.terminal.quick.title })), el("div", { class: "body" }, inline.body), el("footer", {}, ...inline.footer)),
    );
    if (focusSearch) {
      inline.focus();
    }
  }

  const stop = workspace.onChange(() => {
    if (workspace.count() === 0 && showing === "workspace") {
      showing = null;
    }
    paint(true);
  });
  ctx.onCleanup(stop);

  if (hasTabs && wantedNode) {
    workspace.openNew(preselect);
  }
  showing = hasTabs ? "workspace" : null;
  paint(false);
}
