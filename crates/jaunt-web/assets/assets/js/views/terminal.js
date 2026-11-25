import { el, replace } from "../dom.js";
import { S } from "../strings.js";
import { linkButton, pageHead } from "../ui.js";
import { emptyState } from "./shared.js";

export async function terminalView(ctx) {
  const extra = [el("p", { class: "muted small", text: S.terminal.picker + ": " + S.terminal.pickerSoon })];
  if (ctx.can("nodes.approve")) {
    extra.push(el("div", { class: "actions center" }, linkButton(S.terminal.toNodes, "#/nodes")));
  }
  replace(ctx.main, pageHead(S.terminal.heading), el("section", { class: "surface-card", "aria-label": S.terminal.picker }, emptyState(S.terminal.comingTitle, S.terminal.comingBody, extra, "terminal")));
}
