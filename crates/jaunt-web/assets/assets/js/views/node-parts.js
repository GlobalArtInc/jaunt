import { el, encodeSegment } from "../dom.js";
import { clean, time, untilOrSince } from "../format.js";
import { S } from "../strings.js";
import { badge } from "../ui.js";

export function labelLink(key, value) {
  return "#/nodes?label=" + encodeSegment(key + ":" + value);
}

export function nodeHref(id) {
  return "#/nodes/" + encodeSegment(id);
}

export function stateBadges(node) {
  const badges = [];
  if (node.state === "removed") {
    badges.push(badge("off", S.nodes.removed));
  } else if (node.state === "active") {
    badges.push(node.connected ? badge("ok", S.nodes.online) : badge("off", S.nodes.offline));
  } else {
    badges.push(badge("plain", clean(node.state)));
  }
  if (node.revoked) {
    badges.push(badge("danger", S.nodes.revoked));
  }
  if (node.state === "active" && node.creates_accounts === true) {
    badges.push(createsAccountsBadge());
  }
  return el("span", { class: "chips" }, ...badges);
}

export function createsAccountsBadge() {
  const mark = badge("acct", S.nodes.createsAccounts);
  mark.setAttribute("title", S.nodes.createsAccountsTip);
  return mark;
}

export function expiryLine(label, seconds) {
  const { text, urgency } = untilOrSince(seconds, Date.now());
  if (text === "") {
    return null;
  }
  const mark = urgency === "expired" ? "✕ " : urgency === "soon" ? "▲ " : "";
  const tone = urgency === "expired" ? "text-danger" : urgency === "soon" ? "text-warn" : null;
  return el("div", { class: tone }, label + ": " + mark + text);
}

export function certificateCell(certificates) {
  if (!certificates || certificates.state === "none") {
    return el("span", { class: "muted", text: S.nodes.certNone });
  }
  if (certificates.state === "pending") {
    return el("span", { class: "muted", text: S.nodes.certPending });
  }
  return el("div", {}, expiryLine(S.nodes.certTls, certificates.x509_expires_at), expiryLine(S.nodes.certSsh, certificates.ssh_host_expires_at));
}

