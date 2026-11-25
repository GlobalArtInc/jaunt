import { el, replace, encodeSegment } from "../dom.js";
import { openConfirm } from "../dialog.js";
import { clean, time, untilOrSince } from "../format.js";
import { S } from "../strings.js";
import { banner, button, chips, crumbs, dataTable, facts, fingerprint, linkButton, pageHead, panel } from "../ui.js";
import { setFlash, takeFlash } from "./shared.js";
import { openRevokeDialog } from "./revocations.js";
import { labelLink, stateBadges } from "./node-parts.js";

const NODES = "/v1/admin/nodes";

function accessTable(access) {
  if (!access.roles || access.roles.length === 0) {
    return el("p", { text: S.node.accessNone });
  }
  const list = (values) => (Array.isArray(values) && values.length > 0 ? values.map(clean).join(", ") : S.none);
  return dataTable({
    caption: S.node.accessTitle,
    columns: [
      { label: S.node.colRole },
      { label: S.node.colUsers },
      { label: S.node.colGroups },
      { label: S.node.colLogins },
      { label: S.node.colForwarding },
      { label: S.node.colInput },
      { label: S.node.colAdmin },
    ],
    rows: access.roles.map((role) => [
      el("span", { class: "name", text: clean(role.role) }),
      list(role.users),
      list(role.groups),
      list(role.logins),
      role.port_forwarding ? S.yes : S.no,
      role.record_input ? S.yes : S.no,
      list(role.admin),
    ]),
  });
}

async function loadAccess(ctx, id) {
  try {
    const access = await ctx.api.get(NODES + "/" + encodeURIComponent(id) + "/access");
    return el(
      "div",
      {},
      el("p", { class: "muted small", text: S.node.accessHint }),
      el("p", { class: "muted small mono", text: S.node.accessPolicy(clean(access.policy_hash), access.policy_loaded_at ? time(access.policy_loaded_at) : "") }),
      accessTable(access),
    );
  } catch (error) {
    if (error.status === 403) {
      return el("p", { class: "muted", text: S.node.accessDenied });
    }
    if (error.status === 401) {
      throw error;
    }
    return el("p", { class: "inline-error", text: S.failure.body });
  }
}

export async function nodeView(ctx) {
  const [id] = ctx.params;
  const node = await ctx.api.get(NODES + "/" + encodeURIComponent(id));
  if (!ctx.isCurrent()) {
    return;
  }
  ctx.setTitle(clean(node.name));
  const canReadSessions = ctx.can("sessions.read");
  const access = canReadSessions ? await loadAccess(ctx, id) : null;
  if (!ctx.isCurrent()) {
    return;
  }

  const actions = [];
  if (ctx.can("revocations.write") && node.state !== "removed") {
    actions.push(
      button(S.node.revoke, {
        kind: "danger-outline",
        onClick: () => openRevokeDialog(ctx, { kind: "node", subject: node.id, display: clean(node.name), onDone: () => ctx.reload() }),
      }),
    );
  }
  if (node.state === "active") {
    actions.push(button(S.node.remove, { kind: "danger-outline", onClick: () => openRemove(ctx, node) }));
  }

  const connected = node.connected && node.connected_since ? time(node.connected_since) : S.node.notConnected;
  const certificates = node.certificates || {};
  const entries = [
    [S.node.state, stateBadges(node)],
    [S.node.address, clean(node.hostname), { mono: true }],
    [S.node.labels, chips(node.labels, labelLink)],
    [S.node.connected, connected],
    [S.node.agent, node.agent_version ? clean(node.agent_version) : S.none, { mono: true }],
    [S.node.tlsCertificate, certificates.x509_expires_at ? expiryText(certificates.x509_expires_at) : null],
    [S.node.sshCertificate, certificates.ssh_host_expires_at ? expiryText(certificates.ssh_host_expires_at) : null],
    [S.node.tlsKey, node.tls_spki_sha256 ? fingerprint(node.tls_spki_sha256) : null],
    [S.node.hostKey, node.ssh_host_key_fingerprint ? fingerprint(node.ssh_host_key_fingerprint) : null],
    [S.node.enrolled, S.node.enrolledBy(time(node.created_at), clean(node.approved_by))],
    [S.node.removedAt, node.removed_at ? time(node.removed_at) : null],
  ];
  const sessions = node.sessions || { open: 0, last_24h: 0 };
  const sessionsBody = el(
    "div",
    {},
    el("p", {}, S.node.sessionsOpen(sessions.open) + " · " + S.node.sessionsDay(sessions.last_24h)),
    canReadSessions ? linkButton(S.node.sessionsLink, "#/sessions?node=" + encodeSegment(node.id), { small: true }) : null,
  );
  replace(
    ctx.main,
    crumbs([{ text: S.node.crumbNodes, href: "#/nodes" }, { text: clean(node.name) }]),
    takeFlash(),
    pageHead(clean(node.name), { actions }),
    node.revoked ? banner("danger", S.nodes.revoked + ".") : null,
    el(
      "div",
      { class: "cols" },
      panel(S.node.factsTitle, facts(entries)),
      el("div", {}, panel(S.node.sessionsTitle, sessionsBody)),
    ),
    canReadSessions ? panel(S.node.accessTitle, access) : null,
  );
}

function expiryText(seconds) {
  const { text } = untilOrSince(seconds, Date.now());
  return time(seconds) + " (" + text + ")";
}

function openRemove(ctx, node) {
  const name = node.name;
  openConfirm({
    title: S.node.removeTitle(clean(name)),
    effects: S.node.removeEffects((node.sessions && node.sessions.open) || 0),
    danger: true,
    confirmLabel: S.node.removeConfirm(clean(name)),
    typed: { expected: name, label: S.node.removeType(clean(name)) },
    onConfirm: () => ctx.api.del(NODES + "/" + encodeURIComponent(node.id), { confirm_name: name }),
    onError: (error) => {
      if (error.status === 422 && error.code === "confirm_name_mismatch") {
        return S.node.removeMismatch;
      }
      if (error.status === 409 && error.code === "node_not_active") {
        return S.node.removeNotActive;
      }
      return null;
    },
    onDone: (result) => {
      const closed = result && Number.isInteger(result.sessions_closed) ? result.sessions_closed : 0;
      setFlash("info", S.nodes.removedNotice(clean(name), closed));
      ctx.navigate("/nodes", {});
    },
  });
}
