import { S } from "./strings.js";

export function hasPermission(session, permission) {
  if (permission === null) {
    return Boolean(session);
  }
  return Boolean(session && Array.isArray(session.permissions) && session.permissions.includes(permission));
}

export const AREAS = [
  {
    id: "nodes",
    label: S.nav.areas.nodes,
    icon: "server",
    pages: [
      { id: "nodes", label: S.nav.pages.nodes, href: "#/nodes", icon: "server", permission: "nodes.approve" },
      { id: "pending", label: S.nav.pages.pending, href: "#/nodes?tab=pending", icon: "clock", permission: "nodes.approve", count: "nodes" },
      { id: "approve", label: S.nav.pages.approve, href: "#/approve", icon: "key", permission: "nodes.approve" },
    ],
  },
  {
    id: "sessions",
    label: S.nav.areas.sessions,
    icon: "pulse",
    pages: [{ id: "sessions", label: S.nav.pages.sessions, href: "#/sessions", icon: "pulse", permission: "sessions.read" }],
  },
  {
    id: "terminal",
    label: S.nav.areas.terminal,
    icon: "terminal",
    pages: [{ id: "terminal", label: S.nav.pages.terminal, href: "#/terminal", icon: "terminal", permission: null }],
  },
  {
    id: "access",
    label: S.nav.areas.access,
    icon: "shield",
    pages: [{ id: "revocations", label: S.nav.pages.revocations, href: "#/revocations", icon: "shield", permission: "sessions.read" }],
  },
  {
    id: "audit",
    label: S.nav.areas.audit,
    icon: "audit",
    pages: [{ id: "audit", label: S.nav.pages.audit, href: "#/audit", icon: "audit", permission: "audit.read" }],
  },
];

export const ADD_NEW = { id: "add", label: S.nav.areas.add, href: "#/approve", icon: "add", permission: "nodes.approve" };

export function visiblePages(area, session) {
  return area.pages.filter((page) => hasPermission(session, page.permission));
}

export function visibleAreas(session) {
  return AREAS.map((area) => ({ area, pages: visiblePages(area, session) })).filter((entry) => entry.pages.length > 0);
}

export function firstAllowedHref(session) {
  for (const area of AREAS) {
    for (const page of area.pages) {
      if (page.permission !== null && hasPermission(session, page.permission)) {
        return page.href.slice(1);
      }
    }
  }
  return null;
}
