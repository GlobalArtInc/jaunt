import { createApi } from "./api.js";
import { el, replace } from "./dom.js";
import { closeRouteDialogs, openDialog } from "./dialog.js";
import { renderForbidden, renderNotFound, renderProblem } from "./errors.js";
import { S } from "./strings.js";
import { closeOpenMenu } from "./menu.js";
import { createConnectInfo } from "./connect.js";
import { firstAllowedHref, hasPermission } from "./nav.js";
import { createShell } from "./shell.js";
import { button } from "./ui.js";
import { auditView } from "./views/audit.js";
import { approveView } from "./views/approve.js";
import { nodeView } from "./views/nodes.js";
import { nodesView } from "./views/nodes-list.js";
import { revocationsView } from "./views/revocations.js";
import { renderSignIn, loginHref } from "./views/signin.js";
import { sessionView, sessionsView } from "./views/sessions.js";
import { terminalView } from "./views/terminal.js";

const PENDING_MAX_AGE_MS = 60000;
const NODES_PAGE = (query) => (query.get("tab") === "pending" ? "pending" : "nodes");

const ROUTES = [
  { pattern: /^\/nodes$/, view: nodesView, permission: "nodes.approve", area: "nodes", page: NODES_PAGE, title: S.titles.nodes, reportsPending: true },
  { pattern: /^\/nodes\/([^/]+)$/, view: nodeView, permission: "nodes.approve", area: "nodes", page: () => "nodes", title: S.titles.nodes },
  { pattern: /^\/approve$/, view: approveView, permission: "nodes.approve", area: "nodes", page: () => "approve", title: S.titles.approve, reportsPending: true },
  { pattern: /^\/sessions$/, view: sessionsView, permission: "sessions.read", area: "sessions", page: () => "sessions", title: S.titles.sessions },
  { pattern: /^\/sessions\/([^/]+)$/, view: sessionView, permission: "sessions.read", area: "sessions", page: () => "sessions", title: S.titles.sessions },
  { pattern: /^\/revocations$/, view: revocationsView, permission: "sessions.read", area: "access", page: () => "revocations", title: S.titles.revocations },
  { pattern: /^\/audit$/, view: auditView, permission: "audit.read", area: "audit", page: () => "audit", title: S.titles.audit },
  { pattern: /^\/terminal$/, view: terminalView, permission: null, area: "terminal", page: () => "terminal", title: S.titles.terminal },
];

export { hasPermission };

function parseHash() {
  const raw = location.hash.replace(/^#/, "");
  const cut = raw.indexOf("?");
  const path = cut === -1 ? raw : raw.slice(0, cut);
  const query = new URLSearchParams(cut === -1 ? "" : raw.slice(cut + 1));
  return { path: path === "" ? "/" : path, query };
}

function matchRoute(path) {
  for (const route of ROUTES) {
    const match = route.pattern.exec(path);
    if (match) {
      try {
        return { route, params: match.slice(1).map(decodeURIComponent) };
      } catch {
        return null;
      }
    }
  }
  return null;
}

function hashFor(path, query) {
  const pairs = [];
  for (const [key, value] of Object.entries(query || {})) {
    for (const item of Array.isArray(value) ? value : [value]) {
      if (item !== "" && item !== null && item !== undefined) {
        pairs.push([key, item]);
      }
    }
  }
  const text = new URLSearchParams(pairs).toString();
  return "#" + path + (text === "" ? "" : "?" + text);
}

export function start(root) {
  const state = { session: null, wasSignedIn: false, token: 0, cleanups: [], expiredDialog: null, shell: null, active: true, counts: {}, current: { area: null, page: null }, pendingAt: 0 };

  const api = createApi({
    onUnauthorized: () => showExpired(),
    onSession: (session) => {
      if (state.session && state.session.user_id !== session.user_id) {
        connect.reset();
      }
      state.session = session;
      refreshNav();
    },
  });

  const connect = createConnectInfo(api);
  connect.onChange(() => refreshNav());

  function runCleanups() {
    const pending = state.cleanups;
    state.cleanups = [];
    for (const cleanup of pending) {
      cleanup();
    }
  }

  function showExpired() {
    if (!state.wasSignedIn || state.expiredDialog) {
      return;
    }
    const status = el("p", { class: "inline-error", role: "alert", hidden: true, text: S.expired.stillOut });
    const signIn = el("a", { class: "btn btn-primary", href: loginHref(), target: "_blank", rel: "noopener", "data-autofocus": "" }, S.expired.signIn);
    const proceed = button(S.expired.continue, {
      onClick: async () => {
        status.hidden = true;
        try {
          state.session = await api.session();
          refreshNav();
          state.expiredDialog.close();
        } catch (error) {
          status.textContent = error.status === 401 ? S.expired.stillOut : S.failure.network;
          status.hidden = false;
        }
      },
    });
    state.expiredDialog = openDialog({
      title: S.expired.heading,
      body: [el("p", { text: S.expired.body }), el("p", { text: S.expired.keep }), status],
      footer: [signIn, proceed],
      dismissable: false,
      onClose: () => {
        state.expiredDialog = null;
      },
    });
  }

  function go(path, query, options = {}) {
    const hash = hashFor(path, query);
    if (hash === location.hash) {
      render();
    } else if (options.replace) {
      history.replaceState(null, "", hash);
      render();
    } else {
      location.hash = hash;
    }
  }

  function currentModel() {
    return { session: state.session, current: state.current, counts: state.counts, terminal: connect.terminalEnabled() };
  }

  function buildShell() {
    connect.reset();
    const shell = createShell({ root, onSignOut: signOutNow });
    state.shell = { main: shell.main, live: shell.live, handle: shell };
    state.counts = {};
    state.pendingAt = 0;
    state.current = { area: null, page: null };
    refreshNav();
  }

  function refreshNav() {
    if (!state.shell) {
      return;
    }
    state.shell.handle.update(currentModel());
  }

  async function loadPending() {
    if (!hasPermission(state.session, "nodes.approve") || !state.shell) {
      return;
    }
    state.pendingAt = Date.now();
    try {
      const page = await api.get("/v1/admin/nodes", { limit: 1 });
      if (state.shell && Number.isInteger(page.pending_enrolments)) {
        state.counts.nodes = page.pending_enrolments;
        refreshNav();
      }
    } catch (error) {
      if (error.status === 401) {
        return;
      }
      state.pendingAt = 0;
    }
  }

  async function signOutNow() {
    try {
      await api.post("/v1/web/logout");
    } catch (error) {
      if (error.status !== 401) {
        state.shell.main.prepend(el("p", { class: "inline-error", role: "alert", text: S.api.server }));
        return;
      }
    }
    api.forget();
    runCleanups();
    state.session = null;
    state.wasSignedIn = false;
    state.shell.handle.destroy();
    state.shell = null;
    renderSignIn(root, { notice: S.signIn.signedOut });
  }

  async function render() {
    if (!state.active || !state.shell) {
      return;
    }
    runCleanups();
    closeRouteDialogs();
    closeOpenMenu();
    state.shell.handle.closeDrawer();
    state.token += 1;
    const mine = state.token;
    const { main } = state.shell;
    const { path, query } = parseHash();
    if (path === "/") {
      const target = firstAllowedHref(state.session);
      if (target) {
        go(target, null, { replace: true });
        return;
      }
      await connect.load();
      if (state.token !== mine || !state.active) {
        return;
      }
      if (connect.terminalEnabled() !== false) {
        go("/terminal", null, { replace: true });
        return;
      }
      state.current = { area: null, page: null };
      refreshNav();
      document.title = S.titles.notAllowed + " · " + S.product;
      renderForbidden(main, { session: state.session, permission: null, path: null });
      return;
    }
    const matched = matchRoute(path);
    main.replaceChildren();
    if (!matched) {
      state.current = { area: null, page: null };
      refreshNav();
      document.title = S.titles.notFound + " · " + S.product;
      renderNotFound(main);
      main.focus({ preventScroll: true });
      return;
    }
    const { route, params } = matched;
    state.current = { area: route.area, page: route.page(query) };
    refreshNav();
    document.title = route.title + " · " + S.product;
    if (!hasPermission(state.session, route.permission)) {
      document.title = S.titles.notAllowed + " · " + S.product;
      renderForbidden(main, { session: state.session, permission: route.permission, path: "#" + path });
      main.focus({ preventScroll: true });
      return;
    }
    const ctx = {
      api,
      main,
      query,
      params,
      path: "#" + path,
      permission: route.permission,
      session: () => state.session,
      can: (permission) => hasPermission(state.session, permission),
      isCurrent: () => state.token === mine && state.active,
      navigate: go,
      reload: () => render(),
      setTitle: (text) => {
        document.title = text + " · " + S.product;
      },
      navCount: (id) => state.counts[id],
      connect,
      setNavCount: (id, count) => {
        if (!state.shell) {
          return;
        }
        state.counts[id] = count;
        refreshNav();
      },
      onCleanup: (cleanup) => state.cleanups.push(cleanup),
      announce: (text) => {
        state.shell.live.textContent = text;
      },
    };
    main.setAttribute("aria-busy", "true");
    if (!route.reportsPending && Date.now() - state.pendingAt > PENDING_MAX_AGE_MS && !document.hidden) {
      loadPending();
    }
    try {
      await route.view(ctx);
    } catch (error) {
      renderProblem(ctx, error, render);
    } finally {
      if (ctx.isCurrent()) {
        main.removeAttribute("aria-busy");
        main.focus({ preventScroll: true });
      }
    }
  }

  function onHashChange() {
    render();
  }

  function onLinkClick(event) {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return;
    }
    const link = event.target && typeof event.target.closest === "function" ? event.target.closest("a[href]") : null;
    if (link === null || (link.target && link.target !== "_self")) {
      return;
    }
    const href = link.getAttribute("href");
    if (href.startsWith("#/") && href === location.hash) {
      event.preventDefault();
      render();
    }
  }

  async function boot() {
    replace(root, el("p", { class: "boot", role: "status", text: S.loading }));
    let session;
    try {
      session = await api.session();
    } catch (error) {
      if (error.status === 401) {
        renderSignIn(root, {});
      } else {
        renderSignIn(root, { error: S.signIn.unreachable, onRetry: boot });
      }
      return;
    }
    state.session = session;
    state.wasSignedIn = true;
    buildShell();
    await render();
  }

  window.addEventListener("hashchange", onHashChange);
  root.addEventListener("click", onLinkClick);
  const booted = boot();

  return {
    ready: booted,
    stop() {
      state.active = false;
      window.removeEventListener("hashchange", onHashChange);
      root.removeEventListener("click", onLinkClick);
      runCleanups();
      if (state.shell) {
        state.shell.handle.destroy();
      }
    },
  };
}
