import { createApi } from "./api.js";
import { el, replace } from "./dom.js";
import { closeRouteDialogs, openDialog } from "./dialog.js";
import { renderForbidden, renderNotFound, renderProblem } from "./errors.js";
import { S } from "./strings.js";
import { cycleTheme, themeLabel } from "./theme.js";
import { button } from "./ui.js";
import { auditView } from "./views/audit.js";
import { approveView } from "./views/approve.js";
import { nodeView, nodesView } from "./views/nodes.js";
import { revocationsView } from "./views/revocations.js";
import { renderSignIn, loginHref } from "./views/signin.js";
import { sessionView, sessionsView } from "./views/sessions.js";

const NAV = [
  { id: "nodes", href: "#/nodes", label: S.nav.nodes, permission: "nodes.approve" },
  { id: "sessions", href: "#/sessions", label: S.nav.sessions, permission: "sessions.read" },
  { id: "audit", href: "#/audit", label: S.nav.audit, permission: "audit.read" },
  { id: "revocations", href: "#/revocations", label: S.nav.revocations, permission: "sessions.read" },
];

const ROUTES = [
  { pattern: /^\/nodes$/, view: nodesView, permission: "nodes.approve", nav: "nodes", title: S.titles.nodes },
  { pattern: /^\/nodes\/([^/]+)$/, view: nodeView, permission: "nodes.approve", nav: "nodes", title: S.titles.nodes },
  { pattern: /^\/approve$/, view: approveView, permission: "nodes.approve", nav: "nodes", title: S.titles.approve },
  { pattern: /^\/sessions$/, view: sessionsView, permission: "sessions.read", nav: "sessions", title: S.titles.sessions },
  { pattern: /^\/sessions\/([^/]+)$/, view: sessionView, permission: "sessions.read", nav: "sessions", title: S.titles.sessions },
  { pattern: /^\/revocations$/, view: revocationsView, permission: "sessions.read", nav: "revocations", title: S.titles.revocations },
  { pattern: /^\/audit$/, view: auditView, permission: "audit.read", nav: "audit", title: S.titles.audit },
];

export function hasPermission(session, permission) {
  return Boolean(session && Array.isArray(session.permissions) && session.permissions.includes(permission));
}

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
  const state = { session: null, wasSignedIn: false, token: 0, cleanups: [], expiredDialog: null, shell: null, active: true };

  const api = createApi({
    onUnauthorized: () => showExpired(),
    onSession: (session) => {
      state.session = session;
      refreshNav();
    },
  });

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

  function buildShell() {
    const who = el("span", { class: "who" }, S.signedInAs + " ", el("strong", { text: state.session.display_name || state.session.email || "" }));
    const theme = button(themeLabel(), {
      small: true,
      onClick: () => {
        cycleTheme();
        theme.textContent = themeLabel();
      },
    });
    theme.classList.add("theme-toggle");
    const signOut = button(S.signOut, { small: true, onClick: signOutNow });
    const main = el("main", { id: "main", tabindex: "-1" });
    const list = el("ul", {});
    const skip = el("button", { type: "button", class: "skip", on: { click: () => main.focus() } }, S.skip);
    const live = el("div", { class: "visually-hidden", role: "status", "aria-live": "polite" });
    const app = el(
      "div",
      { class: "app" },
      skip,
      el(
        "header",
        { class: "topbar" },
        el(
          "div",
          { class: "wrap" },
          el("a", { class: "brand", href: "#/" }, el("span", { class: "brand-mark", "aria-hidden": "true", text: "J" }), S.product),
          el("span", { class: "server", text: location.host }),
          el("span", { class: "spacer" }),
          who,
          theme,
          signOut,
        ),
      ),
      el("nav", { class: "mainnav", "aria-label": S.navLabel }, el("div", { class: "wrap" }, list)),
      main,
      live,
    );
    replace(root, app);
    state.shell = { main, list, live, counts: {}, current: null };
    refreshNav();
  }

  function refreshNav() {
    if (!state.shell) {
      return;
    }
    const { list, counts, current } = state.shell;
    const items = NAV.filter((item) => hasPermission(state.session, item.permission));
    const children = [];
    if (items.length > 0) {
      children.push(el("li", { class: "nav-group", "aria-hidden": "true", text: S.navGroupAdmin }));
    }
    for (const item of items) {
      const link = el("a", { href: item.href, "aria-current": item.id === current ? "page" : null }, el("span", { text: item.label }));
      if (counts[item.id] > 0) {
        link.appendChild(el("span", { class: "nav-count", text: S.pendingCount(counts[item.id]) }));
      }
      children.push(el("li", {}, link));
    }
    replace(list, ...children);
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
    state.shell = null;
    renderSignIn(root, { notice: S.signIn.signedOut });
  }

  function firstAllowed() {
    const item = NAV.find((candidate) => hasPermission(state.session, candidate.permission));
    return item ? item.href.slice(1) : null;
  }

  async function render() {
    if (!state.active || !state.shell) {
      return;
    }
    runCleanups();
    closeRouteDialogs();
    state.token += 1;
    const mine = state.token;
    const { main } = state.shell;
    const { path, query } = parseHash();
    if (path === "/") {
      const target = firstAllowed();
      if (target) {
        go(target, null, { replace: true });
        return;
      }
      state.shell.current = null;
      refreshNav();
      document.title = S.titles.notAllowed + " · " + S.product;
      renderForbidden(main, { session: state.session, permission: null, path: null });
      return;
    }
    const matched = matchRoute(path);
    main.replaceChildren();
    if (!matched) {
      state.shell.current = null;
      refreshNav();
      document.title = S.titles.notFound + " · " + S.product;
      renderNotFound(main);
      main.focus();
      return;
    }
    const { route, params } = matched;
    state.shell.current = route.nav;
    refreshNav();
    document.title = route.title + " · " + S.product;
    if (!hasPermission(state.session, route.permission)) {
      document.title = S.titles.notAllowed + " · " + S.product;
      renderForbidden(main, { session: state.session, permission: route.permission, path: "#" + path });
      main.focus();
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
      navCount: (id) => (state.shell ? state.shell.counts[id] : undefined),
      setNavCount: (id, count) => {
        if (!state.shell) {
          return;
        }
        state.shell.counts[id] = count;
        refreshNav();
      },
      onCleanup: (cleanup) => state.cleanups.push(cleanup),
      announce: (text) => {
        state.shell.live.textContent = text;
      },
    };
    main.setAttribute("aria-busy", "true");
    try {
      await route.view(ctx);
    } catch (error) {
      renderProblem(ctx, error, render);
    } finally {
      if (ctx.isCurrent()) {
        main.removeAttribute("aria-busy");
        main.focus();
      }
    }
  }

  function onHashChange() {
    render();
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
  const booted = boot();

  return {
    ready: booted,
    stop() {
      state.active = false;
      window.removeEventListener("hashchange", onHashChange);
      runCleanups();
    },
  };
}
