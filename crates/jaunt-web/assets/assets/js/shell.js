import { el, replace } from "./dom.js";
import { clean } from "./format.js";
import { icon, svg } from "./icons.js";
import { menuButton } from "./menu.js";
import { ADD_NEW, hasPermission, visibleAreas } from "./nav.js";
import { S } from "./strings.js";
import { currentTheme, setTheme } from "./theme.js";

const DRAWER_MAX_WIDTH = 900;
const COLLAPSE_KEY = "jaunt-nav-collapsed";
const FOCUSABLE = 'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])';

function readCollapsed() {
  try {
    return localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
}

function writeCollapsed(value) {
  try {
    if (value) {
      localStorage.setItem(COLLAPSE_KEY, "1");
    } else {
      localStorage.removeItem(COLLAPSE_KEY);
    }
  } catch {
    return;
  }
}

const MARK_SHAPES = [
  ["rect", { x: 0.75, y: 0.75, width: 62.5, height: 62.5, rx: 14.5, fill: "#17143F", stroke: "#4A4590", "stroke-width": 1.5 }],
  ["path", { d: "M19 49V31a13 13 0 0 1 26 0v18", fill: "none", stroke: "#FFFFFF", "stroke-width": 6.5, "stroke-linecap": "round", "stroke-linejoin": "round" }],
  ["circle", { cx: 32, cy: 33, r: 5.5, fill: "#B7A4FF" }],
];

function brandMark() {
  const root = svg("svg", { viewBox: "0 0 64 64", class: "brand-mark", "aria-hidden": "true", focusable: "false" });
  for (const [tag, attributes] of MARK_SHAPES) {
    root.appendChild(svg(tag, attributes));
  }
  return root;
}

export function wordmark() {
  return el("span", { class: "wordmark" }, brandMark(), el("span", { class: "wordmark-text", text: S.product }));
}

function initialOf(name) {
  const first = Array.from(String(name || "").trim())[0];
  return first ? first.toUpperCase() : "?";
}

export function createShell({ root, onSignOut }) {
  let drawerOpen = false;
  let collapsed = readCollapsed();
  let model = { session: null, current: { area: null, page: null }, counts: {}, terminal: null };

  const main = el("main", { id: "main", tabindex: "-1" });
  const live = el("div", { class: "visually-hidden", role: "status", "aria-live": "polite" });
  const skip = el("button", { type: "button", class: "skip", on: { click: () => main.focus({ preventScroll: true }) } }, S.skip);

  const hamburger = el(
    "button",
    { type: "button", class: "icon-btn hamburger", "aria-label": S.shell.openNav, "aria-expanded": "false", "aria-controls": "sidebar" },
    icon("menu"),
  );
  const brand = el("a", { class: "brand", href: "#/", "aria-label": S.shell.home }, wordmark());
  const bellSlot = el("div", { class: "bell-slot" });
  const accountSlot = el("div", { class: "account-slot" });
  const topbar = el(
    "header",
    { class: "topbar" },
    hamburger,
    brand,
    el("span", { class: "spacer" }),
    bellSlot,
    accountSlot,
  );

  const railList = el("ul", { class: "rail-list", "aria-label": S.shell.areas });
  const railFoot = el("ul", { class: "rail-list rail-foot" });
  const rail = el("div", { class: "rail" }, el("div", { class: "rail-inner" }, railList, el("hr", { class: "rail-rule" }), railFoot));

  const subTitle = el("h2", { class: "subnav-title" });
  const collapseButton = el("button", { type: "button", class: "icon-btn collapse-btn", "aria-expanded": "true", "aria-controls": "subnav-body" });
  const closeButton = el("button", { type: "button", class: "icon-btn drawer-close", "aria-label": S.shell.closeNav }, icon("close"));
  const subList = el("ul", { class: "subnav-list" });
  const subBody = el("div", { class: "subnav-body", id: "subnav-body" }, subList);
  const subFoot = el(
    "p",
    { class: "subnav-foot" },
    el("span", { class: "subnav-foot-label", text: S.shell.server }),
    el("span", { class: "mono", text: location.host }),
  );
  const subnav = el("div", { class: "subnav" }, el("div", { class: "subnav-inner" }, el("div", { class: "subnav-head" }, subTitle, collapseButton, closeButton), subBody, subFoot));

  const sidebar = el("nav", { class: "sidebar", id: "sidebar", "aria-label": S.navLabel }, rail, subnav);
  const scrim = el("div", { class: "drawer-scrim", hidden: true });
  const frame = el("div", { class: "frame" }, sidebar, scrim, main);
  const app = el("div", { class: "app" }, skip, topbar, frame, live);
  replace(root, app);

  function paintCollapse() {
    app.classList.toggle("nav-collapsed", collapsed);
    collapseButton.setAttribute("aria-expanded", collapsed ? "false" : "true");
    collapseButton.setAttribute("aria-label", collapsed ? S.shell.expandNav : S.shell.collapseNav);
    replace(collapseButton, icon(collapsed ? "chevronRight" : "collapse"));
  }

  collapseButton.addEventListener("click", () => {
    collapsed = !collapsed;
    writeCollapsed(collapsed);
    paintCollapse();
  });

  function setDrawer(open, { restoreFocus = true } = {}) {
    if (drawerOpen === open) {
      return;
    }
    drawerOpen = open;
    app.classList.toggle("drawer-open", open);
    scrim.hidden = !open;
    hamburger.setAttribute("aria-expanded", open ? "true" : "false");
    for (const region of [topbar, main]) {
      if (open) {
        region.setAttribute("inert", "");
      } else {
        region.removeAttribute("inert");
      }
    }
    if (open) {
      const target = sidebar.querySelector("[aria-current]") || sidebar.querySelector(FOCUSABLE);
      if (target) {
        target.focus();
      }
    } else if (restoreFocus) {
      hamburger.focus();
    }
  }

  hamburger.addEventListener("click", () => setDrawer(!drawerOpen));
  closeButton.addEventListener("click", () => setDrawer(false));
  scrim.addEventListener("click", () => setDrawer(false));
  sidebar.addEventListener("click", (event) => {
    if (drawerOpen && event.target.closest && event.target.closest("a[href]")) {
      setDrawer(false, { restoreFocus: false });
    }
  });
  sidebar.addEventListener("keydown", (event) => {
    if (!drawerOpen) {
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      setDrawer(false);
      return;
    }
    if (event.key !== "Tab") {
      return;
    }
    const items = Array.from(sidebar.querySelectorAll(FOCUSABLE)).filter((node) => node !== collapseButton);
    if (items.length === 0) {
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && active === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  });

  function railItem(entry, active) {
    return el(
      "li",
      {},
      el("a", { class: "rail-item", href: entry.href, "aria-current": active ? "page" : null }, icon(entry.icon), el("span", { class: "rail-label", text: entry.label })),
    );
  }

  function paintBell() {
    const session = model.session;
    if (!hasPermission(session, "nodes.approve")) {
      replace(bellSlot);
      return;
    }
    const count = Number.isInteger(model.counts.nodes) ? model.counts.nodes : 0;
    replace(
      bellSlot,
      el(
        "a",
        { class: "icon-btn bell", href: "#/approve", "aria-label": S.shell.notifications(count) },
        icon("bell"),
        count > 0 ? el("span", { class: "bell-count", "aria-hidden": "true", text: count > 99 ? "99+" : String(count) }) : null,
      ),
    );
  }

  function paintAccount() {
    const session = model.session;
    const name = clean((session && (session.display_name || session.email)) || "");
    const themes = ["auto", "light", "dark"];
    const account = menuButton({
      className: "account-btn",
      align: "end",
      content: [el("span", { class: "avatar", "aria-hidden": "true", text: initialOf(name) }), el("span", { class: "account-name", text: name }), icon("chevronDown", { size: "sm" })],
      items: () => [
        { type: "heading", text: S.shell.signedInAs + " " + name },
        { type: "separator" },
        { type: "heading", text: S.shell.themeHeading },
        ...themes.map((theme) => ({
          text: S.shell.themes[theme],
          role: "menuitemradio",
          checked: currentTheme() === theme,
          onSelect: () => setTheme(theme),
        })),
        { type: "separator" },
        { text: S.signOut, icon: "logout", onSelect: () => onSignOut() },
      ],
    });
    replace(accountSlot, account.element);
  }

  function paintNav() {
    const { session, current, counts } = model;
    const entries = visibleAreas(session, { terminal: model.terminal });
    replace(
      railList,
      entries.map(({ area, pages }) => railItem({ href: pages[0].href, icon: area.icon, label: area.label }, area.id === current.area)),
    );
    replace(railFoot, hasPermission(session, ADD_NEW.permission) ? railItem(ADD_NEW, false) : null);
    const active = entries.find(({ area }) => area.id === current.area) || null;
    subnav.hidden = active === null;
    if (active === null) {
      app.classList.add("nav-single");
      return;
    }
    app.classList.remove("nav-single");
    subTitle.textContent = active.area.label;
    replace(
      subList,
      active.pages.map((page) => {
        const count = page.count ? counts[page.count] : 0;
        return el(
          "li",
          {},
          el(
            "a",
            { class: "subnav-item", href: page.href, "aria-current": page.id === current.page ? "page" : null },
            icon(page.icon, { size: "sm" }),
            el("span", { class: "subnav-label", text: page.label }),
            count > 0 ? el("span", { class: "nav-count", text: String(count) }) : null,
          ),
        );
      }),
    );
  }

  function heldFocus() {
    const active = document.activeElement;
    for (const region of [sidebar, topbar]) {
      if (active && active !== document.body && region.contains(active) && active.hasAttribute("href")) {
        return { region, tag: active.localName, className: active.getAttribute("class"), href: active.getAttribute("href") };
      }
    }
    return null;
  }

  function restoreFocus(held) {
    if (!held || (document.activeElement && document.activeElement !== document.body && held.region.contains(document.activeElement))) {
      return;
    }
    const again = Array.from(held.region.querySelectorAll(held.tag)).find((node) => node.getAttribute("class") === held.className && node.getAttribute("href") === held.href);
    if (again) {
      again.focus({ preventScroll: true });
    }
  }

  function onResize() {
    if (drawerOpen && window.innerWidth > DRAWER_MAX_WIDTH) {
      setDrawer(false, { restoreFocus: false });
    }
  }

  window.addEventListener("resize", onResize);
  paintCollapse();

  return {
    main,
    live,
    update(next) {
      const held = heldFocus();
      const accountChanged = !model.session || !next.session || (model.session.email !== next.session.email || model.session.display_name !== next.session.display_name);
      model = next;
      paintNav();
      paintBell();
      if (accountChanged || accountSlot.childElementCount === 0) {
        paintAccount();
      }
      restoreFocus(held);
    },
    destroy: () => window.removeEventListener("resize", onResize),
    closeDrawer: () => setDrawer(false, { restoreFocus: false }),
    isDrawerOpen: () => drawerOpen,
    isCollapsed: () => collapsed,
  };
}
