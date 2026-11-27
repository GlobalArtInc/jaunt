import { afterEach, beforeEach } from "node:test";

import { click, json, mount, settle, signedIn, until } from "./support.mjs";
import { TICKET, installTerminalHooks } from "./terminal-support.mjs";

export const HOOKS = "../../crates/jaunt-web/assets/assets/js/terminal/hooks.js";
export const TICKET_ROUTE = "POST /v1/web/terminal/ticket";
export const TARGETS_ROUTE = "GET /v1/web/terminal/targets";
export const RECENT_ROUTE = "GET /v1/web/terminal/recent";
export const CONFIG_ROUTE = "GET /v1/client-config";
export const GRANT = json(200, { ticket: TICKET, expires_in: 30 });
export const LIMITS_ROUTE = "GET /v1/web/terminal/limits";
export const CONFIG = { ssh_suffix: "jaunt.example.com" };
export const LIMITS = { max_per_user: 4, idle_timeout_secs: 1800 };
export const FLEET = [
  { node: "web-01", labels: { env: "prod", team: "web" }, connected: true, pinned: false, logins: ["deploy", "alice"], hidden_logins: ["Alice.M"] },
  { node: "db-01", labels: { env: "prod" }, connected: true, pinned: true, logins: ["postgres"], hidden_logins: [] },
  { node: "web-02", labels: { env: "staging" }, connected: true, pinned: false, creates_accounts: true, logins: ["deploy"] },
  { node: "db-replica-02", labels: {}, connected: false, pinned: false, logins: ["deploy"] },
];

export function baseRoutes(extra = {}, permissions = []) {
  return {
    ...signedIn(permissions),
    [TARGETS_ROUTE]: json(200, FLEET),
    [RECENT_ROUTE]: json(200, []),
    [CONFIG_ROUTE]: json(200, CONFIG),
    [LIMITS_ROUTE]: json(200, LIMITS),
    [TICKET_ROUTE]: GRANT,
    ...extra,
  };
}

export function useRig() {
  const env = { ui: null, rig: null };
  beforeEach(async () => {
    const { terminalHooks } = await import(HOOKS);
    env.rig = installTerminalHooks(terminalHooks);
  });
  afterEach(() => {
    if (env.ui) {
      env.ui.stop();
      env.ui = null;
    }
    env.rig.restore();
  });
  env.mount = async (extra = {}, hash = "#/terminal", permissions = [], options = {}) => {
    env.ui = await mount(baseRoutes(extra, permissions), hash, options);
    return env.ui;
  };
  env.chooseAndOpen = async (node, login) => {
    if (window.location.hash !== "#/terminal") {
      window.location.hash = "#/terminal";
      await settle();
    }
    const root = env.ui.root;
    let scope = root.querySelector(".panel.quick");
    if (!scope) {
      click(Array.from(root.querySelectorAll(".tabbar button")).find((item) => item.textContent.trim() === "New terminal"));
      scope = document.querySelector(".modal.quick");
    }
    const rowOf = () => Array.from(scope.querySelectorAll(".quick-row")).find((item) => item.querySelector(".name").textContent === node);
    const toggle = Array.from(rowOf().querySelectorAll("button")).find((item) => item.textContent === "Choose login");
    if (toggle) {
      click(toggle);
    }
    const radio = Array.from(rowOf().querySelectorAll('input[name="quick-login"]')).find((input) => input.value === login);
    radio.checked = true;
    radio.dispatchEvent(new window.Event("change", { bubbles: true }));
    click(scope.querySelector("footer .btn-primary"));
  };
  env.openTab = async (node, login) => {
    const before = env.rig.sockets.length;
    await env.chooseAndOpen(node, login);
    await until(() => env.rig.sockets.length === before + 1, "the socket of " + login + "@" + node);
    await settle();
    return env.rig.sockets.at(-1);
  };
  env.ready = async (socket, fields = {}) => {
    socket.accept();
    socket.control({ t: "ready", session_id: "s-" + env.rig.sockets.indexOf(socket), ...fields });
    await settle();
  };
  return env;
}

export const tabLabels = (root) => Array.from(root.querySelectorAll('[role="tab"] .lbl')).map((label) => label.textContent);
export const activeTab = (root) => root.querySelector('[role="tab"][aria-selected="true"] .lbl').textContent;
export const pane = (root) => Array.from(root.querySelectorAll(".term-pane")).find((item) => !item.hidden);
export const bannerOf = (root) => pane(root).querySelector(".term-banner").textContent;
export const stateOf = (root) => pane(root).querySelector(".statusbar [role=status]").textContent;
