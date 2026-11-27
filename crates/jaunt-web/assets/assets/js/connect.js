import { S } from "./strings.js";

const TARGETS = "/v1/web/terminal/targets";
const CLIENT_CONFIG = "/v1/client-config";
const DNS_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const DNS_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){0,8}$/;
const LOGIN = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$/;
const MAX_LOGINS = 32;

export function isSafeLogin(value) {
  return typeof value === "string" && LOGIN.test(value);
}

function readTargets(body) {
  if (!Array.isArray(body)) {
    return null;
  }
  const targets = new Map();
  for (const entry of body) {
    if (!entry || typeof entry.node !== "string" || !Array.isArray(entry.logins)) {
      continue;
    }
    targets.set(entry.node, { logins: entry.logins.filter(isSafeLogin).slice(0, MAX_LOGINS), createsAccounts: entry.creates_accounts === true });
  }
  return targets;
}

export function createConnectInfo(api) {
  let pending = null;
  let targets = null;
  let suffix = null;
  let terminal = null;
  const listeners = new Set();

  async function fetchOne(path) {
    try {
      return await api.get(path);
    } catch (error) {
      if (error.status === 0) {
        pending = null;
      }
      if (path === TARGETS && error.status === 404) {
        terminal = false;
      }
      return null;
    }
  }

  async function fetchAll() {
    const [targetsBody, configBody] = await Promise.all([fetchOne(TARGETS), fetchOne(CLIENT_CONFIG)]);
    targets = readTargets(targetsBody);
    if (targets !== null) {
      terminal = true;
    }
    suffix = configBody && typeof configBody.ssh_suffix === "string" && DNS_NAME.test(configBody.ssh_suffix) ? configBody.ssh_suffix : null;
    for (const listener of listeners) {
      listener();
    }
  }

  return {
    reset() {
      pending = null;
      targets = null;
      suffix = null;
      terminal = null;
    },
    terminalEnabled: () => terminal,
    markTerminal(enabled) {
      terminal = enabled;
      for (const listener of listeners) {
        listener();
      }
    },
    onChange(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    load() {
      if (pending === null) {
        pending = fetchAll();
      }
      return pending;
    },
    hasTargets: () => targets !== null,
    loginsFor(node) {
      return targets && targets.has(node) ? targets.get(node).logins : null;
    },
    createsAccounts: (node) => Boolean(targets && targets.has(node) && targets.get(node).createsAccounts),
    command(node, login) {
      if (suffix === null || typeof node !== "string" || !DNS_LABEL.test(node)) {
        return null;
      }
      const user = login === undefined ? S.nodes.loginPlaceholder : login;
      if (login !== undefined && !isSafeLogin(login)) {
        return null;
      }
      return "ssh " + user + "@" + node + "." + suffix;
    },
  };
}
