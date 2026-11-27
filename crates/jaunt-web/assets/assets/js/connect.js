import { encodeSegment } from "./dom.js";
import { S } from "./strings.js";

const TARGETS = "/v1/web/terminal/targets";
const RECENT = "/v1/web/terminal/recent";
const LIMITS = "/v1/web/terminal/limits";
const CLIENT_CONFIG = "/v1/client-config";
const PINS = "/v1/web/pins/";
const DNS_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const DNS_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){0,8}$/;
const LOGIN = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$/;
const MAX_LOGINS = 32;
const MAX_TARGETS = 2000;
const MAX_LABELS = 32;
const MAX_HIDDEN = 8;
const MAX_HIDDEN_CHARS = 64;
const MAX_RECENT = 5;
const MAX_LIMIT = 1000;
const MAX_IDLE_SECS = 7 * 86400;

export function isSafeLogin(value) {
  return typeof value === "string" && LOGIN.test(value);
}

function readLabels(value) {
  const labels = {};
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [key, item] of Object.entries(value).slice(0, MAX_LABELS)) {
      if (typeof item === "string") {
        labels[key] = item;
      }
    }
  }
  return labels;
}

function readHidden(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((item) => typeof item === "string" && item !== "" && item.length <= MAX_HIDDEN_CHARS)
    .slice(0, MAX_HIDDEN);
}

export function readTargets(body) {
  if (!Array.isArray(body)) {
    return null;
  }
  const seen = new Set();
  const targets = [];
  for (const entry of body.slice(0, MAX_TARGETS)) {
    if (!entry || typeof entry.node !== "string" || entry.node === "" || seen.has(entry.node) || !Array.isArray(entry.logins)) {
      continue;
    }
    seen.add(entry.node);
    targets.push({
      node: entry.node,
      labels: readLabels(entry.labels),
      connected: entry.connected === true,
      logins: entry.logins.filter(isSafeLogin).slice(0, MAX_LOGINS),
      hiddenLogins: readHidden(entry.hidden_logins),
      pinned: entry.pinned === true,
      createsAccounts: entry.creates_accounts === true,
    });
  }
  return targets;
}

export function readRecent(body) {
  if (!Array.isArray(body)) {
    return [];
  }
  const seen = new Set();
  const pairs = [];
  for (const entry of body) {
    if (!entry || typeof entry.node !== "string" || entry.node === "" || !isSafeLogin(entry.login) || typeof entry.last_at !== "number" || !Number.isFinite(entry.last_at)) {
      continue;
    }
    const key = entry.node + "\u0000" + entry.login;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    pairs.push({ node: entry.node, login: entry.login, lastAt: entry.last_at });
    if (pairs.length >= MAX_RECENT) {
      break;
    }
  }
  return pairs;
}

function readLimit(value) {
  return Number.isInteger(value) && value >= 1 && value <= MAX_LIMIT ? value : null;
}

function readSeconds(value) {
  return Number.isInteger(value) && value >= 1 && value <= MAX_IDLE_SECS ? value : null;
}

export function readTerminalConfig(body) {
  const block = body && typeof body === "object" && !Array.isArray(body) ? body : null;
  return {
    maxPerUser: block ? readLimit(block.max_per_user) : null,
    idleTimeoutSecs: block ? readSeconds(block.idle_timeout_secs) : null,
  };
}

export function createConnectInfo(api) {
  let pending = null;
  let targets = null;
  let byNode = new Map();
  let recent = [];
  let suffix = null;
  let terminal = null;
  let config = { maxPerUser: null, idleTimeoutSecs: null };
  let targetsStatus = null;
  const listeners = new Set();

  function notify() {
    for (const listener of listeners) {
      listener();
    }
  }

  async function fetchOne(path) {
    try {
      return { body: await api.get(path), status: null };
    } catch (error) {
      const status = error && typeof error.status === "number" ? error.status : -1;
      if (status === 0) {
        pending = null;
      }
      if (path === TARGETS && status === 404) {
        terminal = false;
      }
      return { body: null, status };
    }
  }

  async function fetchAll() {
    const [targetsReply, configReply, recentReply, limitsReply] = await Promise.all([fetchOne(TARGETS), fetchOne(CLIENT_CONFIG), fetchOne(RECENT), fetchOne(LIMITS)]);
    targets = readTargets(targetsReply.body);
    byNode = new Map((targets || []).map((target) => [target.node, target]));
    targetsStatus = targets === null ? (targetsReply.status === null ? 500 : targetsReply.status) : null;
    if (targets !== null) {
      terminal = true;
    }
    recent = readRecent(recentReply.body);
    const configBody = configReply.body;
    suffix = configBody && typeof configBody.ssh_suffix === "string" && DNS_NAME.test(configBody.ssh_suffix) ? configBody.ssh_suffix : null;
    config = readTerminalConfig(limitsReply.body);
    notify();
  }

  return {
    reset() {
      pending = null;
      targets = null;
      byNode = new Map();
      recent = [];
      suffix = null;
      terminal = null;
      config = { maxPerUser: null, idleTimeoutSecs: null };
      targetsStatus = null;
    },
    terminalEnabled: () => terminal,
    markTerminal(enabled) {
      terminal = enabled;
      notify();
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
    refresh() {
      pending = fetchAll();
      return pending;
    },
    targetsError: () => targetsStatus,
    hasTargets: () => targets !== null,
    targets: () => (targets === null ? [] : targets),
    target: (node) => byNode.get(node) || null,
    loginsFor: (node) => (byNode.has(node) ? byNode.get(node).logins : null),
    hiddenLoginsFor: (node) => (byNode.has(node) ? byNode.get(node).hiddenLogins : []),
    createsAccounts: (node) => Boolean(byNode.has(node) && byNode.get(node).createsAccounts),
    isPinned: (node) => Boolean(byNode.has(node) && byNode.get(node).pinned),
    canPin: (node) => byNode.has(node),
    recent: () => recent.filter((pair) => byNode.has(pair.node) && byNode.get(pair.node).logins.includes(pair.login)),
    lastUsed(node) {
      const used = new Map();
      for (const pair of recent) {
        if (pair.node === node && !used.has(pair.login)) {
          used.set(pair.login, pair.lastAt);
        }
      }
      return used;
    },
    terminalConfig: () => config,
    async setPinned(node, pinned) {
      if (!byNode.has(node)) {
        return;
      }
      const path = PINS + encodeSegment(node);
      if (pinned) {
        await api.put(path);
      } else {
        await api.del(path);
      }
      const current = byNode.get(node);
      if (current) {
        current.pinned = pinned;
      }
      notify();
    },
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
