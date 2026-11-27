import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createTerminalBackend } from "./terminal-stub.mjs";

const ASSETS = resolve(process.env.JAUNT_ASSETS || fileURLToPath(new URL("../../crates/jaunt-web/assets", import.meta.url)));
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".png": "image/png" };
const COOKIE = "jaunt_stub";

function now() {
  return Math.floor(Date.now() / 1000);
}

function seedNodes() {
  const t = now();
  const make = (index, name, labels, extra = {}) => ({
    id: "n-" + index,
    name,
    hostname: name + ".example.com",
    labels,
    state: "active",
    revoked: false,
    connected: true,
    connected_since: t - 3600 * (index + 1),
    agent_version: "0.4.2",
    certificates: { state: "delivered", x509_expires_at: t + 5 * 86400, ssh_host_expires_at: t + 4 * 86400 },
    approved_by: "alice@example.com",
    created_at: t - 30 * 86400,
    removed_at: null,
    tls_spki_sha256: "SHA256:q3Nf0ZyKc1v8xXK2mB9oA7tPq1Lw5eRZ0cYjH4uD2sE",
    ssh_host_key_fingerprint: "SHA256:Vd8kP2rL0tQx7mN4bWc9eYhJ3sAf6uGz1oKiR5nTqXw",
    ...extra,
  });
  return [
    make(1, "web-01", { env: "prod", team: "web" }),
    make(2, "web-02", { env: "prod", team: "web" }, { creates_accounts: true }),
    make(3, "db-01", { env: "prod", team: "data", tier: "primary" }),
    make(4, "db-replica-02", { env: "prod", team: "data" }, { connected: false, connected_since: null, certificates: { state: "delivered", x509_expires_at: t + 21 * 3600, ssh_host_expires_at: t + 21 * 3600 } }),
    make(5, "ci-runner-03", { env: "staging", team: "platform" }),
    make(6, "build-cache", { env: "dev", team: "platform" }, { connected: false, connected_since: null, revoked: true, certificates: { state: "delivered", x509_expires_at: t - 2 * 86400, ssh_host_expires_at: t - 2 * 86400 } }),
    make(7, "x".repeat(60) + "-very-long-node-name", { "a-very-long-label-key-for-testing": "value-" + "v".repeat(70) }, { hostname: "long-" + "h".repeat(70) + ".example.com" }),
    make(8, '<img src=x onerror="window.__pwned=1">', { '"><script>1</script>': "‮txt.exe" }),
    make(9, "queue-01", { env: "prod", team: "platform", service: "queue", region: "eu", tier: "gold" }),
    make(10, "cache-02", { env: "staging", team: "platform", service: "cache" }),
    make(11, "mail-01", { env: "prod", team: "comms" }, { connected: false, connected_since: null, certificates: { state: "pending" } }),
    make(12, "metrics-01", { env: "prod", team: "sre", service: "metrics", region: "us" }),
  ];
}

function seedSessions() {
  const t = now();
  const row = (index, state, extra = {}) => ({
    id: "5b1c0a4" + index + "-aaaa-bbbb-cccc-111122223333",
    state,
    user_id: "u-alice",
    user_email: "alice@example.com",
    node_id: "n-1",
    node_name: "web-01",
    login: "deploy",
    origin: index % 2 === 0 ? "ssh" : "web",
    created_at: t - 600 * (index + 1),
    authorized_at: t - 600 * (index + 1) + 1,
    ended_at: state === "ended" ? t - 300 * index : null,
    end_reason: state === "ended" ? "closed" : null,
    exit_status: state === "ended" ? 0 : null,
    bytes_in: 2048 * index,
    bytes_out: 1_500_000 * (index + 1),
    ...extra,
  });
  return [row(1, "active"), row(2, "active", { user_email: "bob@example.com", user_id: "u-bob", node_id: "n-3", node_name: "db-01" }), row(3, "ended"), row(4, "ended", { end_reason: "revoked", exit_status: null }), row(5, "routed")];
}

export async function startStub({ permissions }) {
  const state = {
    nodes: seedNodes(),
    sessions: seedSessions(),
    revocations: [{ id: "r-1", kind: "user", subject: "u-mallory", reason: "Left the company", created_at: now() - 86400, created_by: "web:u-alice" }],
    enrolments: new Map(),
    sessionsTokens: new Map(),
    lookupLimited: false,
    targets: null,
    recent: [],
    recordings: new Map(),
    recordingRequests: [],
    terminations: [],
    log: [],
  };
  const origin = { value: "" };
  const terminal = createTerminalBackend({ origin });

  function auditEvents() {
    const events = [];
    for (let index = 0; index < 5; index += 1) {
      const time = new Date((now() - 600 * index) * 1000).toISOString();
      events.push({ v: 1, id: "ev-" + index, type: index % 2 === 0 ? "admin.node.approved" : "login.succeeded", time, actor: "u-alice", node: index % 2 === 0 ? "n-1" : undefined, session_id: undefined, policy_hash: "3f9c2e1a", fields: { name: "web-0" + index, replaced: false, count: index } });
    }
    return events.map((event) => JSON.parse(JSON.stringify(event)));
  }

  async function body(request) {
    const chunks = [];
    for await (const chunk of request) {
      chunks.push(chunk);
    }
    const text = Buffer.concat(chunks).toString("utf8");
    return text === "" ? undefined : JSON.parse(text);
  }

  function send(response, status, payload, headers = {}) {
    const text = payload === undefined ? "" : JSON.stringify(payload);
    response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", ...headers });
    response.end(text);
  }

  function sessionOf(request) {
    const match = /(?:^|;\s*)jaunt_stub=([a-f0-9]+)/.exec(request.headers.cookie || "");
    return match ? state.sessionsTokens.get(match[1]) || null : null;
  }

  function page(items, url, key) {
    const limit = Math.min(Number(url.searchParams.get("limit") || 50), 200);
    const start = Number(url.searchParams.get("cursor") || url.searchParams.get("after") || 0);
    const slice = items.slice(start, start + limit);
    const next = start + limit < items.length ? String(start + limit) : null;
    return { [key]: slice, next };
  }

  async function api(request, response, url) {
    const path = url.pathname;
    const method = request.method;
    if (path === "/v1/web/login") {
      const token = randomBytes(16).toString("hex");
      state.sessionsTokens.set(token, { csrf: randomBytes(16).toString("hex") });
      response.writeHead(302, { Location: "/", "Set-Cookie": COOKIE + "=" + token + "; Path=/; HttpOnly; SameSite=Strict", "Content-Security-Policy": CSP });
      response.end();
      return;
    }
    if (path === "/v1/agent/enroll" && method === "POST") {
      const input = await body(request);
      const code = randomBytes(4).toString("hex").toUpperCase();
      const id = "e-" + (state.enrolments.size + 1);
      state.enrolments.set(code, { id, state: "pending", name: input.name, labels: input.labels || {}, hostname: input.hostname || "ip-10-0-3-17" });
      send(response, 200, { code });
      return;
    }
    if (path === "/v1/client-config" && method === "GET") {
      send(response, 200, { ssh_suffix: "jaunt.example.com", gate: { host: "gate.example.com", port: 22 }, host_ca_keys: [] });
      return;
    }
    let match;
    const current = sessionOf(request);
    if (!current) {
      send(response, 401, { error: "unauthorized" });
      return;
    }
    if (path === "/v1/web/session" && method === "GET") {
      send(response, 200, { user_id: "u-alice", email: "alice@example.com", display_name: null, groups: ["ops"], permissions, expires_at: now() + 28800, csrf_token: current.csrf });
      return;
    }
    if (method !== "GET") {
      const originHeader = request.headers.origin;
      if ((originHeader && originHeader !== origin.value) || request.headers["x-jaunt-csrf"] !== current.csrf) {
        send(response, 403, { error: "forbidden" });
        return;
      }
    }
    if (path === "/v1/web/terminal/targets" && method === "GET") {
      if (state.targets === null) return send(response, 404, { error: "not_found" });
      return send(response, 200, state.targets);
    }
    if (path === "/v1/web/terminal/limits" && method === "GET") {
      if (state.targets === null) return send(response, 404, { error: "not_found" });
      return send(response, 200, { max_per_user: terminal.control.maxPerUser, idle_timeout_secs: 1800 });
    }
    if (path === "/v1/web/terminal/recent" && method === "GET") {
      if (state.targets === null) return send(response, 404, { error: "not_found" });
      return send(response, 200, state.recent);
    }
    if ((match = /^\/v1\/web\/pins\/([^/]+)$/.exec(path)) && (method === "PUT" || method === "DELETE")) {
      const entry = (state.targets || []).find((target) => target.node === decodeURIComponent(match[1]));
      if (!entry) return send(response, 404, { error: "not_found" });
      if (method === "PUT" && !entry.pinned && state.targets.filter((target) => target.pinned).length >= 50) return send(response, 409, { error: "too_many_pins" });
      entry.pinned = method === "PUT";
      return send(response, 204, undefined);
    }
    if (path === "/v1/web/terminal/ticket" && method === "POST") {
      const reply = terminal.issue(current, await body(request), state.targets);
      return send(response, reply.status, reply.body);
    }
    if (path === "/v1/web/logout" && method === "POST") {
      send(response, 204, undefined);
      return;
    }
    const need = (permission) => {
      if (!permissions.includes(permission)) {
        send(response, 403, { error: "forbidden" });
        return false;
      }
      return true;
    };
    if (path === "/v1/admin/nodes" && method === "GET") {
      if (!need("nodes.approve")) return;
      const wanted = url.searchParams.get("state") || "active";
      const prefix = url.searchParams.get("q") || "";
      const labels = url.searchParams.getAll("label").map((entry) => entry.split(":"));
      const items = state.nodes.filter((node) => node.state === wanted && node.name.startsWith(prefix) && labels.every(([key, value]) => node.labels[key] === value));
      const pending = [...state.enrolments.values()].filter((entry) => entry.state === "pending").length;
      send(response, 200, { ...page(items, url, "nodes"), pending_enrolments: pending });
      return;
    }
    if ((match = /^\/v1\/admin\/nodes\/([^/]+)(\/access)?$/.exec(path))) {
      if (!need(match[2] ? "sessions.read" : "nodes.approve")) return;
      const node = state.nodes.find((entry) => entry.id === decodeURIComponent(match[1]));
      if (!node) return send(response, 404, { error: "not_found" });
      if (match[2]) {
        return send(response, 200, { node_id: node.id, node_name: node.name, labels: node.labels, policy_hash: "3f9c2e1a", policy_loaded_at: now() - 600, roles: [{ role: "prod-ops", users: ["alice@example.com"], groups: ["infra-admins"], logins: ["deploy"], port_forwarding: false, record_input: false, admin: ["sessions.read"] }] });
      }
      if (method === "GET") {
        return send(response, 200, { ...node, sessions: { open: 2, last_24h: 7 } });
      }
      if (method === "DELETE") {
        const input = await body(request);
        if (input.confirm_name !== node.name) return send(response, 422, { error: "confirm_name_mismatch" });
        if (node.state !== "active") return send(response, 409, { error: "node_not_active" });
        node.state = "removed";
        node.removed_at = now();
        return send(response, 200, { id: node.id, name: node.name, state: "removed", removed_at: node.removed_at, sessions_closed: 2 });
      }
    }
    if (path === "/v1/admin/enrolments/lookup" && method === "POST") {
      if (!need("nodes.approve")) return;
      const input = await body(request);
      if (state.lookupLimited) {
        return send(response, 429, { error: "too_many_requests", retry_after: 30 }, { "Retry-After": "30" });
      }
      const code = String(input.code || "").replace(/-/g, "").toUpperCase();
      const entry = state.enrolments.get(code);
      if (!entry) return send(response, 422, { error: "no_pending_enrolment" });
      if (entry.state !== "pending") return send(response, 409, { error: "already_approved" });
      const t = now();
      send(response, 200, {
        enrolment: { id: entry.id, name: entry.name, labels: entry.labels, hostname: entry.hostname, peer_addr: "203.0.113.24:40022", source_network: "203.0.113.0/24", agent_version: "0.4.2", requested_at: t - 120, expires_at: t + 780, tls_key_sha256: "SHA256:q3Nf0ZyKc1v8xXK2mB9oA7tPq1Lw5eRZ0cYjH4uD2sE", ssh_host_key_fingerprint: "SHA256:Vd8kP2rL0tQx7mN4bWc9eYhJ3sAf6uGz1oKiR5nTqXw", replace_existing: state.nodes.some((node) => node.name === entry.name && node.state === "active") },
        intent: "intent-" + entry.id,
        intent_expires_at: t + 300,
      });
      return;
    }
    if ((match = /^\/v1\/admin\/enrolments\/([^/]+)\/(approve|reject)$/.exec(path)) && method === "POST") {
      if (!need("nodes.approve")) return;
      const input = await body(request);
      const entry = [...state.enrolments.values()].find((candidate) => candidate.id === match[1]);
      if (!entry || input.intent !== "intent-" + entry.id) return send(response, 422, { error: "invalid_intent" });
      if (entry.state !== "pending") return send(response, 409, { error: "already_approved" });
      if (match[2] === "reject") {
        entry.state = "rejected";
        return send(response, 200, { enrolment_id: entry.id, name: entry.name });
      }
      entry.state = "approved";
      const node = { ...seedNodes()[0], id: "n-new-" + entry.id, name: entry.name, labels: input.labels || {} };
      state.nodes.push(node);
      return send(response, 200, { enrolment_id: entry.id, node: { id: node.id, name: node.name }, labels: node.labels, replaced: null });
    }
    if ((match = /^\/v1\/admin\/sessions\/([^/]+)\/recording(\/manifest)?$/.exec(path)) && method === "GET") {
      if (!need("recordings.read")) return;
      const stored = state.recordings.get(decodeURIComponent(match[1]));
      state.recordingRequests.push({ path, query: url.search, session: decodeURIComponent(match[1]) });
      if (!stored) return send(response, 404, { error: "not_found" });
      if (match[2]) return send(response, 200, stored.manifest);
      if (!stored.cast) return send(response, 404, { error: "not_found" });
      if (!url.searchParams.has("download") && stored.manifest.raw_bytes > stored.manifest.playback_limit_bytes) return send(response, 413, { error: "recording_too_large" });
      const headers = { "Content-Type": "application/x-asciicast; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; sandbox", "X-Content-Type-Options": "nosniff" };
      if (url.searchParams.get("download") === "1") headers["Content-Disposition"] = 'attachment; filename="' + match[1] + '.cast"';
      response.writeHead(200, headers);
      response.end(stored.cast);
      return;
    }
    if (path === "/v1/admin/sessions" && method === "GET") {
      if (!need("sessions.read")) return;
      const wanted = url.searchParams.get("state");
      const origin = url.searchParams.get("origin");
      if (origin !== null && origin !== "web" && origin !== "ssh") return send(response, 400, { error: "invalid_origin" });
      const items = state.sessions.filter((entry) => (!wanted || entry.state === wanted) && (!origin || entry.origin === origin));
      return send(response, 200, page(items, url, "sessions"));
    }
    if ((match = /^\/v1\/admin\/sessions\/([^/]+)\/terminate$/.exec(path)) && method === "POST") {
      if (!need("sessions.terminate")) return;
      const input = await body(request);
      const keys = input === undefined ? [] : Object.keys(input);
      const reasonOk = (value) => typeof value === "string" && Array.from(value).length <= 200 && !/[\u0000-\u001f\u007f-\u009f]/.test(value) && !/\b(bearer|basic)\s+\S+|\b(password|passwd|secret|token|api[_-]?key)\s*[:=]/i.test(value);
      if (keys.some((key) => key !== "reason") || (input && input.reason !== undefined && !reasonOk(input.reason))) return send(response, 422, { error: "invalid_reason" });
      const entry = state.sessions.find((candidate) => candidate.id === decodeURIComponent(match[1]));
      if (!entry) return send(response, 404, { error: "not_found" });
      if (entry.state === "ended") return send(response, 409, { error: "already_ended" });
      entry.state = "ended";
      entry.ended_at = now();
      entry.end_reason = "terminated";
      state.terminations.push({ id: entry.id, reason: input && input.reason !== undefined ? input.reason : null });
      return send(response, 204, undefined);
    }
    if ((match = /^\/v1\/admin\/sessions\/([^/]+)$/.exec(path)) && method === "GET") {
      if (!need("sessions.read")) return;
      const entry = state.sessions.find((candidate) => candidate.id === decodeURIComponent(match[1]));
      if (!entry) return send(response, 404, { error: "not_found" });
      const stored = state.recordings.get(entry.id);
      return send(response, 200, { ...entry, recording: stored ? stored.manifest.state : "none", serial: "4242", expires_at: now() + 120, max_duration_secs: 3600, client_addr: "203.0.113.9:51022" });
    }
    if (path === "/v1/admin/revocations") {
      if (method === "GET") {
        if (!need("sessions.read")) return;
        return send(response, 200, page(state.revocations, url, "revocations"));
      }
      if (method === "POST") {
        if (!need("revocations.write")) return;
        const input = await body(request);
        if (input.subject === "u-nobody") return send(response, 404, { error: "unknown_subject" });
        const revocation = { id: "r-" + (state.revocations.length + 1), kind: input.kind, subject: input.subject, reason: input.reason, created_at: now(), created_by: "web:u-alice" };
        state.revocations.unshift(revocation);
        return send(response, 201, { revocation, created: true, terminated_sessions: 2 });
      }
    }
    if ((match = /^\/v1\/admin\/revocations\/([^/]+)$/.exec(path)) && method === "DELETE") {
      if (!need("revocations.write")) return;
      const index = state.revocations.findIndex((entry) => entry.id === match[1]);
      if (index < 0) return send(response, 404, { error: "not_found" });
      state.revocations.splice(index, 1);
      return send(response, 204, undefined);
    }
    if (path === "/v1/admin/audit" && method === "GET") {
      if (!need("audit.read")) return;
      return send(response, 200, { events: auditEvents(), next_cursor: null });
    }
    send(response, 404, { error: "not_found" });
  }

  async function serveStatic(response, url) {
    const requested = url.pathname === "/favicon.ico" ? "assets/brand/favicon.ico" : url.pathname.startsWith("/assets/") ? url.pathname.slice(1) : "index.html";
    const file = normalize(join(ASSETS, requested));
    if (!file.startsWith(ASSETS + "/") && file !== ASSETS) {
      response.writeHead(404);
      response.end();
      return;
    }
    const headers = { "Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "Cache-Control": requested === "index.html" ? "no-cache" : "public, max-age=3600" };
    try {
      const bytes = await readFile(file);
      response.writeHead(200, { ...headers, "Content-Type": TYPES[extname(file)] || "application/octet-stream" });
      response.end(bytes);
    } catch {
      response.writeHead(404, headers);
      response.end();
    }
  }

  const server = createServer((request, response) => {
    const url = new URL(request.url, origin.value);
    const handler = url.pathname.startsWith("/v1/") ? api(request, response, url) : serveStatic(response, url);
    handler.catch((error) => {
      state.log.push(String(error && error.stack));
      if (!response.headersSent) {
        response.writeHead(500);
      }
      response.end();
    });
  });
  server.on("upgrade", (request, socket) => terminal.upgrade(request, socket, sessionOf));
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  origin.value = "http://127.0.0.1:" + server.address().port;
  return {
    origin: origin.value,
    state,
    terminal: terminal.control,
    async enrol(name, labels) {
      const reply = await fetch(origin.value + "/v1/agent/enroll", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, labels }) });
      return (await reply.json()).code;
    },
    expireSessions: () => state.sessionsTokens.clear(),
    setRecording(id, manifest, cast) {
      state.recordings.set(id, { manifest, cast });
    },
    setTargets(targets) {
      state.targets = targets;
    },
    setRecent(recent) {
      state.recent = recent;
    },
    setNodes(nodes) {
      state.nodes = nodes;
    },
    limitLookups(limited) {
      state.lookupLimited = limited;
    },
    close: () => new Promise((done) => server.close(done)),
  };
}
