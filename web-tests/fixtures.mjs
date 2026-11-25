export const NOW = Math.floor(Date.now() / 1000);

export const HOSTILE = {
  tag: '<img src=x onerror="window.__pwned=1">',
  quote: '"><script>window.__pwned=1</script>',
  rtl: "evil‮gpj.exe‬",
  control: "bell\u0007null\u0000esc\u001b[31m",
  long: "A".repeat(100_000),
  link: "javascript:alert(1)",
};

export function session(permissions, extra = {}) {
  return {
    user_id: "u-alice",
    email: "alice@example.com",
    display_name: null,
    groups: ["ops"],
    permissions,
    expires_at: NOW + 28_800,
    csrf_token: "csrf-token-one",
    ...extra,
  };
}

export const ALL = ["nodes.approve", "sessions.read", "recordings.read", "revocations.write", "audit.read"];

export function node(overrides = {}) {
  return {
    id: "n-web-01",
    name: "web-01",
    hostname: "web-01.example.com",
    labels: { env: "prod", team: "web" },
    state: "active",
    revoked: false,
    connected: true,
    connected_since: NOW - 3600,
    agent_version: "0.4.2",
    certificates: { state: "delivered", x509_expires_at: NOW + 5 * 86400, ssh_host_expires_at: NOW + 4 * 86400 },
    approved_by: "alice@example.com",
    created_at: NOW - 30 * 86400,
    removed_at: null,
    ...overrides,
  };
}

export function nodeDetail(overrides = {}) {
  return {
    ...node(),
    tls_spki_sha256: "SHA256:q3Nf0ZyKc1v8xXK2mB9oA7tPq1Lw5eRZ0cYjH4uD2sE",
    ssh_host_key_fingerprint: "SHA256:Vd8kP2rL0tQx7mN4bWc9eYhJ3sAf6uGz1oKiR5nTqXw",
    sessions: { open: 2, last_24h: 7 },
    ...overrides,
  };
}

export function access() {
  return {
    node_id: "n-web-01",
    node_name: "web-01",
    labels: { env: "prod" },
    policy_hash: "3f9c2e1a",
    policy_loaded_at: NOW - 600,
    roles: [
      { role: "prod-ops", users: ["alice@example.com"], groups: ["infra-admins"], logins: ["deploy"], port_forwarding: false, record_input: false, admin: ["sessions.read"] },
    ],
  };
}

export function sessionRow(overrides = {}) {
  return {
    id: "5b1c0a42-aaaa-bbbb-cccc-111122223333",
    state: "active",
    user_id: "u-alice",
    user_email: "alice@example.com",
    node_id: "n-web-01",
    node_name: "web-01",
    login: "deploy",
    created_at: NOW - 600,
    authorized_at: NOW - 599,
    ended_at: null,
    end_reason: null,
    exit_status: null,
    bytes_in: 2048,
    bytes_out: 1_500_000,
    ...overrides,
  };
}

export function sessionDetail(overrides = {}) {
  return { ...sessionRow(), serial: "4242", expires_at: NOW + 120, max_duration_secs: 3600, client_addr: "203.0.113.9:51022", ...overrides };
}

export function revocation(overrides = {}) {
  return { id: "r-1", kind: "user", subject: "u-mallory", reason: "Left the company", created_at: NOW - 86400, created_by: "web:u-alice", ...overrides };
}

export function auditEvent(overrides = {}) {
  return {
    v: 1,
    id: "ev-1",
    type: "admin.node.approved",
    time: "2026-11-24T10:15:30.123Z",
    actor: "u-alice",
    node: "n-web-01",
    session_id: "5b1c0a42",
    policy_hash: "3f9c2e1a",
    fields: { name: "web-01", replaced: false, labels_count: 2 },
    ...overrides,
  };
}

export function lookup(overrides = {}) {
  return {
    enrolment: {
      id: "e-1",
      name: "web-03",
      labels: { env: "prod", team: "web" },
      hostname: "ip-10-0-3-17",
      peer_addr: "203.0.113.24:40022",
      source_network: "203.0.113.0/24",
      agent_version: "0.4.2",
      requested_at: NOW - 120,
      expires_at: NOW + 780,
      tls_key_sha256: "SHA256:q3Nf0ZyKc1v8xXK2mB9oA7tPq1Lw5eRZ0cYjH4uD2sE",
      ssh_host_key_fingerprint: "SHA256:Vd8kP2rL0tQx7mN4bWc9eYhJ3sAf6uGz1oKiR5nTqXw",
      replace_existing: false,
      ...overrides,
    },
    intent: "intent-opaque-1",
    intent_expires_at: NOW + 300,
  };
}
