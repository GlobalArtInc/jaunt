# Configuration reference

Every file is YAML and strict: a key that is not listed here stops the program with an error naming the file. Durations are whole seconds, sizes are bytes. A value outside its range stops `jauntd` at start with a message that names the key.

`scripts/check-config-docs.sh` reads the field names of the configuration structs in the source and fails if one of them is missing from this file. It checks names only, not defaults.

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `JAUNT_CONFIG` | `jauntd` | path of `jauntd.yaml` (default `/etc/jaunt/jauntd.yaml`); same as `--config` |
| `RUST_LOG` | `jauntd`, `jaunt-agent` | log filter, for example `info` or `jaunt::agent=debug`. Default `info`. For the agent it wins over `log_level` in `agent.yaml` |
| `JAUNT_OIDC_CLIENT_SECRET` | `jauntd` | the OIDC client secret. Set it or `oidc.client_secret_file`, not both |
| `JAUNT_CA_KEY` | `jauntd` | the age identity that decrypts the CA keys (the secret text) |
| `JAUNT_CA_KEY_FILE` | `jauntd` | path of a file that holds that identity. Set `JAUNT_CA_KEY` or this one, not both. If neither is set, `jauntd` reads `<data_dir>/ca/age-identity.txt` |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | `jauntd` | S3 credentials when `recordings.s3.access_key_file` is not set. The session token is optional |
| `JAUNT_SERVER` | `jaunt` | server URL for `jaunt login` |
| `JAUNT_PROFILE` | `jaunt` | profile name, default `default` |
| `JAUNT_HOME` | `jaunt` | absolute path that replaces `~/.jaunt` |
| `USER` | `jauntd` | recorded as `cli:<user>` in the audit events of the `jauntd` commands |

## jauntd.yaml

Top-level keys:

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `data_dir` | path | required | holds `jaunt.db`, `ca/`, the default policy and staging directories. Should be mode 0700 and owned by the `jauntd` account; a mode that is open to others is logged as a warning |
| `listen` | address:port | `127.0.0.1:8443` | the plain HTTP listener of the console and the API. Put a TLS terminator in front of it |
| `agents_listen` | address:port or empty | `0.0.0.0:8444` | TLS 1.3 listener for agents (client certificates required). An empty string turns it off, which also rules out `ssh_gate` |
| `public_url` | URL | required | the `https` origin users type. No path, no trailing slash, no credentials. The OIDC redirect URI is this value plus `/v1/login/callback` |
| `cert_ttl_secs` | integer | 28800 | user certificate lifetime, 60 to 86400. Certificates start valid two minutes in the past |
| `device_login` | boolean | `true` | serves the device-code endpoints and the verification page. The `jaunt login --device` command does not exist yet |
| `web` | boolean | `true` | serves the console and `/v1/admin/*` |
| `client_ip_header` | string | none | name of an HTTP header (letters, digits, hyphens, up to 64) that carries the client address when `jauntd` sits behind a proxy. Needs `client_ip_trusted_proxies` |
| `client_ip_trusted_proxies` | list of CIDR | empty | networks whose `client_ip_header` is believed. Needs `client_ip_header`. A block that would trust the whole internet is refused |
| `ssh_suffix` | DNS name | required | node names are `<node>.<ssh_suffix>`. Lower-case labels. The `jaunt` CLI needs at least two labels |
| `agent_endpoint` | `host:port` | required | what agents connect to. `host` is a DNS name, not an IP address, because agents send it as the TLS server name. Its certificate is issued by the internal CA |
| `policy_dir` | path | `<data_dir>/policy` | directory of policy YAML files |
| `policy_poll_secs` | integer | 5 | how often the directory is checked, 1 to 3600 |
| `gate_endpoint` | `host[:port]` | none | the SSH gate address that clients learn from the server (port default 22). Required when `ssh_gate` is set. An IPv6 literal goes in square brackets, but not with `ssh_gate` |
| `ssh_gate` | map | none | the SSH gate. Without it no one can connect with `ssh` |
| `oidc` | map | required | the identity provider |
| `audit` | map | see below | where audit events go |
| `limits` | map | see below | rate and connection limits |
| `recordings` | map | see below | session recordings. Without `recordings.dir` (or `store: s3`) nothing is recorded |
| `web_terminal` | map | see below | the browser terminal |

### ssh_gate

| Key | Type | Default | Meaning |
|---|---|---|---|
| `listen` | address:port | required | the SSH listener. Must differ from `listen` and `agents_listen` |
| `hostnames` | list of DNS names | required | names clients use for the gate; 1 to 64, no repeats. The host of `gate_endpoint` must be one of them. The gate presents a host certificate for each |
| `proxy_protocol` | boolean | `false` | expect a PROXY protocol v2 header from a load balancer. Needs `trusted_proxies` |
| `trusted_proxies` | list of CIDR | empty | networks allowed to send that header. Needs `proxy_protocol: true` |
| `max_unauthenticated` | integer | 512 | connections that have not authenticated yet, all addresses together, 1 to 1048576 |
| `write_stall_secs` | integer | 900 | a client that accepts no data for this long is disconnected. 0 turns it off, at most 86400 |

### oidc

| Key | Type | Default | Meaning |
|---|---|---|---|
| `issuer_url` | URL | required | the provider. `jauntd` fetches its discovery document at start and does not start if that fails |
| `client_id` | string | required | |
| `client_secret_file` | path | none | file with the secret; trailing newlines are removed. The secret may instead come from `JAUNT_OIDC_CLIENT_SECRET`; exactly one source |
| `scopes` | list | `openid`, `email`, `profile`, `groups` | requested scopes |
| `username_claim` | string | `preferred_username` | the claim `{username}` in policy logins expands to |
| `groups_claim` | string | `groups` | the claim with the user's groups, matched against `members.groups` |
| `require_verified_email` | boolean | `true` | refuse users whose `email_verified` is not true |
| `extra_root_certificates_file` | path | none | PEM file of additional CA certificates to trust for the provider, for a provider with a private CA |

### audit

| Key | Type | Default | Meaning |
|---|---|---|---|
| `jsonl` | `stdout`, `off` or `{file: <path>}` | `stdout` | JSON lines, one event per line. `jauntd` writes to stdout; the human log goes to stderr |
| `database` | boolean | `true` | store events in `jaunt.db`. The console and `GET /v1/admin/audit` read from there |
| `queue` | integer | 1024 | events buffered before the writers; 1 to 1000000 |
| `retention_days` | integer or null | 365 with `database: true` | the daemon deletes stored events older than this once a day. `0` or `null` keeps everything. Range 1 to 36500; needs `database: true` |

At least one of `jsonl` and `database` must be on.

### limits

Every rate is a map `{burst: N, per_minute: M}`: a token bucket per client address (IPv6 addresses count per /64) that holds `burst` tokens and gains `M` per minute. `burst` is 1 to 1000000, `per_minute` 1 to 6000000. A refused request gets HTTP 429 with `Retry-After`.

The keys below sit in the sections `limits.http`, `limits.ssh` and `limits.agents`; `tracked_addresses` sits directly in `limits`.

| Key | Default | Applies to |
|---|---|---|
| `tracked_addresses` | 65536 | addresses remembered per limiter, 1 to 4194304 |
| `http.login_start` | burst 60, 30 per minute | `POST /v1/login/start` |
| `http.login_finish` | burst 60, 30 per minute | `POST /v1/login/finish` |
| `http.device_start` | burst 30, 10 per minute | `POST /v1/login/device/start` |
| `http.device_poll` | burst 60, 60 per minute | `POST /v1/login/device/poll` |
| `http.web_login` | burst 60, 30 per minute | `GET /v1/web/login` |
| `http.enroll` | burst 60, 6 per minute | `POST /v1/agent/enroll` |
| `http.enroll_poll` | burst 120, 120 per minute | `POST /v1/agent/enroll/poll` |
| `http.enrolment_lookup` | burst 30, 10 per minute | `POST /v1/admin/enrolments/lookup` (guessing approval codes) |
| `http.web_terminal` | burst 30, 30 per minute | `/v1/web/terminal` and its ticket |
| `http.other` | burst 600, 300 per minute | every other route |
| `http.max_connections` | 4096 | open HTTP connections, 1 to 1048576 |
| `http.max_connections_per_address` | 256 | open HTTP connections per address, 1 to 1048576 |
| `ssh.connections` | burst 600, 600 per minute | new SSH connections to the gate |
| `ssh.unauthenticated_per_address` | 128 | SSH connections per address that have not authenticated, 1 to 1048576 |
| `agents.handshakes` | burst 128, 1200 per minute | TLS handshakes on `agents_listen` |
| `agents.handshaking_per_address` | 64 | handshakes in progress per address, 1 to 1048576 |

### recordings

Recording is off unless `dir` is set (directory store) or `store: s3`. The sizes below bound memory and disk use; the defaults suit most installations.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `store` | `directory` or `s3` | `directory` | where finished recordings are kept |
| `dir` | absolute path | none | the directory store. Setting it turns recording on. Not allowed with `store: s3` |
| `staging_dir` | absolute path | `<data_dir>/recording-staging` | with `store: s3`: local files kept until the upload is stored |
| `s3` | map | none | required with `store: s3`, see below |
| `min_free_bytes` | integer | 1073741824 | the directory store refuses a recording when less is free |
| `max_uploads_per_node` | integer | 64 | recordings one node may upload at once; 1 to `max_uploads_total` |
| `max_uploads_total` | integer | 1024 | recordings uploaded at once, 1 to 65536 |
| `max_pending_bytes_per_node` | integer | 268435456 | received but not yet stored bytes per node; at most `max_pending_bytes_total` |
| `max_pending_bytes_total` | integer | 1073741824 | the same, for all nodes |
| `max_pending_bytes` | integer | 67108864 | the same, for one session; at most `max_pending_bytes_per_node` |
| `idle_timeout_secs` | integer | 7200 | a recording that receives nothing for this long is closed as incomplete; 60 to 86400 |
| `store_retry_secs` | integer | 300 | pause before storing is tried again after an error; 1 to 86400 |
| `max_store_commits` | integer | 8 | recordings committed to the store at the same time; 1 to 1024 |
| `max_wait_secs` | integer | 86400 | after this long a recording that cannot be stored stays on disk and the daemon stops retrying it; `store_retry_secs` to 2592000 |
| `max_chunk_compressed` | integer | 1048576 | largest compressed chunk, 1 to 16777216 |
| `max_chunk_raw` | integer | 8388608 | largest chunk after decompression, 1 to 67108864 |
| `max_chunks` | integer | 200000 | chunks per recording |
| `max_total_raw` | integer | 4294967296 | bytes per recording after decompression; a larger one is cut |
| `max_playback_bytes` | integer | 67108864 | largest recording the console plays; 1048576 to 536870912 |

`recordings.s3`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `endpoint` | URL | AWS | endpoint of an S3-compatible service. `https` unless `allow_insecure_http` |
| `region` | string | required | |
| `bucket` | string | required | |
| `prefix` | string | `recordings/` | key prefix, ends with `/`, up to 256 characters |
| `path_style` | boolean | `false` | path-style addressing, for MinIO and similar |
| `allow_insecure_http` | boolean | `false` | accept an `http` endpoint |
| `sse` | `none` or `aes256` | `none` | server-side encryption header |
| `conditional_put` | boolean | `true` | use `If-None-Match` so an object is never overwritten. Turn it off only for a service that rejects the header |
| `part_size` | integer | 8388608 | multipart part size, 5242880 to 134217728 |
| `upload_deadline_secs` | integer | 120 | time allowed for one request, 1 to 3600 |
| `access_key_file`, `secret_key_file` | path | none | files with the credentials; set both or neither. Without them the `AWS_*` variables are used |

### web_terminal

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | boolean | on when `web` and `ssh_gate` are set | `true` without both is an error |
| `max_per_user` | integer | 4 | open terminals per user, 1 to 64 |
| `max_total` | integer | 64 | open terminals in all, `max_per_user` to 4096 |
| `idle_timeout_secs` | integer | 1800 | a terminal with no input and no output for this long is closed; 60 to 86400 |
| `max_tickets` | integer | 1024 | unused one-time tickets held at once, 16 to 65536 |

## agent.yaml

The file is optional: without it every value has its default. `jaunt-agent install` writes `/etc/jaunt/agent.yaml`. The agent reads it with `jaunt-agent run --config`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `inner`, `recording` | maps | see below | the two sections that hold the keys that follow |
| `state_dir` | absolute path | `/var/lib/jaunt` | the enrolled identity: keys, certificates, `state.json`, `inner-ca.pub`. Mode 0700 |
| `log_level` | string | `info` | a log filter; `RUST_LOG` overrides it |
| `inner.sshd_addr` | address:port | `127.0.0.1:22` | where the local `sshd` listens. Must be a loopback address |
| `inner.sshd_host_key` | absolute path | `/etc/ssh/ssh_host_ed25519_key.pub` | the host key the agent pins for the local `sshd` |
| `recording.session_queue_bytes` | integer | 67108864 | recording data one session may hold in memory while the tunnel is down; 1 MiB to `memory_budget_bytes` |
| `recording.memory_budget_bytes` | integer | 268435456 | the same, for all sessions on the node; 1 MiB to 64 GiB |

Command-line flags:

| Command | Flags |
|---|---|
| `jaunt-agent enroll` | `--server <URL>` and `--name <NAME>` (required), `--labels k=v,...`, `--replace`, `--ca-pin sha256:<hex>`, `--state-dir <DIR>` (default `/var/lib/jaunt`), `--hostname <NAME>`, `--timeout-secs <N>` (default 900), `--token-file <PATH>` (enrol with a join token from this file, without an approval code; see [operations.md](operations.md#enrol-many-nodes-with-join-tokens)) |
| `jaunt-agent install` | `--user` (default `jaunt`), `--binary` (default `/usr/local/bin/jaunt-agent`), `--config`, `--state-dir`, `--root` (default `/`), `--no-service`, `--dry-run` |
| `jaunt-agent uninstall` | `--purge`, `--config`, `--state-dir`, `--root`, `--no-service`, `--dry-run` |
| `jaunt-agent run` | `--config <PATH>`, `--state-dir <DIR>` |

## The command-line client

`jaunt` has no configuration file. It keeps one directory per profile under `~/.jaunt` (or `$JAUNT_HOME`). A profile name is 1 to 32 characters of `a-z`, `0-9`, `_` and `-`, starting with a letter or digit.

| File in `~/.jaunt/<profile>/` | Contents |
|---|---|
| `server` | the server URL |
| `id_ed25519.pub`, `id_ed25519-cert.pub` | the public key and the certificate (mode 0600). The private key is in the ssh-agent; `id_ed25519` exists only when no ssh-agent is available |
| `token` | the API token for `jaunt ls` and `jaunt status --online` |
| `meta.json`, `client.json` | certificate serial and times; the server's SSH settings |
| `ssh_config`, `known_hosts` | generated: `ProxyJump` through the gate, `CertificateFile`, `IdentitiesOnly yes`, and one `@cert-authority` line per host CA key |

`jaunt login` adds `Include ~/.jaunt/*/ssh_config` to `~/.ssh/config` once and keeps a copy in `~/.ssh/config.jaunt-backup`.

| Command | Flags |
|---|---|
| `jaunt login` | `--server <URL>`, `--profile`, `--no-browser`, `--timeout <SECS>` (default 300, at most 900), `--no-ssh-config`, `--accept-ssh-config`, `--device` (not implemented) |
| `jaunt logout`, `jaunt status`, `jaunt ls`, `jaunt ensure` | `--profile`; `status --online`; `ls --format text\|json`; `ensure --quiet` |
| `jaunt policy check <DIR>` | `--format text\|json`. Loads the policy files and runs their `AccessTest` cases; exit code 0 when everything loads and every test passes, 1 when a test fails, 2 when the files do not load |
| `jaunt policy schema` | prints the JSON Schema of the policy documents |

`jaunt ensure` is what `ssh` runs through the generated `Match` line: exit 0 when a certificate with at least 60 seconds left is in place (it signs in again if needed), 1 when a sign-in is needed and cannot be done, 2 on a local error.

## Policy files

`policy_dir` holds any number of `*.yaml` and `*.yml` files (not names that start with a dot), each with one or more YAML documents separated by `---`. Limits: 1 MiB per file, 8 MiB in all, 512 files. The directory may be a Kubernetes ConfigMap mount: `jauntd` follows the `..data` link. `jauntd` loads the directory at start and again when it changes (every `policy_poll_secs`). An invalid set is not applied: the last valid set stays active and a `policy.reload` event with `applied: false` carries the first three errors. A reload that would replace a non-empty set with an empty one is refused the same way. The SHA-256 of the files is written to every decision in the audit trail as `policy_hash`.

Rules in one sentence each: a user's rights are the union of all roles that list them; there are no deny rules; no matching role means no access.

### Role

```yaml
apiVersion: jaunt/v1
kind: Role
metadata: { name: operators }
spec:
  members:
    users: [alice@example.com]
    groups: [infra-admins]
  ssh:
    nodes: { env: [staging, prod], team: ["*"] }
    logins: [deploy, "{username}"]
    portForwarding: false
    recordInput: false
  admin: [nodes.approve, sessions.read, recordings.read, revocations.write, audit.read]
```

| Key | Type | Meaning |
|---|---|---|
| `apiVersion` | string | must be `jaunt/v1` |
| `kind` | string | `Role` |
| `metadata` | map | holds `name` |
| `metadata.name` | string | non-empty, no control characters |
| `spec` | map | holds `members`, `ssh` and `admin` |
| `spec.members` | map | holds `users` and `groups` |
| `spec.members.users` | list | e-mail addresses, compared exactly with the `email` claim |
| `spec.members.groups` | list | group names, compared exactly with the `groups_claim` values. A user is a member if either list matches. A role without members applies to nobody |
| `spec.ssh` | map | SSH access. Omit it for an admin-only role |
| `spec.ssh.nodes` | map of label to list | required, not empty. A node matches when it has every listed label and its value is one of the listed values (`*` means any value). Labels are set when an administrator approves a node |
| `spec.ssh.logins` | list | required, not empty. Each entry is a login or the exact string `{username}`, which becomes the user's `username_claim` value. A login must start with a letter, digit or underscore, continue with letters, digits, `.`, `_` or `-`, and have at most 32 bytes. `{username}` that expands to `root` is ignored; a literal `root` is allowed |
| `spec.ssh.portForwarding` | boolean, default `false` | allow `ssh -L`. Other forwarding is never allowed |
| `spec.ssh.recordInput` | boolean, default `false` | also record what the user types |
| `spec.admin` | list | admin permissions, see the table below |

Note: the agent is stricter than the policy about logins. It accepts only `[a-z_][a-z0-9_.-]{0,31}`, so a role that lists `Deploy` or a user whose `{username}` has an upper-case letter is allowed by the server and refused by the node (`agent.ssh.auth outcome=denied reason=login`). Use lower-case logins.

There is no key for pseudo-terminals, session length or command filtering. A role cannot turn recording off. Every session may use a terminal and ends after at most 12 hours.

### Admin permissions

| Permission | Gates |
|---|---|
| `nodes.approve` | `GET /v1/admin/whoami`; `GET /v1/admin/nodes`, `GET`/`DELETE /v1/admin/nodes/{id}`; `POST /v1/admin/enrolments/lookup`, `/v1/admin/enrolments/{id}/approve` and `/reject` |
| `sessions.read` | `GET /v1/admin/sessions`, `GET /v1/admin/sessions/{id}`, `GET /v1/admin/nodes/{id}/access` (who may reach a node), `GET /v1/admin/revocations` |
| `recordings.read` | `GET /v1/admin/sessions/{id}/recording` and `/recording/manifest` |
| `revocations.write` | `POST /v1/admin/revocations`, `DELETE /v1/admin/revocations/{id}` |
| `audit.read` | `GET /v1/admin/audit`, `GET /v1/admin/ca` |

Opening a terminal needs no admin permission: the policy must allow the user to log in to the node (`/v1/web/terminal*`). The `jauntd` commands on the server need no permission; whoever can run them can read the database.

### AccessTest

```yaml
apiVersion: jaunt/v1
kind: AccessTest
spec:
  - user: alice@example.com
    groups: [infra-admins]
    username: alice
    node: { name: web-01, env: prod, team: platform }
    login: deploy
    expect: allow
```

| Key | Meaning |
|---|---|
| `user` | the e-mail address |
| `groups` | the user's groups, default empty |
| `username` | the `{username}` value; default is the part of `user` before `@` |
| `node` | the node's labels as strings. `name` is the node name and is not a label |
| `login` | the login to test |
| `expect` | `allow` or `deny` |

`jaunt policy check <dir>` runs them. Run it in CI before a policy change merges. `jauntd` itself does not run them.
