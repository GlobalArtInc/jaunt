# Architecture

Jaunt has three programs. `jauntd` runs on one host and holds the control role (sign-in, certificate authorities, policy, database, console) and the gate role (the SSH entry point) in one process. `jaunt-agent` runs on every node and connects outward. `jaunt` is the command-line client on a laptop. Users keep using OpenSSH.

```text
                       +-------------------- jauntd (one process) --------------------+
  laptop               |                                                              |        node
 +-----------+  HTTPS  |  console and API  <--- plain HTTP, TLS terminated in front --+        +------------------+
 | jaunt CLI |-------->|  control: OIDC login, CAs, policy, authorise, revocations,   |        |  jaunt-agent     |
 +-----------+         |           audit, recordings, SQLite                          |<-mTLS--|  (outbound only) |
 | browser   |  HTTPS  |                                                              | :8444  |                  |
 |  console  |-------->|  web terminal: SSH client of the server                      |        |  terminates SSH, |
 |  terminal |   WS    |                                                              |        |  asks control,   |
 +-----------+         |  gate: SSH listener :2222, only forwards to <node>.<suffix>  |        |  records the     |
 | ssh,scp,  |   SSH   |        stream <==> tunnel stream of that node's agent        |        |  session         |
 | rsync     |========>|                                                              |        +--------+---------+
 +-----------+         +--------------------------------------------------------------+                 | loopback
        |                                       end-to-end SSH session                                 v
        +==========================================================================================> sshd :22
```

## A sign-in

1. `jaunt login` makes an Ed25519 key in memory and opens the browser at the server. The server is the OpenID Connect client of your identity provider (authorisation code with PKCE); the CLI never sees the provider's tokens.
2. The provider redirects to `<public_url>/v1/login/callback`. The server checks the ID token, reads e-mail, username and groups, and stores the user. A one-time completion code goes only to the CLI's loopback address, so a login cannot be finished by someone else.
3. The CLI sends its public key and the PKCE verifier and the code. The server signs an SSH user certificate (principal: the user's id; key id `jaunt:<email>:<serial>`; valid for `cert_ttl_secs` from two minutes ago) and returns it with an API token.
4. The CLI loads the key into the ssh-agent for the certificate's lifetime and writes the certificate, `known_hosts` (host CA keys) and `ssh_config` under `~/.jaunt/<profile>/`. The console login is the same flow with a `__Host-jaunt` cookie instead of a certificate.

## An SSH session

1. `ssh deploy@web-01.nodes.example.com` follows the generated `ProxyJump`: the client connects to the gate on the SSH port as user `jaunt` with the certificate. The gate checks the certificate against the user CA keys, then the revocations.
2. The client asks the gate to forward to `web-01.nodes.example.com:22`. The gate asks control to route: user, node and the policy decide. Control writes `session.routed`.
3. The gate opens a stream through the tunnel that the node's agent keeps open and pipes bytes. The gate sees only encrypted SSH.
4. Through that stream the client runs its own SSH session with the agent, which presents a host certificate signed by the host CA (so `known_hosts` trusts the node) and checks the user certificate again.
5. The agent calls control to authorise (user, serial, login, session id). Control checks the revocations and the policy and answers with the permissions (forwarding, input recording). It writes `session.start`.
6. The agent signs a 60 second inner certificate for the login and logs in to the local `sshd` on loopback, which trusts only that inner CA. It bridges the channels (shell, command, SFTP, `-L`), records a shell with a terminal and uploads the recording while the session runs.
7. At the end the agent reports the exit status and sizes (`session.end`).

## The web terminal

The browser asks control for a one-time ticket (`POST /v1/web/terminal/ticket`) and opens a WebSocket. Control creates an in-process connection to the gate, with an ephemeral key, certified for 120 seconds as the user, and runs the SSH session of steps 3 to 7 over it. The agent records and audits it exactly as for the CLI. Details and close codes: [operations.md](operations.md#web-terminal).

## Enrolling a node

`jaunt-agent enroll` makes a TLS key and an SSH host key on the node, sends a request and prints an 8-character code with both fingerprints. An administrator types the code in the console or `jauntd node approve`, checks the fingerprints and may change the labels. The server then issues a 7 day client certificate (internal CA) and a host certificate (host CA) for the keys in the request; the agent receives them by polling. Certificates renew at half their life through the agent connection.

## Data stores

| Store | Where | Holds |
|---|---|---|
| SQLite | `<data_dir>/jaunt.db` | users, issued certificates, nodes, enrolments, sessions, web sessions, API tokens, revocations, audit events, recording index |
| CA directory | `<data_dir>/ca/` | the user, host and internal keys, each age-encrypted, and the trust sets |
| Policy | `policy_dir` | role and test files, read-only to the daemon |
| Recordings | a directory or an S3 bucket | casts and manifests |
| Node | `/var/lib/jaunt` on each node | TLS key, SSH host key, certificates, `inner-ca.pub` |
| Laptop | `~/.jaunt/<profile>/` | certificate, public key, token, generated SSH settings |

## Code layout

| Crate | Role |
|---|---|
| `jaunt-proto` | wire types shared by all programs |
| `jaunt-ca` | signing, certificate profiles, trust sets, rotation (control only) |
| `jaunt-policy` | policy files and decisions |
| `jaunt-store` | SQLite access and migrations |
| `jaunt-oidc` | the OpenID Connect client |
| `jaunt-record`, `jaunt-audit`, `jaunt-recording-s3` | recording format and stores, audit events |
| `jaunt-tunnel`, `jaunt-ssh` | the agent tunnel (TLS 1.3, HTTP/2 over the agent's own connection) and the SSH hops |
| `jaunt-control`, `jaunt-gate` | the two roles |
| `jauntd`, `jaunt-agent`, `jaunt` | the programs |

`scripts/check-boundaries.sh` keeps `jaunt-gate` from depending on `jaunt-ca` and `jaunt-store`, and the agent and the CLI from depending on the signing, database and control crates. This is a boundary between crates, not between processes: in v1 the gate runs inside `jauntd` next to the control role, so code execution in the gate's listener reaches the keys in the process memory. A separate gate process is not implemented ([security.md](security.md)).

## Roadmap

Planned areas, in no order and without dates: Kubernetes access, database access (PostgreSQL first), TCP forwarding, local users with WebAuthn and TOTP, per-session MFA, live session viewing and joining, access requests, machine identities for CI, web applications, MCP servers and high availability. Nothing in this list exists in the code today.
