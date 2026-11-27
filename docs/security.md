# Security

This page states what Jaunt protects, what it trusts and what happens when a part is compromised. To report a vulnerability see [SECURITY.md](../SECURITY.md).

## Trust model

```text
 laptop            control host (jauntd: control + gate)            node
 ssh client  ---->  gate  ===== SSH, end to end ===============>  agent -> sshd (loopback)
 jaunt CLI   ---->  control: OIDC, CAs, policy, database          agent (mTLS, outbound)
 browser     ---->  console, web terminal
```

| Who | Trusts | Because |
|---|---|---|
| the laptop | the server's TLS certificate (public web PKI); the host CA key it receives at sign-in, written to `known_hosts` as `@cert-authority` | the CLI refuses a private CA; the host CA key arrives over the verified TLS connection |
| the SSH gate | user certificates signed by the user CA keys it receives from control; its own host certificate from the host CA | the gate crate has no CA private key and no database code of its own. The build checks this: `scripts/check-boundaries.sh` fails if `jaunt-gate` depends on `jaunt-ca` or `jaunt-store` (and the agent and the CLI on the crates in their rows of that script). In v1 the gate runs inside the `jauntd` process, so this is a boundary between crates, not between processes |
| the control host | the identity provider (the user's identity and groups at sign-in); agents by a client certificate it issued; the policy files | an agent is admitted only after an administrator types the code shown on the node |
| the agent | the server by the pinned internal CA root (`--ca-pin`); the user CA keys it fetches from the server over that mTLS channel; the local `sshd` by its pinned host key | the pin is checked at enrolment and the root is stored; the agent does not accept another root later |
| the node's `sshd` | only the node's own internal CA, and only for connections from loopback | the installer adds `Match Address 127.0.0.1,::1` with `TrustedUserCAKeys`, and checks the effective configuration with `sshd -T -C` |

**Certificates carry identity, not rights.** A user certificate names the user and a serial. Rights come from the policy at every connection: the gate asks control to route, then the agent asks control to authorise. A role change, a revocation or a removed node acts at the next connection without a new certificate.

**End-to-end SSH.** The SSH session of a laptop is terminated by the agent on the node, not by the gate. The gate forwards bytes it cannot read (an outer SSH hop authenticates the user and routes to `<node>.<suffix>`; the inner hop to the agent is the user's own SSH session). The end-to-end property holds on the wire: someone who only observes or alters the gate's network traffic cannot read or alter session contents. **The gate is not a separate process in v1.** The boundary between the gate and the signing code is a boundary between crates, not between processes: `jaunt-gate` has no dependency on `jaunt-ca` or `jaunt-store` (`scripts/check-boundaries.sh` allows it to depend on `jaunt-control`), but it runs inside `jauntd` next to the control role. A remote code execution bug in the gate's SSH listener would give the attacker the memory of the whole process, including the decrypted CA keys, and so the ability to issue certificates and to impersonate nodes. A gate that runs as its own process is not implemented. Treat the SSH port as part of the control host's attack surface.

The agent then logs in to the local `sshd` with an **inner certificate** that lives 60 seconds, names the login and the session id and is signed by an Ed25519 key that exists only in the agent's memory.

**mTLS.** Agents connect outward to the agent port with TLS 1.3 and a client certificate (7 days, renewed at half its life, issued by the internal CA, naming the node). Every call an agent makes is checked against the node in its certificate: an agent can ask only about its own node and sessions.

## What a compromise gives

| Compromised | Can | Cannot |
|---|---|---|
| a laptop (key and certificate stolen) | connect to what the user may reach until the certificate expires (8 hours by default) or an administrator revokes the user or the serial | reach nodes outside the user's roles; extend the certificate |
| the identity provider | sign in as any user it can issue claims for, including admin roles that match | |
| a node (root on it) | act as any local user of that node; forge or withhold the recordings of its own sessions; mint inner certificates for its own `sshd` | get user certificates; reach other nodes; authorise a session of another node |
| the agent process only (unprivileged account) | log in to the local `sshd` as any user, because it brokers every login. This is inherent in the design. Where account creation is on: ask the root helper for new accounts, see [below](#account-creation-and-the-root-helper) | read the CA keys; change or delete an account |
| the gate as a network peer (traffic only) | see who connects and to which node; refuse service | read or alter CLI session contents; sign certificates |
| the gate code in `jauntd` (a bug that runs attacker code in the process) | everything the control host can do, see the next row | |
| the control host (`jauntd`) | everything: it holds the CA keys, decrypts them in memory and issues certificates; read recordings and the database | |
| a browser session (cookie stolen) | act with that user's console rights | sign in from another site without the cookie (it is `__Host-`, `HttpOnly`, `SameSite=Strict`) |
| a stolen backup | with the age identity: issue certificates; without it: read the database and recordings | read the CA keys |

**Web terminal.** The browser terminal is an SSH client run by the server. The server sees the terminal bytes in clear text; the end-to-end property holds for `ssh` from a laptop only. The terminal uses a certificate that the server signs for the user for 120 seconds. A browser open on the console can open a terminal wherever the policy allows; use short sessions (the cookie lasts 8 hours) for sensitive nodes.

**Join tokens.** A join token ([operations.md](operations.md#enrol-many-nodes-with-join-tokens)) is a bearer credential: a host that holds it joins without a person approving the request or comparing fingerprints. The server stores only its SHA-256 hash and shows it once. What limits a leak is the scope pinned in the token, because policy gives access by node name and labels: an exact name or a name prefix, the labels the node gets (the agent cannot ask for others), a use count and a lifetime of at most 7 days. Replacing a running node needs the token's `--allow-replace` as well as the agent's `--replace`. Every refusal looks the same to the agent and carries a reason in the audit event `join_token.refused`.

**Group membership** is read at sign-in. Removing a user from a group at the identity provider takes effect at the next sign-in (at most one certificate lifetime) or at once if you revoke the user.

## Account creation and the root helper

When the operator turns on account creation ([operations.md](operations.md#account-creation-at-first-login)), one small program runs as root: `jaunt-host-users`. It is a separate binary on purpose. The agent keeps all the code that parses network input (TLS, HTTP/2, SSH, recordings) and stays the unprivileged user `jaunt`; the helper has no network, TLS or SSH code (`scripts/check-boundaries.sh` limits its dependencies) and runs under a systemd sandbox. Neither `sudo` nor capabilities for the agent were used, because they would weaken the agent unit or make it root in effect.

**Who can talk to it.** systemd starts one helper process for each connection to `/run/jaunt/host-users.sock` (mode 0660, owner `root`, group `jaunt`, at most 4 connections at once). The helper reads the user id of the peer from the kernel (`SO_PEERCRED`) and answers only the uid of the agent user that the unit names; any other peer gets no answer and a line `connection=rejected peer_uid=...` in the journal. The path of the configuration and the name of the agent user come from the unit file, not from the request. One process serves one request and exits; nothing lives in its memory between requests.

**What the request holds.** One line of JSON up to 1 KiB, read within 5 seconds: `login`, a reference `H-...` and a session id. The last two go to the journal and decide nothing. The agent cannot send a uid, a group, a shell, a home directory, a password, a skeleton directory, a path or an option.

**What the helper decides.** It reads `/etc/jaunt/agent.yaml` again for every request and checks the section itself. The file, `/etc/jaunt` and `/etc` must belong to root and be closed to writes by group and others, and the file must not be a link; otherwise the answer is `disabled`. Then, in this order: the node takes users from a network directory (`disabled`, unless `allow_with_directory`); the account exists (`exists`); the name rules of the node; the reserved names; a group with that name exists; the home directory exists; `max_users` is reached; more than 5 attempts in a minute or 50 in a day. Only then does it create the account.

**How it creates it.** `useradd` by absolute path (`/usr/sbin/useradd` or `/sbin/useradd`, never through `PATH`), with a fixed list of arguments, without a shell, with a cleared environment and `LC_ALL=C`, standard input `/dev/null`, no inherited descriptors, a timeout of 5 seconds that kills the whole process group. The tool and every directory above it must belong to root and be closed to writes by group and others. The uid is chosen by `useradd` inside `uid_min` to `uid_max` and checked afterwards, as are the home directory (a real directory of the new owner), the shell and the group. The password field is `*`. If a step fails, the helper removes what it made itself and nothing else.

**What it never does.** There is no operation to change or delete an account, a group or a home directory, so an attacker with the agent cannot touch an existing one. A login that equals an existing user or group, a reserved name (system users and groups, `systemd-*`, `_*`, common service names, the privileged groups) or a name the operator denied is refused. Privileged groups (`root`, `sudo`, `wheel`, `adm`, `admin`, `docker`, `lxd`, `libvirt`, `disk`, `shadow`) are refused in `groups` and can be given only through the separate key `privileged_groups`, which the operator writes on purpose. The product never deletes an account on its own (the only `userdel` is the rollback of a creation that failed halfway).

| Who | Can | Cannot |
|---|---|---|
| the agent (the process and the files of `jaunt`) | ask for any login that passes the node's rules, up to `max_users` accounts and 5 a minute and 50 a day; learn the uid and home of what it created; use up the quota, so that legitimate first logins are refused until an operator deletes accounts | change or delete an account; choose uid, groups, shell, home, password or skeleton; create an existing, reserved or denied name; turn creation on or change the rules (the file belongs to root); change the program or its arguments; talk to the helper as another user |
| the control plane | allow any login to any user on a node where creation is on, and the account then appears within that node's rules | turn creation on; widen groups, range or limits; create an account on a node where it is off; change or delete one |
| another local user | nothing | open the socket |
| root of the node | everything it could already do | |

The agent can already log in to `sshd` as any account of the node, and as root where `PermitRootLogin` allows certificates, so the rules of the helper are defence in depth and a ceiling on the one new kind of trace: permanent accounts. Two consequences are worth planning for. A user whose identity provider lets them choose their own username can reach any name that the node permits, so on shared nodes use `names.allow_prefixes` or literal logins in roles to keep them away from service names that are not in the built-in list (a package installed later would then adopt the existing account). And `sshd` still has the last word: `AllowUsers`, `AllowGroups`, `DenyUsers`, PAM and `access.conf` apply to created accounts as to any other.

**Network directories.** If `/etc/nsswitch.conf` takes users from `ldap`, `nis`, `winbind`, or from `sss` while `/etc/sssd/sssd.conf` exists, creation is off. When the directory is down `getent` says "no such user", and the helper would create a local copy that shadows the directory user. `allow_with_directory: true` removes the guard; use it only if you accept that risk. Under the helper's unit `sss_cache` cannot write to `/var/lib/sss` (see the operations page).

**Records.** Every attempt has a reference. An attempt that reaches the helper has it in the agent log, the helper journal (`journalctl -t jaunt-host-users`, the only place with the tool's error output) and the control audit. A refusal by the node rules that the agent checks itself (name rule, reserved name) never reaches the helper and has no helper journal line, and a login that finds no account while creation is off has an agent log line but no `host_user.*` audit event. The helper keeps its own record of the accounts it made in `/var/lib/jaunt-host-users` (root, mode 0700) and marks an account as its own only while the record and the account agree on the uid.

## What is logged and recorded

- Audit events for every sign-in, certificate, routing decision, session start and end, denial, node enrolment, revocation, CA change, policy reload and recording access ([operations.md](operations.md#audit)). Each decision carries the SHA-256 of the policy files in force.
- Recordings of terminal output, and of input when a role says `recordInput: true` ([operations.md](operations.md#recordings)). Input recordings contain whatever the user typed, including passwords typed where echo is off.
- Error messages and logs never contain secrets, tokens, key material or whole certificates; `Debug` output of secret-holding types is redacted. The audit schema has no field for the e-mail address.

## Secrets

| Secret | Where | Notes |
|---|---|---|
| CA private keys | `<data_dir>/ca/*/*.age`, encrypted with age; decrypted in `jauntd`'s memory | three independent keys: user, host, internal |
| age identity | `JAUNT_CA_KEY_FILE` (or `JAUNT_CA_KEY`), or `ca/age-identity.txt` if you let `ca init --generate-identity` write it | **keep it away from the data directory in production**: with both files an attacker issues certificates. Mount it from a secret store (a Kubernetes Secret, systemd `LoadCredential=`, a vault agent). It cannot be rotated in v1 |
| OIDC client secret | `oidc.client_secret_file` (mode 0640, group of the service) or `JAUNT_OIDC_CLIENT_SECRET` | not printed anywhere |
| S3 keys | `recordings.s3.access_key_file`, `secret_key_file`, or `AWS_*` | credential files up to 4 KiB; give the keys only the permissions listed in operations |
| database | `jaunt.db`, mode 0600 | API tokens and web session secrets are stored as hashes |
| node identity | `/var/lib/jaunt` on the node, mode 0700: TLS key, SSH host key, certificates | created on the node; the private keys never leave it |

## Hardening checklist

- Run `jauntd` from the unit in [deploy/systemd/jauntd.service](../deploy/systemd/jauntd.service) (account `jauntd`, `NoNewPrivileges`, `ProtectSystem=strict`, private `/tmp` and devices, no capabilities, a system-call filter, `MemoryDenyWriteExecute`). `systemd-analyze security` rates it 1.3 on Debian 13 (systemd 257); the agent unit written by `jaunt-agent install` rates 1.7.
- Terminate TLS for the console with a certificate from a public CA, enable HSTS at the proxy, pass the client address in `X-Forwarded-For` and set `client_ip_header` and `client_ip_trusted_proxies` so that limits and audit see real addresses, and expose only: 443 (proxy), 8444 (agents) and the SSH gate port. Do not expose the plain `listen` port.
- Keep the agent port on TCP passthrough: a proxy that terminates TLS cannot pass the client certificate.
- Set `client_ip_header` and `client_ip_trusted_proxies` only for a proxy you control; the header is believed only from those networks.
- Keep the age identity off the data directory and out of backups of it.
- Save the internal CA pin ([operations.md](operations.md#internal-ca-pin)) and use `--ca-pin` on every enrolment. Compare both fingerprints that `enroll` prints with the ones the approval shows.
- Write the policy in Git and run `jaunt policy check` in CI. Prefer roles by group and narrow node labels over `"*"`. Do not list `root` as a login.
- Set `device_login: false` if no one uses the device flow (the CLI does not offer it yet).
- Keep `cert_ttl_secs` short. Rotate the user and host CAs once a year ([operations.md](operations.md#ca-rotation)).
- Send the audit JSON lines to a log system the `jauntd` account cannot write to; keep `audit.database` on for the console.
- Keep the clocks of all machines synchronised.
- Back up `data_dir` and test the restore ([operations.md](operations.md#backup-and-restore)).
- Remove `NODE_LOGIN` accounts that nobody needs on the nodes, and keep the node's `sshd` otherwise as hardened as before: Jaunt adds a way in, it removes none.
- Keep the system time and the `jaunt-agent` version current; run `jaunt-agent` only under the account `jaunt-agent install` creates.

## Known limits

- One `jauntd` process per database. No high availability.
- The internal CA cannot be rotated without enrolling every node again.
- A join token does not identify the host that uses it, and revoking it does not remove nodes that already enrolled. The answer `409 name_taken` is not the generic refusal: it is given before the token is looked at, so anyone who can reach the enrolment endpoint can learn that an active node has a given name (this was already so for enrolment by code).
- No `deny` rules, no second factor per session, no live view of a session, no agent forwarding, `-R` or X11.
- The gate is not isolated from the control role: both run in the `jauntd` process. A code execution bug in the SSH listener reaches the CA keys in memory.
- Web sessions, including the browser terminal, pass through the gate and the server in clear text. This is an accepted risk of the design; use `ssh` from a laptop where end-to-end protection matters.
- A recording is trusted as far as the node is: a compromised node can produce false recordings of its own sessions.
- The directory and the S3 store never delete recordings, and the bucket must be a trusted store.
