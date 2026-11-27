# Operations

Runbooks for running Jaunt for a year. Each one has a trigger, the commands, what you see, how to go back and what not to do. Commands that start with `jauntd` run on the control host as the service account, with the configuration file named:

```sh
alias jd='sudo -u jauntd jauntd --config /etc/jaunt/jauntd.yaml'
```

The outputs below were captured from a real run of [quickstart.md](quickstart.md). Values such as fingerprints and ids differ in your installation.

Contents: [Revocation](#revocation), [CA rotation](#ca-rotation), [Internal CA pin](#internal-ca-pin), [Enrol many nodes with join tokens](#enrol-many-nodes-with-join-tokens), [Recordings](#recordings), [Backup and restore](#backup-and-restore), [Upgrade and rollback](#upgrade-and-rollback), [Limits](#limits), [Audit](#audit), [Troubleshooting](#troubleshooting), [Web terminal](#web-terminal).

## Revocation

**Trigger:** a laptop is lost, a person leaves, a certificate leaks, a node is compromised.

A revocation has a kind: a **user** (every certificate the user has or will get until the revocation is removed), a **serial** (one certificate) or a **node**.

```sh
jd node list
jd revoke user 4e06bbeb-7371-4ac9-8203-5bedb42fa80b --reason "left the company"
jd revoke serial 3 --reason "laptop lost"
jd revoke node web-01 --reason "host compromised"
jd revocations list
```

The user id and the serial are in the audit events `cert.issued` and `session.start`, and in the console (Sessions and Revocations pages). The command prints:

```text
revoked user 4e06bbeb-7371-4ac9-8203-5bedb42fa80b (revocation cb639e56-c9a5-4365-a402-8e9c71a228a2)
if a jauntd that uses this database is running, it refuses new connections for it at once and closes its live sessions within about a second, at its next revocation check
```

What is cut, measured on the test stand: a running `ssh` session ended 1 second after the command; the client printed `Received disconnect from ... port 2222:11: jaunt: access denied or node unavailable`. New connections get `channel 0: open failed: connect failed: jaunt: access denied or node unavailable`. Web terminals of the user close with code 4001. Revoking a user also ends the user's web sessions and API tokens (`web_sessions_ended` and `api_access_removed` in the `revoke.created` event). Revoking a node closes its tunnel, ends its sessions and removes it from routing.

Revocations are checked on every connection, because certificates carry identity and not rights. Nothing has to be distributed to nodes.

**Undo:** `jd revocations rm <revocation id>`. A removed user revocation accepts new connections at once, but the web sessions and API tokens that were deleted stay deleted: the user signs in again. A removed node revocation does not bring the node back: the node was removed, so its agent must enrol again (`jaunt-agent enroll --replace`) and be approved.

**Do not:** rely on a short certificate lifetime instead of revoking; a certificate is valid until its end. Do not revoke by editing the database. A change to a policy file (removing a user from a role) also takes effect on the next connection, but group changes in the identity provider only take effect when the user signs in again, up to `cert_ttl_secs` (8 hours by default) later: revoke the user to cut access at once.

## CA rotation

**Trigger:** a planned rotation (once a year is reasonable), or a suspected leak of a CA key.

Jaunt has three authorities: the **user CA** signs user certificates, the **host CA** signs the certificates of the gate and the nodes, and the **internal CA** secures the agent connection. The user and host CAs rotate without downtime. Each has an `active` key, at most one `next` key and at most one `previous` key, and rotation is three commands: `add-next`, `promote`, `retire`. `promote` and `retire` check that the step is safe and refuse with exit code 3 when it is not.

Exit codes of `jauntd ca add-next|promote|retire`: 0 done, 1 error, 3 blocked by a check (nothing changed). `jd ca status` prints the state and what blocks the next step; `jd ca status --json` prints the same for scripts, with the counters and the lists of names (`behind_names`, `offline_names`, `names`). The counters are complete, the lists name at most the first 20 nodes. The running daemon notices a changed key directory within 10 seconds and tells the connected agents; each agent reads the new set after a random delay of up to 5 seconds. A command that changed keys ends with the line `applied within 10 s`; `status` and a blocked step (exit 3) do not print it.

### User CA

```sh
jd ca status
jd ca add-next user
jd ca status
jd ca promote user
jd ca retire user
```

1. `add-next user` creates the next key and adds it to the trust set. Output: `user key <fingerprint> added as next` and `applied within 10 s`.
2. `promote user` makes the new key the signing key. It is blocked until every node that reads the trust set has the current set:

   ```text
   promote: blocked: 1 node behind (web-01)
   the promote check blocks this step, so it was not applied; --force skips the check and is audited
   ```

   Wait and run `jd ca status`; in the test stand the node was current after about 10 seconds. A node that has not read the trust set for 20 minutes counts as offline, is listed in `offline` and does not block. When the line `promote: ready` shows, run `promote`:

   ```text
   user key 0a365b... is active, 1be1de... is previous
   applied within 10 s
   ```

3. `retire user` removes the previous key and deletes its private key. It is blocked while certificates signed by the previous key (or issued before rotation was tracked) have not expired:

   ```text
   retire: blocked: 1 unexpired user certificate signed by a previous key or before rotation tracking
   ```

   With the default `cert_ttl_secs` of 8 hours that is at most 8 hours after `promote`. Running sessions are not cut by `retire`: the certificate is checked when the session starts.

### Host CA

Same three commands with `host`. The checks differ:

- `promote host` is blocked while unexpired user certificates exist that were issued before the clients learned the new host key (the clients learn it when they sign in): `promote: blocked: 1 unexpired user certificate issued before the current host keys were published`. This takes at most `cert_ttl_secs` after `add-next host`.
- After `promote host` the gate re-issues its own certificate at once, and every agent of the current version renews its host certificate within up to 5 minutes (random spread).
- `retire host` is blocked while a node still presents a certificate signed by the previous key. The refusal reads `retire: blocked: 1 node on a previous host key (web-01)` and `status` shows it as `nodes on previous host keys or untracked`. Nodes that were offline during the rotation renew when they start.

An agent from before the rotation work (it only speaks the first trust protocol) renews its host certificate at half of its 7 day lifetime, and a restart does not change that. `retire host` stays blocked naming it. The way out is to enrol the node again: `sudo jaunt-agent enroll --replace ...` and approve it. Update the agent and this does not happen again.

### Timings

Measured by the end-to-end stand (`just e2e-rotation`, three nodes, 120 second certificates, 61 steps): three runs on Debian 13 took 747, 832 and 690 seconds in all. The deadlines the stand allows are the worst cases of the product, not typical times:

| Step | Worst case |
|---|---|
| live nodes have the new trust set after `add-next` | 10 s watcher + 5 s agent delay |
| the gate presents the new host key after `promote host` | 10 s watcher + re-issue |
| agents renew their host certificates after `promote host` | up to 5 min delay |
| `promote user` unblocked | every node current |
| `retire user` unblocked | `cert_ttl_secs` after `promote` |
| `retire host` unblocked, current agents | minutes; old-protocol agents: re-enrolment |

### `--force`

`--force` skips the check of `promote` or `retire`. Use it for a compromised key: `add-next`, `promote --force`, `retire --force`, then revoke the affected users and certificates (see above), because `retire` does not end sessions. The command prints `forced past the check`. The audit event `ca.key.promoted` or `ca.key.retired` carries `forced: true`, `blocked: true` and the counters that the check had found (`nodes_behind`, `old_unexpired`, `nodes_old`), and `changed_by` names the operator (`cli:<USER>`).

Consequences of forcing: a node that has not read the new trust set refuses logins signed by the new key (`Permission denied (publickey)`, and the agent logs `agent.ssh.auth outcome=denied reason=untrusted_ca`) until it reads it. A stale agent recovers by itself within about a minute once it can reach the server; if it cannot reach the API, restart the agent. After `retire host --force`, users who have not signed in again still trust the old host key until their next sign-in.

**Do not:** edit `ca/` by hand; copy only some of the files from a backup; run two rotation commands at the same time (they take a lock and the second fails with a lock error); delete the previous key by hand instead of `retire`.

### The internal CA

Rotating the internal CA is not supported in v1. Its root lives 10 years, its private key sits in the same directory as the other two and the agents pin it. If it must be replaced (key leak or expiry), start over. Stop `jauntd`. Move the whole directory away: `sudo mv /var/lib/jauntd/ca /var/lib/jauntd/ca.old` (it holds the old age identity if you kept it there). Create new authorities with a new age identity: `sudo -u jauntd jauntd ca init --generate-identity --config /etc/jaunt/jauntd.yaml`. This prints the new `internal-ca` pin and writes the identity to `/var/lib/jauntd/ca/age-identity.txt`. If the identity belongs outside the data directory, move that file there and set `JAUNT_CA_KEY_FILE` for `jauntd` (`Environment=JAUNT_CA_KEY_FILE=...` in a unit drop-in). A bare `ca init` without `--generate-identity` needs `JAUNT_CA_KEY` or `JAUNT_CA_KEY_FILE` to point to an existing age identity and fails otherwise. Start `jauntd`, then run `jaunt-agent enroll --replace --ca-pin <new pin>` on every node and approve each. Delete `ca.old` after the last node is back; it holds the old keys. Replacing the whole `ca/` directory also replaces the user and host CAs; users sign in again and clients learn the new host key at that sign-in. Every node is unreachable until it is enrolled again. `jauntd ca add-next internal` answers `rotating the internal certificate authority is not supported in v1, see the runbook` and exits 1.

## Internal CA pin

Nodes trust the server's internal CA by a pin: `sha256:` and the SHA-256 of the root certificate. `jauntd ca init` prints it once. No `jauntd` command prints it again (`ca status` lists only the user and host keys). The root certificate itself is public and kept unencrypted, so the pin can be recomputed from the file:

```sh
sudo sh -c 'sha256sum /var/lib/jauntd/ca/internal/*.root.der'
```

The output is `<64 hex digits>  <file>`; the pin is `sha256:<64 hex digits>`. This is the same value `ca init` printed (checked on the test stand). If the data directory is lost together with all backups, the pin is lost with it; but then the CA keys are lost too and the previous section applies. Without `--ca-pin` the agent takes the root the server hands over during enrolment, so a first enrolment over a hostile network could be fooled. Use the pin.

## Enrol many nodes with join tokens

**Trigger:** you bring in many hosts at once (a fleet, a rebuild, a scaling group) and typing a code for each one is too slow, or no person is at the host.

A join token pre-approves a bounded number of enrolments. The agent reads the token from a file, and the server creates its enrolment already approved. No one types a code and no one compares fingerprints. The token is a bearer credential: whoever holds it can enrol a host inside its scope until it expires or runs out.

### What a token can and cannot do

| Property | Rule |
|---|---|
| node name | exactly one of `--name` (the only name accepted) and `--name-prefix` (any name that starts with it). A name is 1 to 63 lowercase letters, digits or `-`, starting and ending with a letter or digit; a prefix has the same characters, starts with a letter or digit and may end with `-`. Write `web-`, not `web`: `web` also matches `website` |
| labels | the node gets exactly the `--label k=v` pairs of the token, at most 16, repeated once per label (rules as for `--labels` of `enroll`: the key matches `[a-z][a-z0-9_.-]{0,62}`, the value `[A-Za-z0-9._-]{0,63}`). The agent's own `--labels` may only repeat pairs the token has; any other label is refused. An agent that gives no labels still gets all pinned ones |
| uses | `--uses`, 1 to 1000, default 1 |
| lifetime | `--ttl`, a whole number and one of `s`, `m`, `h`, `d` (`30m`, `2d`); at least 1 second, at most `7d`, default `1h` |
| replacing a node | only when the token has `--allow-replace` and the agent runs `enroll --replace` |

A token cannot widen its scope, be extended, or be shown again: the server keeps only its SHA-256 hash. It does not identify the host that uses it, so keep the scope as narrow as the job allows. A node that enrols with a token gets a name inside the token's scope and exactly the token's labels. Policy gives access by labels, so a token that pins `env=prod` gives the new host every access that `env=prod` nodes have.

### 1. Create the token

On the control host:

```sh
jd join-token create --name-prefix web- --label env=prod --label role=web --uses 5 --ttl 2h
```

Exactly one of `--name` and `--name-prefix` is required. The token is the only thing printed on stdout (47 characters: `jt1.` and 43 more). The id and the expiry go to stderr:

```text
jt1.<43 characters>
```

```text
created join token 5b0c0a3e-8d4f-4b1a-9c27-3f6e1d2a7b90 for node names starting with web-; 5 uses; labels env=prod,role=web; expires at 2026-11-26T14:00:00Z
the token above is shown only this once: put it in a file with mode 0600 owned by the agent's user and run `jaunt-agent enroll --token-file <file>`
```

Because stdout carries only the token, you can write it to a file that nobody else can read, and keep the terminal free of it:

```sh
(umask 077 && jd join-token create --name-prefix web- --label env=prod --label role=web --uses 5 --ttl 2h > join-token.txt)
```

That file lives on the control host and is owned by you. Deliver the token to the node through your own secret channel, then delete the file at once (`shred -u join-token.txt` or `rm -- join-token.txt`).

Exit codes: 0 done, 1 failed, 2 a usage error (a bad name, prefix, label, `--uses` or `--ttl`, or both or neither of `--name` and `--name-prefix`). The command needs the database, so start `jauntd` once before the first token. Creating a token is audited (`join_token.created`).

### 2. Put the token on the node

The token must not appear in a command line, so type or paste it into a file. On the node:

```sh
sudo sh -c 'umask 077 && cat > /root/jaunt-join-token'
```

Paste the token, press Enter, then Ctrl-D. Or let your configuration management or secret store write the file. The agent refuses the file unless all of these hold:

- the mode is 0600 or stricter (no bit outside `rw` for the owner);
- the owner is the user that runs `jaunt-agent enroll` (under `sudo`, root);
- it is a regular file, and the last part of the path is not a symbolic link;
- it is at most 4 KiB, and it holds the token and nothing else (blanks and line ends around it are ignored).

### 3. Install, enrol, start

Keep the order from [install.md](install.md): install the service, then enrol, then start. `install` refuses a state directory that `enroll` has already filled.

```sh
sudo jaunt-agent install
sudo jaunt-agent enroll --server https://<host> --name web-01 --labels env=prod,role=web --ca-pin sha256:<hash> --token-file /root/jaunt-join-token
sudo systemctl start jaunt-agent
sudo rm -- /root/jaunt-join-token
```

Keep `--ca-pin` ([Internal CA pin](#internal-ca-pin)): the agent sends the token to the server it is talking to. The agent prints no code. It shows the fingerprints of its keys and the time by which it must collect its certificates (15 minutes), and then it enrols:

```text
tls key:      sha256:...
ssh host key: SHA256:...
expires at:   2026-11-26T12:15:00Z
```

```text
the join token was accepted; collecting the certificates
enrolled as node 3f9a... (web-01); certificates valid until 2026-12-03T12:00:00Z; start the agent with `jaunt-agent run`
```

On the control host the node appears with the token as its approver. The trail has `node.enroll.requested`, `join_token.used` (it takes the place of `node.enroll.approved`, which a join does not write) and, when the agent collects its certificates, `node.enroll.delivered`:

```sh
jd node list
jd join-token list
```

```text
NAME    STATE   CERT       LABELS             APPROVED BY                                      CREATED
web-01  active  delivered  env=prod,role=web  join-token:5b0c0a3e-8d4f-4b1a-9c27-3f6e1d2a7b90  2026-11-26T12:00:00Z
```

```text
ID                                    NAME   LABELS             USES  EXPIRES               REVOKED               REPLACE
5b0c0a3e-8d4f-4b1a-9c27-3f6e1d2a7b90  web-*  env=prod,role=web  4/5   2026-11-26T14:00:00Z  -                     no
a4e1d7c2-0b35-4f68-8e19-72c5b9d03a16  db-01  -                  1/1   2026-11-26T13:30:00Z  2026-11-26T12:40:00Z  yes
```

`USES` is the uses left and the uses allowed. The list never shows a token. An expired token stays in the list for about an hour and is then deleted; its audit events stay.

### Uses

A use is consumed in the same database transaction that creates the node and its approved enrolment. A refused attempt (wrong name, wrong labels, a name that is taken) consumes nothing.

A use is not given back once it is consumed. If the agent stops before it collects its certificates, the node stays: `jd node list` shows it `active` with `CERT` `pending`, and `none` after the 15 minutes, and the name is taken. To try again, remove the node and enrol again with a token that has a use left, or use `--replace` with a token that has `--allow-replace`:

```sh
jd node rm web-01
```

### Replacing an existing node

Replacing needs both sides: the agent runs `enroll --replace` and the token was created with `--allow-replace`. The old node is removed in the same transaction that consumes the use (`node.removed` with `reason: replaced` and the token as the actor), its open sessions are closed at once, and the new host takes the name. If closing the sessions fails the log says so and the periodic session sweep closes them. With `--replace` but without `--allow-replace`, an active name is refused (`replace_not_allowed`); `--replace` on a name that is free just enrols.

Note: `--allow-replace` lets whoever holds the token take over the name of a running node with a new host and new keys, and the policy that matches that name or its labels then reaches the new host. Use it only with `--name`, `--uses 1` and a short `--ttl`, and never with a prefix that covers production hosts.

### Revoke a token

```sh
jd join-token rm 5b0c0a3e-8d4f-4b1a-9c27-3f6e1d2a7b90
```

```text
revoked join token 5b0c0a3e-8d4f-4b1a-9c27-3f6e1d2a7b90 (4 of 5 uses were left)
```

Revoking stops new enrolments at once. It does not remove nodes that already enrolled with the token, nor enrolments whose certificates were not collected yet. Find those nodes by `join-token:<id>` in the `APPROVED BY` column and remove the ones you do not trust:

```sh
jd node list | grep 'join-token:5b0c0a3e-8d4f-4b1a-9c27-3f6e1d2a7b90'
jd node rm web-03
```

Revoking an unknown id or a revoked token exits with 1 (`no join token has this id`, `the join token is already revoked`). `join_token.revoked` records the operator and the uses left.

### When a token is refused

The agent always sees the same refusal, whatever the reason, so that someone who guesses tokens learns nothing:

```text
the server refused the join token: it is unknown, expired, used up or revoked, or it does not allow this name, these labels or --replace
```

The cause is in the audit event `join_token.refused`: `reason`, `join_id` (absent when the token is unknown or malformed), the requested `name`, `source_ip` and `source_network`. Refusals are noisy events without a `suppressed` count: each one is a separate event, and when the noisy audit queue is full the newest are dropped (see Limits), so a flood of guesses can hide some refusals from the trail. The reasons:

| `reason` | Cause | What to do |
|---|---|---|
| `malformed` | the text is not shaped like a join token (an agent never sends this) | look at `source_ip`: this is a hand-made request |
| `unknown` | no token has this hash: a mistyped or truncated token, a token of another server, or a token deleted an hour after its expiry | create a new token |
| `revoked` | the token was revoked | create a new token if the revocation was a mistake |
| `expired` | past its `--ttl` | create a new token |
| `used_up` | all uses are consumed | create a new token, or look for a node that was enrolled and never finished (see Uses) |
| `name_mismatch` | the node name is not the token's name or does not start with its prefix | fix `--name` on the agent, or create a token for that name |
| `label_mismatch` | the agent asked for a label that the token does not pin, or with another value | remove the label from the agent or create a token with it |
| `replace_not_allowed` | the agent used `--replace`, the name is active and the token has no `--allow-replace` | read the Note above before you create such a token |

When several of `revoked`, `expired` and `used_up` hold, the first of them in this order is reported. One answer is different on purpose: if the name is active and the agent did not pass `--replace`, the server answers `409` and the agent prints `the server refused the request: the name is already used by an active node; run again with --replace to replace that node`. That check runs before the token is read and writes no `join_token.refused` event. Attempts count against the `http.enroll` rate limit (429, see Limits).

### Do not

- Do not put a token in a command line, an environment variable, a chat message or a ticket. The agent and `jauntd` have no option for it, on purpose: arguments show up in the process list and in shell history.
- Do not create long-lived tokens. The limit is 7 days and the default is 1 hour. Create the token when you start the roll-out and revoke it when you finish.
- Do not reuse one token across environments. Make one token per environment and role, with its labels pinned, so that a leak in staging does not enrol a production host.
- Do not leave the token file on the node after enrolment, and do not copy it into an image or a backup.
- Do not give a prefix token more uses than the number of hosts you are bringing in.

## Recordings

### What is recorded

Recording is on when `recordings.dir` is set (or `recordings.store: s3`). `dir` has no default; `/var/lib/jauntd/recordings` in this guide is only the quickstart's choice. The rules in the code:

- A shell session with a terminal is recorded as an asciicast v2 file (`.cast`) of what the terminal printed, uploaded by the agent while the session runs, in compressed chunks with a SHA-256 each. `ssh -t host command` also gets a terminal and is recorded.
- A command without a terminal (`ssh host command`), `scp`, `rsync` and `sftp` leave only metadata: the command or the fact, the exit status and the byte counts. Port forwards are not recorded.
- What the user types is recorded only when the role sets `recordInput: true`. Passwords typed with echo off still appear in an input recording; plan for that.
- There is no switch to turn recording off per role. Without `recordings.dir` nothing at all is recorded. Policy has no key for disabling the terminal (`pty`): every session may use one, so no role can force "metadata only".

### Storage

| Backend | Layout | Notes |
|---|---|---|
| `directory` | `<dir>/<year>/<month>/<session id>.cast` and `.manifest.json` | the daemon refuses new recordings when less than `min_free_bytes` (1 GiB) is free |
| `s3` | `<prefix><year>/<month>/<session id>.cast` and `.manifest.json` in the bucket | recordings are staged in `staging_dir` and uploaded when the session is complete |

S3 needs these permissions on the prefix: `s3:PutObject`, `s3:GetObject`, `s3:ListBucket`, `s3:DeleteObject` and `s3:AbortMultipartUpload`. Add a lifecycle rule `AbortIncompleteMultipartUpload` (for example 1 day). Set no expiry rule you do not intend: the product never deletes recordings, and the bucket is a trusted store (anyone who can write to it can forge recordings). The manifest is the commit marker: an object `.cast` without `.manifest.json` is an unfinished upload, and the daemon removes such objects when it scans the bucket (at start and every 6 hours). Credentials come from `recordings.s3.access_key_file` and `secret_key_file` or from the `AWS_*` variables. More on conflicts and quarantine: `crates/jaunt-recording-s3/README.md`.

While a recording waits for the bucket, `staging_dir` holds `<year>/<month>/<session id>.cast.part` and `<session id>.manifest.pending`. If the object store is not reachable they stay there and the maintenance task of the daemon tries again every 5 minutes; after `max_wait_secs` (24 hours) it stops retrying and logs an error, keeping the files. A `.manifest.pending` that stays unreadable is moved with its cast to `<staging_dir>/quarantine/<session id>/` after five attempts, and the session is marked failed; nothing in quarantine is ever deleted by the daemon. At start, staged recordings are published or adopted again. A conflict between a staged and a stored object keeps both and answers `409 conflict`; see `crates/jaunt-recording-s3/README.md` for the table.

### What a restart does

A restart of `jauntd` closes the sessions of the earlier run (the log says `open sessions of earlier runs are closed at start`). A restart of the agent, or a lost tunnel, cuts the live sessions of that node. The agent keeps chunks that could not be sent in memory (up to `recording.session_queue_bytes` per session and `memory_budget_bytes` in all) and sends them when the tunnel returns; a restart of the agent process loses what was still in memory. A session whose recording stops arriving is closed by the server after `idle_timeout_secs` (2 hours) and marked incomplete or failed; the console shows it so. Measured on the test stand: a command on the node can run for 13 to 30 seconds after the tunnel broke.

### Playing, verifying, auditing

In the console, Sessions, choose a session and press Watch recording (permission `recordings.read`). The page serves the recording with restrictive headers (`Content-Security-Policy: sandbox`) and refuses recordings larger than `max_playback_bytes` (64 MiB). Each view writes a `recording.viewed` event.

```sh
jd recordings verify 3d1c2c3b-7e97-4af0-a689-19a1c1d693db
```

```text
recording 3d1c2c3b-7e97-4af0-a689-19a1c1d693db verified: 1 chunks, 222 bytes, complete, cast sha256 0190bbd4...
```

`verify` recomputes the digests of the stored cast against the manifest. Exit 0 verified, 1 failed or not found (`no recording is stored for session ...`), 2 for an argument that is not a session id.

### Retention

The product deletes no recordings. Directory and bucket grow until you delete files. Delete by age with `find <dir> -name '*.cast' -mtime +365 -delete` (and the matching `.manifest.json`) or a bucket lifecycle rule, and keep the audit events: they outlive the recordings in the database for `audit.retention_days`. Deleting files does not delete the session rows in the database.

Events: `recording.completed`, `recording.rejected`, `recording.viewed`, `recording.mismatch` (the agent and the server disagree about completeness).

## Backup and restore

What is where, under `data_dir` (`/var/lib/jauntd`):

| Path | Contents | Secret |
|---|---|---|
| `jaunt.db`, `jaunt.db-wal`, `jaunt.db-shm` | the SQLite database: users, certificates, nodes, sessions, revocations, audit events, web sessions | yes: API tokens and web session secrets are stored hashed, but the file lists people, nodes and activity |
| `ca/user`, `ca/host`, `ca/internal` | the private CA keys, each encrypted with age (`*.age`), the public keys (`*.pub`) and the internal root certificate (`*.root.der`) | the `.age` files are useless without the age identity |
| `ca/age-identity.txt` | the age identity that decrypts the CA keys, when `ca init --generate-identity` made it. In production it is outside the data directory (`JAUNT_CA_KEY_FILE`) | **yes: with the `.age` files it issues certificates** |
| `recordings/` | the directory store | yes: terminal output |
| `policy/` | policy files, if `policy_dir` is the default | no |

Back up the database with SQLite's online backup, which is safe while the daemon runs, and the other trees by copy:

```sh
sudo install -d -m 0700 -o jauntd -g jauntd /srv/backup
sudo -u jauntd sqlite3 /var/lib/jauntd/jaunt.db ".backup /srv/backup/jaunt.db"
sudo -u jauntd tar -C /var/lib/jauntd -cpf /srv/backup/ca.tar ca
sudo -u jauntd tar -C /var/lib/jauntd -cpf /srv/backup/recordings.tar recordings
```

Keep the age identity in a separate place from the `ca.tar` (a password manager, a sealed secret). Do not copy `jaunt.db` with `cp` while the daemon runs: the write-ahead log would be missed. Copying the whole directory with the daemon stopped is also fine.

**What a lost key means:** without the age identity the CA keys cannot be read, `jauntd` does not start and nothing signs; recover by `ca init` in a clean directory and re-enrolling every node (see the internal CA section). Without `jaunt.db` the keys still work but all state is gone: users, nodes, certificate serials and revocations. Treat it as a new installation: every node enrols again and every user signs in again.

**Restore rehearsal** (done on the test stand; do it on a scratch host, with a copy of the configuration that points to another `data_dir`). It needs the `sqlite3` command-line tool for the database steps here and in the backup above (`apt install sqlite3`, `dnf install sqlite`). If the age identity is not in `ca/age-identity.txt`, export `JAUNT_CA_KEY_FILE` to its path for the `jauntd` commands (`sudo -u jauntd env JAUNT_CA_KEY_FILE=<path> jauntd ...`):

```sh
sudo install -d -m 0700 -o jauntd -g jauntd /srv/restore
sudo -u jauntd sh -c 'cp /srv/backup/jaunt.db /srv/restore/jaunt.db && tar -C /srv/restore -xpf /srv/backup/ca.tar && tar -C /srv/restore -xpf /srv/backup/recordings.tar'
sed 's#/var/lib/jauntd#/srv/restore#' /etc/jaunt/jauntd.yaml | sudo tee /srv/restore.yaml >/dev/null
sudo -u jauntd jauntd ca status --config /srv/restore.yaml
sudo -u jauntd jauntd node list --config /srv/restore.yaml
sudo -u jauntd jauntd recordings verify <session id> --config /srv/restore.yaml
sudo -u jauntd sqlite3 /srv/restore/jaunt.db 'pragma integrity_check;'
```

Expect the keys and trust ids of the backed up system, your nodes, `verified` and `ok`. Remove `/srv/restore` afterwards. To restore for real, stop `jauntd`, put the files back with the same owner and mode (0700 on directories), and start it. Agents reconnect by themselves. What happened after the backup is gone: a user whose certificate was issued after it is refused (`certificate_not_issued`) and signs in again, and a node enrolled after it must enrol again.

## Upgrade and rollback

Order: the control host first, then the nodes, then the laptops. Agents and `jauntd` of adjacent versions work together: the trust protocol has two versions (v1 and v2) and the server serves both, and an agent that meets an old server falls back to v1.

1. Back up (previous section). A backup taken before the upgrade is the only way back.
2. Replace the binary and restart: `sudo install -m 0755 jauntd /usr/local/bin/jauntd && sudo systemctl restart jauntd`. A restart closes live sessions and cuts live recordings; choose a quiet moment. For the container image, change the tag.
3. At start `jauntd` applies the database migrations (`migrate` runs in `jauntd run` and in every `jauntd` subcommand that opens the database). They only go forward; there is no down migration. Check the log for `serving plain http`.
4. Upgrade the agents: replace `/usr/local/bin/jaunt-agent` and `systemctl restart jaunt-agent` (see [install.md](install.md)). The identity under `/var/lib/jaunt` is kept.

**Rollback.** Stop `jauntd`, restore the database from the backup taken before the upgrade, install the old binary, start it. Do not start an older `jauntd` on a database a newer one migrated: it refuses with `cannot migrate the database: migration error: migration 13 was previously applied but is missing in the resolved migrations` (checked on the test stand). The certificate authority directory format does not change between these versions, so the `ca/` tree needs no rollback. Data written by the newer version after the backup (sessions, audit events, nodes enrolled in the meantime) is lost with the restore.

**Do not:** run two `jauntd` processes on one database (a single process is assumed and logged at start); skip versions and then discover a migration problem without a backup.

## Limits

Defaults are in [configuration.md](configuration.md#limits). What you see when one is hit:

| Limit | Behaviour | Where to see it |
|---|---|---|
| HTTP rate per address (`limits.http.*`) | HTTP 429 with `Retry-After`, body `too_many_requests` | audit `http.rate_limited` with `endpoint` and `retry_after`; at most one event per endpoint and address per interval, with a `suppressed` count |
| HTTP connections (`max_connections`, `max_connections_per_address`) | the connection is closed | audit `http.connection_limited` with `reason` |
| Enrolment attempts (`http.enroll`, 6 a minute per address after a burst of 60) and code guesses (`http.enrolment_lookup`) | 429 | `http.rate_limited` with `endpoint: enroll` or `enrolment_lookup` |
| Device-code attempts | a lock-out for the address | audit `login.device.code_failed`, `login.device.locked_out` |
| SSH connections per address (`limits.ssh`) | the connection is dropped | audit `gate.limited` with `reason` `rate`, `concurrent` or `table_full` |
| SSH connections that have not authenticated (`ssh_gate.max_unauthenticated`, 512) | refused | `gate.limited` |
| open SSH streams per user and node | 8; the next `ssh` gets `jaunt: too many open sessions` | `gate.forward` with `outcome: limit` |
| handshakes in progress on `agents_listen` per address (`limits.agents`) | the TLS handshake is refused | audit `agent.limited`; with `services.domain` set, `gate.tls.refused` with `reason: limit` instead |
| open pass-through connections to `<cluster>.kube.<services.domain>` per address (`limits.kube`) | the connection is closed before a byte reaches the cluster agent | `gate.tls.refused` with `reason: limit` |
| the services entry on `agents_listen` (with `services.domain`): 1024 handshakes at once, PROXY header in 5 s, ClientHello at most 16 KiB, hello and TLS handshake in 10 s | the connection is closed | `gate.tls.refused` with `reason` `limit`, `proxy_timeout`, `hello_too_large` or `hello_timeout` |
| API connections of one node (4) and of all nodes (1024) | the extra connection is refused | server log and the agent's log |
| web terminals | `max_per_user` 4, `max_total` 64, 8 tickets per web session | `terminal.denied` with `reason` `limit` or `tickets_full` |
| recording memory on the node (`recording.*`) | recording data is dropped and the session is marked incomplete | agent log `agent.ssh.recording_dropped`; session `recording_incomplete: true` |
| recording uploads and sizes on the server (`recordings.*`) | the upload is refused | audit `recording.rejected` with `reason` |

Noisy events are the connection-level and flood-driven ones (the `(noisy)` rows in the [Audit](#audit) table). Nine of them carry a `suppressed` field: the first occurrence is logged and later ones are counted into it (`recording.rejected`, `login.callback_refused`, `http.rate_limited`, `http.connection_limited`, `http.client_ip_header_ignored`, `gate.limited`, `agent.limited`, `gate.tls.refused`, `terminal.denied`). `gate.tls.refused` counts each `reason` on its own, so a flood of one reason never hides the first event of another. The other six have no such field and are written one by one: `login.device.code_failed`, `gate.connect`, `gate.session_refused`, `gate.disconnect`, `agent.rejected` and `join_token.refused`. Noisy events wait in their own queue, a quarter of `audit.queue` (256 with the default of 1024). Critical events have their own queue and are written first, so a flood of noisy events never displaces them. When the noisy queue is full, the newest noisy events are dropped, not the old ones. The daemon logs `the noisy audit queue is full, the newest noisy events were dropped` with the number dropped, at most once a minute, and the daemon log is the only place that says so.

## Audit

Every event is one JSON object: `v` (schema version, 1), `id`, `type`, `time` (UTC, milliseconds), `actor` (a user id, `node:<node id>`, `system` or `anonymous`), `node`, `session_id`, `policy_hash` where they apply, and `fields`. Events go to stdout (`audit.jsonl`), to the database (`audit.database`) or to both. Under systemd, stdout is in the journal next to the human log (which starts with `{"timestamp"`):

```sh
sudo journalctl -u jauntd -o cat | grep '^{"v":1' | jq -c 'select(.type | startswith("session."))'
```

The console's Audit log page and `GET /v1/admin/audit` (permission `audit.read`, browser session) read the database. Query parameters, each at most once: `type` (a type or a prefix such as `session.`), `actor`, `node` (node id), `session`, `from` and `to` (RFC 3339 UTC, `from` before `to`), `limit` (default 50, at most 200) and `cursor` (from `next_cursor`). An unknown parameter is an error `unknown_parameter`. The answer is `{"events": [...], "next_cursor": "..."}`.

The 65 types and their fields (generated from `crates/jaunt-audit/src/spec.rs`; text fields are truncated to a fixed length; `email` is never stored):

| Type | Actor | Fields |
|---|---|---|
| `login.started` | anonymous | `login_id` |
| `login.approved` | user | `login_id`, `kind` |
| `login.denied` | anonymous | `login_id`, `reason` |
| `login.finish_failed` | user | `login_id`, `reason` |
| `login.device.started` | anonymous | `login_id`, `ip` |
| `login.device.code_failed` (noisy) | anonymous | `ip` |
| `login.device.locked_out` | anonymous | `ip`, `reason` |
| `login.device.continued` | anonymous | `login_id` |
| `login.web.started` | anonymous | `login_id` |
| `login.web.session_created` | user | `login_id`, `ip`, `expires_at` |
| `login.web.session_ended` | user | `reason` |
| `cert.issued` | user | `login_id`, `serial` |
| `cert.rotated` | system | `not_after` |
| `admin.csrf_denied` | user | `reason` |
| `admin.enrolment.looked_up` | user | `outcome`, `enrollment_id` |
| `authz.deny` | user | `phase`, `reason`, `permission`, `serial`, `node_name`, `login`, `client_addr`; envelope: node, session_id, policy_hash |
| `session.routed` | user | `serial`, `node_name`, `client_addr`; envelope: node, session_id, policy_hash |
| `session.start` | user | `serial`, `login`, `pty`, `port_forwarding`, `record_input`, `max_duration_secs`, `roles`, `client_addr`; envelope: node, session_id, policy_hash |
| `session.end` | user | `serial`, `login`, `exit_status`, `bytes_in`, `bytes_out`, `recording_incomplete`, `outcome`, `late`, `state_before`; envelope: node, session_id |
| `session.end_rejected` | node | `reason`; envelope: node, session_id |
| `session.terminated` | user | `serial`, `reason`; envelope: node, session_id |
| `revoke.created` | user | `revocation_id`, `kind`, `subject`, `reason`, `web_sessions_ended`, `api_access_removed` |
| `revoke.removed` | user | `revocation_id`, `kind`, `subject` |
| `gate.connect` (noisy) | anonymous | `client_addr`, `peer_addr`, `proxied` |
| `gate.auth` | user | `outcome`, `reason`, `client_addr`, `serial`, `login` |
| `gate.session_refused` (noisy) | anonymous | `client_addr` |
| `gate.forward` | anonymous | `outcome`, `node`, `client_addr`; envelope: session_id |
| `gate.stream_end` | anonymous | `node`, `client_addr`, `bytes_up`, `bytes_down`, `duration_ms`, `reason`; envelope: session_id |
| `gate.disconnect` (noisy) | anonymous | `client_addr`, `reason` |
| `gate.terminated` | user | `serial`, `reason`, `connections` |
| `agent.connected` | node | `remote_addr`, `alpn`, `replaced`; envelope: node |
| `agent.disconnected` | node | `reason`, `alpn`; envelope: node |
| `agent.rejected` (noisy) | anonymous | `reason`, `remote_addr`; envelope: node |
| `agent.trust.served` | node | `keys`, `trust_id`; envelope: node |
| `node.enroll.requested` | anonymous | `enrollment_id`, `name`, `hostname`, `source_ip`, `source_network`, `agent_version`, `replace` |
| `node.enroll.approved` | user | `enrollment_id`, `name`, `replaced_node_id`; envelope: node |
| `node.enroll.rejected` | user | `enrollment_id`, `name` |
| `node.enroll.expired` | system | `enrollment_id`, `name` |
| `node.enroll.delivered` | node | `enrollment_id`, `name`, `x509_serial`, `ssh_serial`; envelope: node |
| `node.removed` | user | `name`, `reason`; envelope: node |
| `node.cert.renewed` | node | `name`, `x509_serial`, `ssh_serial`, `rotated`; envelope: node |
| `join_token.created` | user | `join_id`, `name`, `name_prefix`, `labels`, `max_uses`, `expires_at`, `allow_replace` |
| `join_token.used` | anonymous | `join_id`, `enrollment_id`, `name`, `uses_left`, `replaced_node_id`, `source_ip`, `source_network`; envelope: node |
| `join_token.refused` (noisy) | anonymous | `reason`, `join_id`, `name`, `source_ip`, `source_network` |
| `join_token.revoked` | user | `join_id`, `uses_left` |
| `recording.completed` | node | `chunks`, `raw_bytes`, `incomplete`, `input_recorded`; envelope: node, session_id |
| `recording.rejected` (noisy) | node | `reason`, `suppressed`; envelope: node, session_id |
| `recording.viewed` | user | `kind`; envelope: session_id |
| `recording.mismatch` | node | `manifest_incomplete`, `session_incomplete`; envelope: node, session_id |
| `policy.reload` | system | `applied`, `error_count`, `error_1`, `error_2`, `error_3`; envelope: policy_hash |
| `login.callback_refused` (noisy) | anonymous | `reason`, `client`, `suppressed` |
| `http.rate_limited` (noisy) | anonymous | `endpoint`, `client`, `retry_after`, `suppressed` |
| `http.connection_limited` (noisy) | anonymous | `peer_addr`, `reason`, `suppressed` |
| `http.client_ip_header_ignored` (noisy) | anonymous | `peer_addr`, `total`, `suppressed` |
| `gate.limited` (noisy) | anonymous | `client`, `reason`, `suppressed` |
| `agent.limited` (noisy) | anonymous | `client`, `reason`, `suppressed` |
| `gate.tls.refused` (noisy) | anonymous | `client` (the address from the PROXY header when there is one, IPv6 per /64), `reason` (`proxy_untrusted`, `proxy_malformed`, `proxy_timeout`, `limit`, `hello_too_large`, `hello_timeout`, `bad_hello`, `no_sni`, `unknown_sni`, `alpn_unsupported`, `unsupported_class`), `suppressed` |
| `ca.key.added` | user | `kind`, `fp` |
| `ca.key.promoted` | user | `kind`, `fp`, `forced`, `blocked`, `nodes_behind`, `old_unexpired` |
| `ca.key.retired` | user | `kind`, `fp`, `forced`, `blocked`, `old_unexpired`, `nodes_old` |
| `ca.reloaded` | system | `kind`, `trust_id`, `active_fp` |
| `ca.reload.failed` | system | `reason` |
| `terminal.opened` | user | `node`, `login`, `serial`, `client_addr`; envelope: node, session_id |
| `terminal.closed` | user | `reason`, `bytes_in`, `bytes_out`, `duration_ms`, `serial`; envelope: node, session_id |
| `terminal.denied` (noisy) | user | `reason`, `node`, `login`, `client_addr`, `suppressed` |

What is **not** audited: terminal output and keystrokes (that is the recording); individual SFTP file operations; the contents of commands run with `ssh host command` beyond what the metadata recording holds; reads of the console pages other than recordings; and the agent-side events listed under `agent.ssh.*` (they are in the agent's log, not in the server's trail). The `jauntd` subcommands that change state (`revoke`, `node approve`, `node rm`, `join-token create`, `join-token rm`, `ca ...`) are audited; `node list`, `join-token list`, `ca status` and `recordings verify` are not. With `audit.database: false` the console and the API see nothing; with `audit.jsonl: off` the trail exists only in the database, which an administrator with access to the host can alter.

## Troubleshooting

The gate and the agent answer a refusal with a generic text on purpose, so that an attacker learns nothing. The operator finds the cause in the audit trail and the logs.

| What the user sees | Real causes | Where to look |
|---|---|---|
| `channel 0: open failed: connect failed: jaunt: access denied or node unavailable`, or `Received disconnect ... 2222:11: jaunt: access denied or node unavailable` | no role allows this user on this node and login; the user or serial or node is revoked; the node is offline; the name is wrong | audit `authz.deny` (`phase`, `reason`: `policy_denied`, `revoked`, `node_unavailable`, ...), `gate.forward` `outcome` |
| `jaunt: your certificate has expired, run jaunt login` | the user certificate ended | `jaunt login`; `jaunt status` shows the time left |
| `jaunt: too many open sessions` | 8 streams for the same user and node | `gate.forward` `outcome: limit` |
| `Permission denied (publickey).` straight from the gate (no `jaunt:` text) | the certificate is not signed by a trusted user CA, expired, or the key is not the one in the certificate | audit `gate.auth` with `outcome` and `reason` (`untrusted_ca`, `expired`, `plain_key`, ...) |
| `Permission denied (publickey).` after the gate accepted | the **agent** refused. Agent log `agent.ssh.auth` with `reason`: `login` (the login does not match `[a-z_][a-z0-9_.-]{0,31}`), `untrusted_ca` (the agent has an old trust set), `policy_denied`, `revoked`, `session_used`, `inner_login` failures `host_key_mismatch`, `refused`, `connect`, or `not_loopback` | `journalctl -u jaunt-agent`; the server's `authz.deny` when the agent asked the server |
| the web terminal shows "Access denied" | same causes as the line above; with `reason=login` in the node log the login has an upper-case letter or a character the agent does not accept | node log `agent.ssh.auth outcome=denied reason=login`; audit `terminal.denied`, `terminal.closed` |
| Console login fails after waiting a long time on the identity provider page | the login state lives 5 minutes; start again | audit `login.callback_refused`, `login.denied` with `reason: request_expired` or `unknown_state` |
| Sign-in is denied right after the provider's page, for a user who can sign in elsewhere | the provider's `email_verified` is not true and `oidc.require_verified_email` is on (the default); or the provider sends no `email`, `sub` or username claim under the configured names | audit `login.denied` with `reason: email_not_verified` or `identity_rejected`; set `oidc.require_verified_email`, `oidc.username_claim` or `oidc.scopes` ([configuration.md](configuration.md#oidc)) |
| Sign-in works but the user has no access, or `{username}` logins are refused | the groups claim is missing (the provider did not release the `groups` scope or uses another claim name), so no group role matches | `oidc.scopes` and `oidc.groups_claim`; the role list in the console under the node's access view |
| `jaunt login` prints an error about the callback or state | the redirect URI at the provider is not exactly `https://<host>/v1/login/callback`; `public_url` differs from the address in the browser | `login.denied`, `login.finish_failed` with `reason` |
| 429 from the console or the CLI | a rate limit | `http.rate_limited` |
| `jauntd` does not start | the message names the key; `cannot set up the identity provider` means the provider was not reachable or the discovery document is wrong; `no age identity for the certificate authorities` means `JAUNT_CA_KEY_FILE` is missing | `journalctl -u jauntd` |
| `jauntd` warns that the data directory or database is accessible by others | file modes | `chmod 0700 /var/lib/jauntd` |
| `jauntd` warns that the policy directory is writable | a ConfigMap mount often is; harmless when the pod is the only writer | |

Enrolment:

| Message | Cause |
|---|---|
| the code is rejected as unknown or expired | the request lives 15 minutes; start `jaunt-agent enroll` again |
| `name_taken` | a node of that name is active. Choose another name, or use `--replace` and approve: the old node is removed. After a join-token enrolment that did not finish, the half-enrolled node holds the name: see [Uses](#uses) |
| the agent refuses the server (pin mismatch) | `--ca-pin` is not the `internal-ca` value of this server; see [Internal CA pin](#internal-ca-pin) |
| `refusing to use the state directory ... it exists, is not empty and has no inner-ca.pub` from `install` | `install` ran after `enroll`; run `install` first |
| 429 on enrol | a rate limit |
| `the server refused the join token: it is unknown, expired, used up or revoked, or it does not allow this name, these labels or --replace` | the one answer the agent gets for every join-token refusal. Where to look: audit `join_token.refused` with `reason` `malformed`, `unknown`, `revoked`, `expired`, `used_up`, `name_mismatch`, `label_mismatch` or `replace_not_allowed`; the table in [When a token is refused](#when-a-token-is-refused) |
| `cannot use the join token file: ...` | the agent checked the file before it sent anything: `cannot open`, `is a symbolic link`, `is not a regular file`, `is not owned by the user running the agent`, `has mode 0644; it must be 0600 or stricter`, `does not hold a join token` (also for a file over 4 KiB). Where to look: the file rules in [Put the token on the node](#2-put-the-token-on-the-node); under `sudo` the owner must be root |
| the agent cannot connect with TLS errors | `agent_endpoint` host does not resolve to the control host from the node, or port 8444 is blocked, or a load balancer terminates TLS (it must pass it through) |

Agent log lines (structured JSON; `target` `jaunt::agent`):

| Line | Meaning |
|---|---|
| `the agent now accepts SSH sessions` | the trust set and the host certificate are loaded |
| `loaded the user CA trust set` | the agent read the server's trust set (after `add-next`, `retire`, start) |
| `loading the user CA trust set failed; the previous set stays in use` | the API was not reachable; the agent retries with backoff |
| `reloading the user CA trust set after a refused certificate failed` | a user presented a certificate of a CA the agent does not know (the "wake" on `untrusted_ca`) and the reload failed |
| `agent.ssh.refused` `reason=trust_not_loaded` or `host_certificate_not_loaded` | a stream arrived before the agent was ready; transient |
| `agent.clock_skew` | the node clock differs from the server's by more than a minute: fix time synchronisation; certificates are refused as not yet valid or expired |
| `the server no longer knows this node (node_removed)` | the node was removed or revoked; enrol again |
| `agent.ssh.auth`, `agent.ssh.end`, `agent.ssh.recording_*` | one per session; `end` has `reason` (`unauthenticated`, ...) |

Clock skew: certificates start two minutes in the past and end at their time; a node or laptop clock more than a couple of minutes off produces `not_yet_valid` or `expired` refusals. DNS: the console name, `agent_endpoint` and the gate name must resolve from where they are used. Node names (`<node>.<ssh_suffix>`) are resolved by the gate and need no DNS record.

Noise that is harmless: `gate.disconnect` with `reason: handshake_failed` appears for every TCP health check of the SSH gate port (a load balancer that opens the port and closes it without an SSH handshake). It is in the trail as a noisy event; filter it out. A `curl: (7) Failed to connect` line from a health probe during start is expected until `jauntd` listens.

## Web terminal

The console opens a shell in the browser. The browser never talks to the node: the server runs an SSH client for it through its own gate and the node's agent, so the session is authorised, recorded and audited like one from a laptop. The server sees the terminal bytes in clear text (the end-to-end property of the SSH path does not hold for the browser terminal; see [security.md](security.md)).

How it starts: the page asks for a ticket, then opens a WebSocket.

| Step | Detail |
|---|---|
| ticket | `POST /v1/web/terminal/ticket` with the session cookie and the CSRF header, body `{"node": "web-01", "login": "deploy"}`; answer `{"ticket": "...", "expires_in": 30}`. 403 `denied` if policy does not allow; 429 `limit` when the ticket table is full |
| connect | `GET /v1/web/terminal?node=web-01&login=deploy&cols=120&rows=30` as a WebSocket. Offered subprotocols: `jaunt-terminal.v1` and `jaunt-ticket.<ticket>`. The `Origin` must equal `public_url`. Columns up to 500, rows up to 200 |
| targets | `GET /v1/web/terminal/targets` lists the nodes and logins the user may open |
| frames | binary frames carry terminal bytes both ways, at most 64 KiB each. Text frames are JSON: from the browser `{"t":"resize","cols":N,"rows":N}` and `{"t":"ping"}`; from the server `{"t":"ready","session_id":"..."}`, `{"t":"exit","status":N,"signal":"..."}`, `{"t":"error","code":"..."}` and `{"t":"pong"}` |

Close codes: 1000 normal end (the shell exited, the user closed it); 1001 the server is shutting down; 1008 policy (denied, limit, session time limit, web session ended, bad message); 1009 message too big; 1011 unavailable (the connection to the node was lost, or the terminal stopped making progress for 60 seconds); 4001 revoked; 4002 idle timeout.

The terminal logs in to the node with a web certificate that the server signs for 120 seconds; it is used once at the start, and the session is not cut when it expires. The audit trail has `terminal.opened`, `terminal.closed` (with `reason`: `exit`, `client_closed`, `revoked`, `idle_timeout`, `max_duration`, `web_session_ended`, `unavailable`, `wedged`, `dead_peer`, `shutdown`, `limit`, `malformed`, `too_big`, `denied`) and `terminal.denied`.

A terminal ends when: the shell exits; the user closes the tab (the server notices a dead browser after 60 seconds without an answer to its pings); there is no input and no output for `web_terminal.idle_timeout_secs` (30 minutes); the session reaches its time limit of 12 hours; the user is revoked (4001, within about a second); the web session ends because the user signed out or the 8 hour cookie expired (1008); `jauntd` restarts. A browser that signs out on one `jauntd` instance and keeps a terminal on another is noticed within 60 seconds. Open terminals per user and in all are limited (see Limits).

Behind a reverse proxy the WebSocket upgrade and a read timeout of more than a minute must be allowed (the server sends a ping every 20 seconds), and the proxy must pass the `Origin` header and the `Sec-WebSocket-Protocol` header as one line.
