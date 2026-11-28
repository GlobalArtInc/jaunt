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

Exit codes of `jauntd ca add-next|promote|retire`: 0 done, 1 error, 3 blocked by a check (nothing changed). `jd ca status` prints the state and what blocks the next step; `jd ca status --json` prints the same for scripts, with the counters and the lists of names (`behind_names`, `offline_names`, `names`). The counters are complete, the lists name at most the first 20 nodes. The running daemon notices a changed key directory within 10 seconds and tells the connected agents; each agent reads the new set after a random delay of up to 5 seconds. A command that changed keys ends with the line `applied within 10 s`; `status` and a blocked step (exit 3) do not print it. After `ca promote user-x509`, `POST /v1/certificates/x509` answers 503 `authority_unavailable` until the daemon has reloaded the keys (up to the reload interval, about 10 seconds); a slot that fails to load postpones the reload of the other slots that changed until it is fixed.

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
- `kubectl exec` and `kubectl attach` (prepared in control; recorded once the agent supports it): control accepts their recording under a child session of the Kubernetes session when the role sets `recordExec`. With a terminal it is a `.cast` like a shell; without a terminal control accepts only a metadata recording (the command, the exit status and the byte counts) and refuses terminal output for it. See [Events of Kubernetes, database and TCP sessions](#events-of-kubernetes-database-and-tcp-sessions).
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

`verify` recomputes the digests of the stored cast against the manifest. Exit 0 verified, 1 failed or not found (`no recording is stored for session ...`), 2 for an argument that is not the id of an SSH session or of a Kubernetes child session (`kx-` and 32 hexadecimal digits).

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

**Release note (audit of database sessions).** `services[].postgres.audit.max_query_bytes` now accepts at most 8192. An agent that announces more is refused with 422 `invalid_settings` for its whole announcement, so none of its new or changed services reach the approval list until its configuration is lowered.

**Release note (TLS to PostgreSQL).** A `postgres` service must now name `tls.ca_file`: TLS to the database is mandatory and the name in its certificate is always checked. An agent that still announces a `postgres` service with only `tls.server_name` gets 422 `invalid_settings` for its whole announcement from an upgraded control, and its services stay as they were approved before. Add `ca_file` to the agent configuration before upgrading control.

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
| TLS handshakes the gate terminates on `<services.domain>` (SSH and database or TCP together): 1024 at once, its own budget next to the agents' one | the connection is closed | `gate.tls.refused` with `reason: limit` |
| SSH through `<services.domain>` (ALPN `jaunt-ssh/1`) | the same `limits.ssh` and `ssh_gate.max_unauthenticated` as on `ssh_gate.listen`, shared with it per address | `gate.limited` |
| open Kubernetes streams: 32 per address, 512 per cluster; connections with a PROXY `LOCAL` header (health checks of the proxy) are not counted per address | the connection is closed without a byte, before it reaches the cluster agent | `gate.kube.stream` with `reason` `address_limit` or `cluster_limit` |
| database and TCP connections: 32 per address (counted from before the TLS handshake; PROXY `LOCAL` connections are not counted), 32 per user | the connection is closed | `gate.tls.refused` with `reason: limit` per address; `gate.svc.stream` with `reason: user_limit` per user |
| the inner ClientHello of a database or TCP connection: at most 16 KiB within 10 s after the outer handshake | the connection is closed before control is asked | `gate.svc.stream` with `reason: inner_hello` |
| a Kubernetes, database or TCP stream after one side has closed its direction: the other side has 30 s to finish; client sockets of the gate have TCP keepalive (60 s idle, every 20 s, 3 probes) | both sides are closed and every slot is released | `gate.kube.stream` or `gate.svc.stream` with `reason: half_close_timeout` |
| the gate certificate on `<services.domain>` expired because renewals kept failing | new SSH and database or TCP connections are closed instead of being shown the expired certificate; Kubernetes pass-through is not affected | `gate.tls.refused` with `reason: gate_certificate_expired`; the error log line `the gate tls certificate has expired` |
| API connections of one node (4) and of all nodes (1024) | the extra connection is refused | server log and the agent's log |
| web terminals | `max_per_user` 4, `max_total` 64, 8 tickets per web session | `terminal.denied` with `reason` `limit` or `tickets_full` |
| recording memory on the node (`recording.*`) | recording data is dropped and the session is marked incomplete | agent log `agent.ssh.recording_dropped`; session `recording_incomplete: true` |
| Kubernetes, database and TCP connections that reach an agent (fixed in the agent): 64 unfinished TLS handshakes per service, 10 s for the handshake and 10 s more for the first protocol step, 32 connections per user and service, 512 connections per service, 10 s for the answer of control | the stream is closed; a stream that names a service the agent does not serve, or an SNI that does not name that service, is closed before the agent sends a byte | agent log `kube.tls.refused`, `db.tls.refused` or `tcp.tls.refused` with `reason` and `suppressed` (one line per kind and reason a minute) |
| HTTP of a Kubernetes connection on the agent (fixed): request headers at most 64 KiB (HTTP/1.1 head, HTTP/2 header list), 128 concurrent HTTP/2 streams per connection, an idle HTTP/1.1 connection is closed after 60 s, HTTP/2 pings every 30 s with 20 s to answer; 60 s for the response head of the API server, except for watches and `logs --follow` (their head comes with the first event or log line, so they wait without a limit); bodies are streamed with HTTP/2 windows of 128 KiB per stream and no limit on their length (watches and `logs -f` last until the client, the API server or the session ends), but a response the client accepts nothing of for 60 s, and a request body the client stops sending for 60 s while the API server waits, lose that stream; at most 256 requests in flight per user (all connections together) and 128 per connection (a request holds its place until its response body ends); towards the API server at most 16 connections of 100 streams each, with a connection window of 100 x 128 KiB so that stalled streams never block the others of the connection, 60 s to wait for a free stream, 10 s to connect, and no TLS session resumption (every connection checks the API server certificate again). Paths must be canonical: a trailing slash, an empty or dot segment, an encoded slash, backslash or NUL get 400, so clients that ask for `/version/` or `/api/v1/` get 400. Requests that ask for a protocol switch (`Upgrade`, exec, attach, port-forward) get 403 until the recorded exec path is available | a header block over the limit gets 431 (HTTP/2: 431 or the connection is closed); a slow head gets 504; a request that found no free stream to the API server for 60 s gets 503 with `Retry-After: 1`; requests over the per-user or per-connection limit get 429 with `Retry-After: 1`; a client that stops sending its request body for 60 s gets 408; a stalled stream is reset (HTTP/1.1: the connection is closed) and its slot is freed; every refusal is a Kubernetes `Status` | the client's error; agent log `a request to the Kubernetes API server failed; the client got 502` (at most once a minute) |
| TCP sessions on the agent (fixed in the agent): 256 at once per service; 10 s to connect to the address the agent configuration declares for the service (the client never names an address), with `TCP_NODELAY` and TCP keepalive on that connection (60 s idle, every 20 s, 3 probes); a host name in the address is resolved by the system resolver at every connection, so a dead AAAA record can use up the whole 10 s; after 5 failed connections in a row to one service (refused, timed out or unable to set the socket options), its new sessions are refused for 5 s and the next failure starts another 5 s. Failures are counted when a connection attempt finishes, so up to 256 attempts can already be in flight before the pause starts, and when the pause ends every new session tries to connect again, so a burst of sessions can connect at the same moment; no bytes in either direction for `tcp.idle_timeout_secs` of the service (default 3600, at most 86 400), also after one side has closed its direction; after one side closes its direction the other side has 30 s to finish; data is relayed in 16 KiB pieces and never stored | the session is closed and the agent reports `service_end` (`upstream_error` for a refusal or a failed connection, `idle_timeout`, `closed`); a refused session is closed before the agent connects | audit `tcp.session.end` with `reason` `closed`, `half_close_timeout` (the 30 s after a half-close ran out), `idle_timeout`, `max_duration`, `cancelled`, `upstream_error`, `client_error`, `service_limit` or `upstream_unavailable`, and `bytes_up`, `bytes_down`, `duration_ms` (never the content or the address); agent log `a TCP session was refused before the agent connected to the service` and `connecting to a TCP service failed; the session is closed` (each at most once a minute per service and reason, with `suppressed`) |
| length of one Kubernetes, database or TCP session on the agent: the time control grants, at most 24 hours | when the session is cancelled or reaches its granted time, the agent asks its handler to stop (Kubernetes: running responses, watches included, end cleanly, HTTP/2 gets a GOAWAY and TLS a close_notify) and closes the connection at the latest 1 s later; the end reported to control and the `reason` of `kube.session.end` are the same. The 24-hour cap is a safety backstop in the agent; it does not replace the deadlines control sets and enforces | agent reports `service_end` with `outcome: max_duration` |
| PostgreSQL connections on the agent (fixed): the startup message at most 10 KiB and 64 parameters, sent within the 10 s of the first protocol step (the startup rules refuse earlier: at most 16 parameters and 4096 bytes of them); at most one `SSLRequest` and one `GSSENCRequest` before it (each answered `N`: the stream is already encrypted end to end); 10 s to connect to the database and finish TLS, 10 s more for the database to accept the session; a `Query` streams through up to 64 MiB, a `Parse` and the other small messages are read whole up to 1 MiB, `Bind` and `CopyData` stream up to 64 MiB; 10 cancel requests a minute per user (then one every 6 s); the database connection is closed within 5 s after the client leaves | a refused startup message gets `FATAL 08P01`, a denied session `FATAL 28000 access denied`, a database that cannot be reached, does not answer in time or shows an untrusted certificate `FATAL 08006 the Jaunt service is not available`, a database that asks for a password `FATAL 28000` with a hint to configure the `cert` method, a refusal by the database its own SQLSTATE with a generic text; a message over its size, a malformed message or a message out of place ends the session (`client_too_large`, `client_malformed`, `client_unexpected_message`); a function call (`F`) gets `ERROR 0A000` and ends the session, so psql's `\lo_import` and the other large object functions of libpq do not work through Jaunt; cancel requests over the limit, for an unknown pair or for a session of another user are dropped without an answer | agent log `the database session cannot start` with the reason; audit `db.protocol_error` (`reason: password_requested` and the protocol problems) and `db.error` |
| recording uploads and sizes on the server (`recordings.*`) | the upload is refused | audit `recording.rejected` with `reason` |
| audit events of Kubernetes, database and TCP sessions on the agent (fixed): a queue of 4096 events or 4 MiB, sent in batches of 256 events, 256 KiB or 1 s, whichever comes first; failed sends are repeated with a wait that grows from 1 s to 30 s (a `Retry-After` from control is kept between 1 s and 5 minutes); 2 s for the audit events of a session to reach control before the agent reports the end of the session; a control without the route is asked again after 5 s, then less often up to every 5 minutes, and at every new tunnel connection | a full queue drops noisy events first and lifecycle events only when nothing else is left; the drops are counted per session and reported to control, which marks the session | audit `agent.events.dropped` with `reason: agent_queue`; session `audit_incomplete: true`; agent log `sending audit events to the control plane failed` (at most once a minute) |
| `POST /v1/agent/events` on control (fixed): at most 256 events and 256 KiB per request, 50 requests a second per node (checked before the body is parsed and before the database is read), at most 16 `db.query` events per request cut to fit; per session in any hour 10 000 noisy events, 5000 `kube.exec.*` and 20 `db.protocol_error`, one `*.session.start` and one `*.session.end`; per node `*.session.start`/`*.session.end`, other lifecycle events and `session.audit_incomplete`, each with a burst of `min(200, 500, 100 respectively, pool burst / 4)` and a rate of `min(50, 100, 20 a second respectively, pool rate / 2)` (32 each and 50, 50 and 20 a second with the default queue); for all agents together a burst of `max(audit.queue / 4, 64)` (256 by default) refilled at 200 a second, half of it for `*.session.start`/`*.session.end` (100 a second) and half for the other lifecycle events and `session.audit_incomplete` (100 a second); at most 64 new session flags per request | 429 with `Retry-After`; a body over 256 KiB is 413; a batch with more than 256 events is 400; a batch that names a session that is not an authorized Kubernetes, database or TCP session of this node is 400 with the offending session ids (at most 64), and nothing of it is written; events over a limit, and events of a session that ended more than 5 minutes ago, are dropped one by one; a session flag over the per-request limit and a `session.audit_incomplete` over its limit wait for the sweep of waiting marks (every 5 seconds, at most 256 flags a pass) | audit `agent.events.refused` and `agent.events.dropped` (each at most once per node, reason and 10 s, with `suppressed`); session `audit_incomplete: true` and one `session.audit_incomplete` |
| `POST /v1/agent/sessions/child` on control, a `kubectl exec` or `attach` inside a Kubernetes session (fixed): 30 requests a second per node after a burst of 60 (checked before the body is parsed and before the database is read), at most 64 live child sessions per Kubernetes session and 512 per node | 429 `rate_limited` with `Retry-After`; 400 `invalid` (bad body, namespace, pod or container name); 404 `unknown_parent` (no such session on this node); 409 `not_kube`, `parent_ended` (also for a revoked user or a Kubernetes session past its time) or `too_many_children` | audit `session.child.refused` with the precise `reason` (at most once per node, reason and 10 s, with `suppressed`) |

Noisy events are the connection-level and flood-driven ones (the `(noisy)` rows in the [Audit](#audit) table). Sixteen of them carry a `suppressed` field: the first occurrence is logged and later ones are counted into it (`recording.rejected`, `login.callback_refused`, `http.rate_limited`, `http.connection_limited`, `http.client_ip_header_ignored`, `gate.limited`, `agent.limited`, `gate.tls.refused`, `gate.kube.stream`, `gate.svc.stream`, `terminal.denied`, `admin.signed_request_refused`, `host_user.refused`, `token.used`, `token.refused` and `agent.events.dropped`, which counts per node and `reason` in 10 s; the critical `agent.events.refused` and `session.child.refused` are held back the same way). `gate.tls.refused` and the refusals in `gate.kube.stream` and `gate.svc.stream` count each `reason` on its own, so a flood of one reason never hides the first event of another; a stream that was opened writes its `closed` event every time. The other twelve have no such field and are written one by one: `login.device.code_failed`, `gate.connect`, `gate.session_refused`, `gate.disconnect`, `agent.rejected`, `join_token.refused`, `service.announce_refused`, `host_user.helper_failed`, `authz.service.deny`, `kube.request`, `db.query` and `db.error`. The three that agents send (`kube.request`, `db.query`, `db.error`) are also bounded per session by the event budget (see [Events of Kubernetes, database and TCP sessions](#events-of-kubernetes-database-and-tcp-sessions)). Noisy events wait in their own queue, a quarter of `audit.queue` (256 with the default of 1024). Critical events have their own queue and are written first, so a flood of noisy events never displaces them. When the noisy queue is full, the newest noisy events are dropped, not the old ones. The daemon logs `the noisy audit queue is full, the newest noisy events were dropped` with the number dropped, at most once a minute, and the daemon log is the only place that says so. `authz.service.deny`, the refusal of a Kubernetes, database or TCP session, is noisy as well and is written one by one without such a field, so when the noisy queue is full some of these refusals are lost from the trail; the sessions that were allowed are written as critical `session.service.*` events.

## Audit

Every event is one JSON object: `v` (schema version, 1), `id`, `type`, `time` (UTC, milliseconds), `actor` (a user id, `node:<node id>`, `system` or `anonymous`), `node`, `session_id`, `policy_hash` where they apply, and `fields`. Events go to stdout (`audit.jsonl`), to the database (`audit.database`) or to both. Under systemd, stdout is in the journal next to the human log (which starts with `{"timestamp"`):

```sh
sudo journalctl -u jauntd -o cat | grep '^{"v":1' | jq -c 'select(.type | startswith("session."))'
```

The console's Audit log page and `GET /v1/admin/audit` (permission `audit.read`, browser session) read the database. Query parameters, each at most once: `type` (a type or a prefix such as `session.`), `actor`, `node` (node id), `session`, `ref` (a reference shown to a user with a refusal: `D-` or `H-` and 8 upper-case hexadecimal digits; it finds every event written since migration 0018 that carries it, otherwise `invalid_ref`; rows written before 0018 are not found by `ref`: they have no reference column, so `H-` references of older `host_user.*` rows are not searchable, and `D-` references did not exist before it), `from` and `to` (RFC 3339 UTC, `from` before `to`), `limit` (default 50, at most 200) and `cursor` (from `next_cursor`). An unknown parameter is an error `unknown_parameter`. The answer is `{"events": [...], "next_cursor": "..."}`.

The 111 types and their fields (generated from `crates/jaunt-audit/src/spec.rs`; text fields are truncated to a fixed length; `email` is never stored):

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
| `cert.x509.issued` | user | `serial`, `parent_serial`, `valid_before`, `client_addr` |
| `cert.service.issued` | node | `service_id`, `kind`, `name`, `serial`, `valid_before`; envelope: node |
| `cert.service.refused` | node | `service_id`, `reason`; envelope: node |
| `cert.gate.issued` | system | `serial`, `valid_before` |
| `cert.db_client.issued` | user | `serial`, `db_user`, `valid_before`; envelope: node, session_id |
| `admin.csrf_denied` | user | `reason` |
| `admin.enrolment.looked_up` | user | `outcome`, `enrollment_id` |
| `admin.signed_request` | user | `decision`, `reason`, `serial`, `method`, `path`, `client_addr` |
| `admin.signed_request_refused` (noisy) | anonymous | `reason`, `client_addr`, `suppressed` |
| `authz.deny` | user | `phase`, `reason`, `permission`, `serial`, `node_name`, `login`, `client_addr`; envelope: node, session_id, policy_hash |
| `session.routed` | user | `serial`, `node_name`, `client_addr`; envelope: node, session_id, policy_hash |
| `session.start` | user | `serial`, `login`, `pty`, `port_forwarding`, `record_input`, `max_duration_secs`, `roles`, `client_addr`; envelope: node, session_id, policy_hash |
| `session.end` | user | `serial`, `login`, `exit_status`, `bytes_in`, `bytes_out`, `recording_incomplete`, `outcome`, `late`, `state_before`, `kind`, `service`; envelope: node, session_id |
| `session.end_rejected` | node | `reason`; envelope: node, session_id |
| `session.terminated` | user | `serial`, `reason`, `by`; envelope: node, session_id |
| `authz.service.deny` (noisy) | user | `phase`, `kind`, `service`, `reason`, `serial`, `login`, `db_name`, `client_addr`; envelope: node, session_id, policy_hash |
| `session.service.routed` | user | `kind`, `service`, `serial`, `client_addr`; envelope: node, session_id, policy_hash |
| `session.service.start` | user | `kind`, `service`, `serial`, `roles`, `login`, `db_name`, `users`, `groups`, `record_exec`, `record_input`, `max_duration_secs`, `db_client_serial`, `client_addr`; envelope: node, session_id, policy_hash |
| `session.service.end` | user | `serial`, `kind`, `outcome`, `bytes_in`, `bytes_out`, `late`; envelope: node, session_id |
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
| `token.created` | user | `jat_id`, `name`, `scope`, `cidrs`, `expires_at` |
| `token.revoked` | user | `jat_id`, `name`, `creator` |
| `token.used` (noisy) | user | `jat_id`, `permission`, `decision`, `reason`, `client_addr`, `suppressed` |
| `token.refused` (noisy) | anonymous | `reason`, `client_addr`, `suppressed` |
| `join_token.revoked` | user | `join_id`, `uses_left` |
| `node.ssh_changed` | node | `ssh_enabled`; envelope: node |
| `service.announce_refused` (noisy) | node | `reason`; envelope: node |
| `service.requested` | node | `service_id`, `kind`, `name`, `revision`, `labels`; envelope: node |
| `service.superseded` | node | `service_id`, `kind`, `name`, `revision`; envelope: node |
| `service.withdrawn` | node | `service_id`, `kind`, `name`, `revision`, `state`; envelope: node |
| `service.reannounced` | node | `service_id`, `kind`, `name`, `revision`, `state`; envelope: node |
| `service.approved` | user | `service_id`, `kind`, `name`, `revision`, `labels`, `labels_overridden`, `replaced_id`; envelope: node |
| `service.rejected` | user | `service_id`, `kind`, `name`, `revision`; envelope: node |
| `service.removed` | user | `service_id`, `kind`, `name`, `revision`; envelope: node |
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
| `gate.tls.refused` (noisy) | anonymous | `client` (the address from the PROXY header when there is one, IPv6 per /64), `reason` (`proxy_untrusted`, `proxy_malformed`, `proxy_timeout`, `limit`, `hello_too_large`, `hello_timeout`, `bad_hello`, `no_sni`, `unknown_sni`, `alpn_unsupported`, `unsupported_class`, `client_certificate`, `tls_handshake`, `gate_certificate_expired`), `suppressed` |
| `gate.kube.stream` (noisy) | anonymous | `outcome` (`refused` or `closed`), `reason` (when refused: `address_limit`, `cluster_limit`, `unknown_cluster`, `control_unavailable`, `node_not_connected`, `kind_not_served`, `agent_unavailable`; when closed: `closed`, `failed`, `shutdown`, `aborted`, `half_close_timeout`), `service` (the cluster), `client_addr`, `bytes_up`, `bytes_down`, `duration_ms`, `suppressed` (refusals only, per `reason`); envelope: node, session_id |
| `gate.svc.stream` (noisy) | user | `outcome` (`refused` or `closed`), `reason` (when refused: `user_limit`, `inner_hello`, `service_name`, `denied`, `control_unavailable`, `node_not_connected`, `kind_not_served`, `agent_unavailable`; when closed: `closed`, `failed`, `shutdown`, `aborted`, `half_close_timeout`), `kind` (`db` or `tcp`), `service`, `serial`, `client_addr`, `bytes_up`, `bytes_down`, `duration_ms`, `suppressed` (refusals only, per `reason`); envelope: node, session_id |
| `ca.key.added` | user | `kind`, `fp` |
| `ca.key.promoted` | user | `kind`, `fp`, `forced`, `blocked`, `nodes_behind`, `old_unexpired` |
| `ca.key.retired` | user | `kind`, `fp`, `forced`, `blocked`, `old_unexpired`, `nodes_old` |
| `ca.reloaded` | system | `kind`, `trust_id`, `active_fp` |
| `ca.reload.failed` | system | `reason` |
| `terminal.opened` | user | `node`, `login`, `serial`, `client_addr`; envelope: node, session_id |
| `terminal.closed` | user | `reason`, `bytes_in`, `bytes_out`, `duration_ms`, `serial`, `ref`; envelope: node, session_id |
| `terminal.denied` (noisy) | user | `reason`, `node`, `login`, `client_addr`, `suppressed`, `ref` |
| `host_user.created` | user | `login`, `uid`, `home`, `groups`, `ref`; envelope: node, session_id |
| `host_user.refused` (noisy) | user | `login`, `reason`, `ref`, `suppressed`; envelope: node, session_id |
| `host_user.helper_failed` (noisy) | user | `login`, `stage`, `exit_status`, `ref`; envelope: node, session_id |
| `kube.session.start` | user | `service`, `user`, `groups`, `client_addr`, `observed_at`; envelope: node, session_id |
| `kube.session.end` | user | `service`, `requests_read`, `requests_write`, `requests_watch`, `requests_exec`, `bytes_up`, `bytes_down`, `reason`, `observed_at`; envelope: node, session_id |
| `kube.request` (noisy) | user | `verb`, `api_group`, `api_version`, `resource`, `subresource`, `namespace`, `name`, `status`, `duration_ms`, `observed_at`; envelope: node, session_id |
| `kube.exec.start` | user | `namespace`, `pod`, `container`, `tty`, `exit_status`, `bytes`, `observed_at`; envelope: node, session_id |
| `kube.exec.end` | user | `namespace`, `pod`, `container`, `tty`, `exit_status`, `bytes`, `observed_at`; envelope: node, session_id |
| `db.session.start` | user | `service`, `db_user`, `db_name`, `application_name`, `server`, `observed_at`; envelope: node, session_id |
| `db.query` (noisy) | user | `text` (at most 8 KiB as sent; masked when the statement may carry a credential, see [Databases](#databases-postgresql); `[withheld]` when it looks like a credential; cut to the longest prefix that keeps the stored event within 16 KiB, with `truncated: true`; absent in `digest` mode), `truncated`, `sha256` and `length` (of the full query text; both absent when the statement may carry a credential), `protocol`, `command`, `observed_at`; envelope: node, session_id |
| `db.error` (noisy) | user | `sqlstate`, `error_message`, `observed_at`; envelope: node, session_id |
| `db.session.end` | user | `service`, `queries`, `errors`, `bytes`, `duration_ms`, `observed_at`; envelope: node, session_id |
| `db.protocol_error` | user | `reason`, `observed_at`; envelope: node, session_id |
| `tcp.session.start` | user | `service`, `client_addr`, `bytes_up`, `bytes_down`, `duration_ms`, `reason`, `observed_at`; envelope: node, session_id |
| `tcp.session.end` | user | `service`, `client_addr`, `bytes_up`, `bytes_down`, `duration_ms`, `reason`, `observed_at`; envelope: node, session_id |
| `agent.events.dropped` (noisy) | node | `count`, `reason` (`invalid`, `budget`, `duplicate`, `node_ceiling`, `agents_ceiling`, `expired` or `agent_queue`), `suppressed`; envelope: node, session_id |
| `agent.events.refused` | node | `reason` (`malformed`, `too_large`, `too_many_events`, `too_many_reports`, `session_id_shape`, `unknown_session`, `foreign_session`, `ssh_session`, `not_authorized`), `events`, `sessions`, `suppressed`; envelope: node |
| `session.audit_incomplete` | user | `dropped_total`; envelope: node, session_id |
| `session.child.created` | user | `parent_session_id`, `kind` (`exec` or `attach`), `service`, `namespace`, `pod`, `container`, `tty`, `record`, `record_input`, `serial`; envelope: node, session_id (the child) |
| `session.child.refused` | node | `reason` (`malformed`, `too_large`, `invalid_parent`, `invalid_name`, `rate_limited`, `unknown_parent`, `foreign_parent`, `not_authorized`, `not_kube`, `nested_parent`, `parent_ended`, `parent_expired`, `revoked`, `parent_cap`, `node_cap`), `parent_session_id`, `suppressed`; envelope: node |

### Events of Kubernetes, database and TCP sessions

The agent that serves a Kubernetes cluster, a database or a TCP service sends the events of its sessions (`kube.*`, `db.*`, `tcp.*`) to `POST /v1/agent/events` over its node certificate. Control decides who the event is about: the actor (the user), the node and the session come from the session row, never from the agent, so an agent cannot write an event for another user, another node or an SSH session. A batch that names a session that is unknown, belongs to another node, is an SSH session or was never authorized is refused whole: nothing of it is written, the answer is 400 `{"error": "invalid_session", "sessions": [...]}` with at most 64 of the ids the agent sent, and the agent drops the events of those sessions (it counts them in its own log) and sends the rest again. A session of this node that ended more than 5 minutes ago does not refuse the batch: its events and drop counts are dropped one by one (`agent.events.dropped` with `reason: expired`) and the session is marked.

Within an accepted batch each event is checked on its own: its name must belong to the kind of its session (`kube.*` for a Kubernetes session, and so on), and its fields must be fields of that event with the right type (the actor, the node, the session, `service`, `observed_at` and `policy_hash` cannot be set by the agent). A text of a noisy event that is longer than its limit drops the event; a text of a lifecycle event is cut to its limit instead, so that the start of a session is recorded even when a client sent an over-long name. A text that looks like a credential (a PEM block, `bearer` and a token, an API token of Jaunt) is stored as `[withheld]`, in `db.query` with `sha256` and `truncated` kept; the answer counts these in `withheld`. A `db.query` whose stored form would exceed 16 KiB keeps the longest prefix of its text that fits and gets `truncated: true`; any other event that large is dropped. The answer is `{"accepted": n, "dropped": m, "withheld": k}`; an agent takes a success answer without `accepted` and `dropped` as a bad answer and sends the batch again. The time of the event is the time control received it; `observed_at` is the agent's own time in milliseconds, kept within the start of the session and one minute ahead of control's clock.

`db.query` and `db.error` carry what users typed and what the database answered, so they are written to the trail under the logging target `jaunt::audit::private`. That target only keeps them out of the daemon's own human log, whatever `RUST_LOG` says (span and field filters that would reach it are left out of the filter; such a filter with a comma inside its brackets stops the daemon at start with an error saying that span and field directives for the private audit target are refused). The trail itself is not protected by it: with `audit.jsonl: stdout` (the default) the trail is printed on standard output, so query texts reach the pod log in clear; send the trail to a file or to the database only if the pod log is read by people who must not see queries.

Limits per session in any hour: 10 000 noisy events (`kube.request`, `db.query`, `db.error`), 5000 `kube.exec.start` and `kube.exec.end` together and 20 `db.protocol_error`; `*.session.start` and `*.session.end` are written once each per session, and a repeat is dropped (`reason: duplicate`). Lifecycle events and `session.audit_incomplete` go to the critical audit queue (`audit.queue`, 1024 by default), and all agents together may hand it at most a quarter of that queue at once: the agents' ceiling is `max(audit.queue / 4, 64)` events (256 by default), refilled at 200 a second. The ceiling is split into two pools so that a flood of exec events cannot take the records of sessions: `*.session.start` and `*.session.end` draw from one half (`audit.queue / 8`, 128 by default, refilled at 100 a second), the other lifecycle events and `session.audit_incomplete` from the other half (128 by default, 100 a second); a refusal by a pool is `reason: agents_ceiling`. Per node there are three allowances, so that one user's flood does not take another user's session records and one node does not take a pool: `*.session.start` and `*.session.end`, the other lifecycle events, and `session.audit_incomplete` (`reason: node_ceiling`). Each node allowance has a burst of `min(b, pool burst / 4)` and a rate of `min(r, pool rate / 2)`, where `b` and `r` are 200 and 50 a second for starts and ends, 500 and 100 a second for the other lifecycle events, and 100 and 20 a second for `session.audit_incomplete`, and the pool is the one the allowance draws from. With the default queue every node burst is 32 (a quarter of a pool of 128), starts and ends and the other lifecycle events refill at 50 a second and `session.audit_incomplete` at 20 a second. So one node takes at most a quarter of a pool at once and half of its rate over time: two nodes that flood exec events together still leave the starts and the exec events of a third node passing. An event refused by its node or by its pool takes nothing from the other. The database writer drained about 11 400 events a second in a debug build, so the sustained 200 a second is under 2 % of it. A `db.query` that has to be cut costs control the most work, so at most 16 per request are cut and the rest are dropped as invalid; an event that control has already seen is recognised by its sequence number before any of this work. An hour is counted in whole minutes, so an event is held against the limit for between 3601 and 3660 seconds; each window is 61 counters of two bytes per session and kind.

Events dropped by control or by the agent (its queue was full) are written as `agent.events.dropped`, at most once per node, `reason` and 10 seconds with the rest counted in `suppressed`, and mark the session `audit_incomplete: true` (the admin session list and `GET /v1/admin/sessions/<id>` show it). The flag is set in the session row while the request is handled, for at most 64 sessions per request; the flags of the other sessions of that request are set by the sweep of waiting marks, which runs every 5 seconds and sets at most 256 flags a pass, those waiting longest first (the sweep once a minute sets them too). The first mark of a session also writes one critical `session.audit_incomplete` with the number of events dropped so far, within the allowances above; a mark over them waits for the same 5-second sweep, which writes as many as the allowances let through: with the default queue a node's burst of 32 is full again after 5 seconds, so one node's waiting marks are written 32 every 5 seconds (2560 of them in about 7 minutes). A session that ended more than 61 minutes ago (3660 seconds) gets the flag without the event. Once the session row is marked, later drops do not write to it again.

Each event carries a sequence number that only grows within its session; the agent starts its numbers from its clock (a thousand per millisecond), so a restarted agent does not reuse one as long as the clock of the host does not go back. Control keeps the highest number it has seen for each session in memory, from the first event until 6 minutes after the session ended, and ignores an event at or below it, so a batch the agent sends again after a lost answer is not written twice. The numbers, the hourly windows and the marks that wait for the sweep are not stored: a restart of control forgets them, so after a restart a batch that was written but not acknowledged can be written a second time, every limit starts again, a waiting flag is not set and a waiting `session.audit_incomplete` is not written (a flag already set in the row stays). An acknowledged event is handed to the audit queue, which is written in the background: if control stops before the queue is written, acknowledged events can be lost (at most once). A batch the agent sends again after a lost answer may repeat its count of dropped events in `agent.events.dropped`; the mark of the session is written once. The numbers and windows are kept for at most 65 536 sessions; when the table is full the least recently used session is forgotten and the daemon log says so. A single stored audit event is limited to 16 KiB; an event over it is not stored, the rest of its batch is, and the daemon log says how many were skipped.

An agent whose control does not have this route (an older version answers 404) logs one warning, counts the events of its sessions per session instead of queueing them, and tries the route again after 5 seconds, then less often up to every 5 minutes, and at every new connection of its tunnel; when control answers, it sends the counts, which mark the sessions. An agent remembers a session that control refused by name for an hour or until the session ends, and drops its events meanwhile. Control does not write these events with an older agent: older agents do not serve Kubernetes, database or TCP sessions.

Each `kubectl exec` and `kubectl attach` is a child session of the Kubernetes session it runs in (control is ready for it; the agent half is not released yet). The agent asks for it with `POST /v1/agent/sessions/child` (`parent_session_id`, `namespace`, `pod`, `container`, `tty`, `kind`) and control answers `{"session_id": "kx-...", "record": ..., "record_input": ...}`: control makes the id from 128 random bits, the agent never chooses it. Control accepts the request only for a live Kubernetes session of the asking node that is not itself a child, whose user, certificate and node are not revoked and whose time has not run out. The child is a row of its own in the session list with the user, roles and decision of its parent, `target` set to `namespace/pod/container` (cut to 320 characters) and `parent_session_id` naming the parent (both in `GET /v1/admin/sessions` and `GET /v1/admin/sessions/<id>`). Whether it is recorded comes from the grant of the parent (`recordExec`, `recordInput` of the matching roles at the time the parent was opened), the same for `exec` and `attach`; the command line goes only into the recording, never into the request or the row. The agent sends `kube.exec.start` and `kube.exec.end` under the child id, uploads the recording under the child id only when `record` is true (control refuses the upload otherwise, and for any other Kubernetes, database or TCP session; the manifest of a child carries an empty `login`; a child without a terminal takes only a metadata recording with the command, the exit status and the byte counts, and control refuses terminal output for it), and reports the end through `/v1/agent/service/end`. When the parent ends, control ends its live children at once: with the same reason when the parent was cut (revocation, node removal, a policy change, an administrator, its time), and with `parent_ended` when the agent reported the parent's end; the agent's own end report for such a child is still taken once, and a repeat of it changes nothing. Only the parent is named in the order to the agent, which closes the parent's connection and with it the commands in it. An administrator terminates the parent; terminating a child is answered `409 child_session`. A periodic sweep also ends any live child whose parent is no longer live. An agent must tell these refusals from a missing route by the JSON `error` code: control answers `404 {"error": "unknown_parent"}` for a parent it does not know, while a 404 or 405 without that body means that control is older and has no such route. The session store is SQLite only, and the limits on children and the check that the parent is still live rely on SQLite running one write at a time; a PostgreSQL store would need `SELECT ... FOR UPDATE` on the parent row, because under READ COMMITTED two children can pass a limit of one and a child can be inserted under a parent that has just ended.

What is **not** audited: terminal output and keystrokes (that is the recording); individual SFTP file operations; the contents of commands run with `ssh host command` beyond what the metadata recording holds; reads of the console pages other than recordings; and the agent-side events listed under `agent.ssh.*` (they are in the agent's log, not in the server's trail). The `jauntd` subcommands that change state (`revoke`, `node approve`, `node rm`, `join-token create`, `join-token rm`, `ca ...`) are audited; `node list`, `join-token list`, `ca status` and `recordings verify` are not. With `audit.database: false` the console and the API see nothing; with `audit.jsonl: off` the trail exists only in the database, which an administrator with access to the host can alter.

## Databases (PostgreSQL)

The agent logs in to PostgreSQL with a client certificate that control issues for each session: the common name is the database role, it is valid for 5 minutes and signed by the `db-client` authority. Passwords are never used.

**On the database** (once per server):

1. Turn on TLS with a server certificate (`ssl = on`, `ssl_cert_file`, `ssl_key_file`).
2. Put the `db-client` roots into the file named by `ssl_ca_file`: every `<data_dir>/ca/db-client/*.root.der` on the `jauntd` host (not the ones under `retired/`), each converted with `openssl x509 -inform der -in <file>`, one after another in one file. During a rotation of `db-client` both roots are there.
3. In `pg_hba.conf` let the agent in by certificate only from its own address: `hostssl all all <agent address>/32 cert`. No other line may accept this CA, otherwise anyone who can reach the database with a certificate of this authority gets in.
4. Reload PostgreSQL (`SELECT pg_reload_conf()`); `ssl_ca_file` is read only at a reload.

**On the agent**, `postgres.tls.ca_file` names the CA of the database certificate and is required: TLS to the database is mandatory, and the agent trusts this file only, never the system roots. The name in the database certificate is always checked: `server_name` when it is set, otherwise the host part of `address` (a DNS name or an IP address). There is no mode that checks the chain alone, because any holder of a certificate from the same CA could then pose as the database. TLS 1.2 and 1.3 are accepted.

What the agent does with a session: it answers `N` to `SSLRequest` and `GSSENCRequest`, refuses `replication` and any startup parameter outside `application_name`, `client_encoding` (UTF-8 only), `DateStyle`, `TimeZone`, `IntervalStyle`, `extra_float_digits` and `search_path`, logs in as the role and database that control granted, and relays the protocol. It writes `db.query` for every simple query and every `Parse` (the text, at most `max_query_bytes` and never more than 8 KiB, cut on a character boundary, with the SHA-256 and the length of the whole text), `db.error` for every error the database sends (its SQLSTATE and at most 512 bytes of its message), and `db.session.start` and `db.session.end`. Bind values are not written by the agent; the exception is the message of a database error, which can quote a value (`invalid input syntax for type integer: "abc"`). `audit.queries: digest` writes the SHA-256, the length and the command class without the text.

A statement that may carry a credential is written masked, whatever the setting. The agent reads the whole statement, also past the part it keeps, and looks for the words `password`, `sslpassword`, `pgpassword` and `passwd` (in any case, as whole words, also inside strings, quoted names and comments, after decoding the escapes of `E'...'`, `U&'...'` and `U&"..."`) and for a URI with a user and password (`scheme://user:secret@host`). Such a statement is written with every string replaced by `'?'` (also `E'...'`, `U&'...'`, `$tag$...$tag$`, national and bit strings), every comment removed and the spaces collapsed, cut to the usual limit with `truncated`, and without SHA-256 and without length (both would help to guess a short password). The shape stays visible: `DROP TABLE payments -- password` is written as `DROP TABLE payments`, `ALTER ROLE app PASSWORD 'x'` as `ALTER ROLE app PASSWORD '?'`. Words outside strings are kept, so a password typed without quotes stays visible. The message of the error that answers such a statement is left out: for a simple query until its `ReadyForQuery`; for `Parse`, `Bind` and `Execute` until the next `ReadyForQuery` after any use of that prepared statement or its portal, named or unnamed (the agent remembers up to 1024 names of each kind, then treats every later `Bind` and `Execute` as one that may carry a credential). What cannot be found: a credential that a `DO` block or a function puts together at run time (`'pass' || 'word'`, `chr()`), a `UESCAPE` clause that changes the escape character of a Unicode string, and a statement sent in the same write right after `SET standard_conforming_strings = off` (the agent follows the setting from the moment the database reports it).

A cancel request is passed to the database, over its own TLS connection with the trust of the session, only for a live session of the same user through this agent; anything else is dropped, and the client sees the same closed connection either way. When the session is cancelled or reaches its time limit, the agent sends `Terminate` to the database and closes the connection within 500 ms. The session key stays in memory only; the copy that the TLS library keeps for signing during the session is not wiped when the session ends.

## Troubleshooting

The gate and the agent answer a refusal with a generic text on purpose, so that an attacker learns nothing. The operator finds the cause in the audit trail and the logs.

| What the user sees | Real causes | Where to look |
|---|---|---|
| `channel 0: open failed: connect failed: jaunt: access denied or node unavailable`, or `Received disconnect ... 2222:11: jaunt: access denied or node unavailable` | no role allows this user on this node and login; the user or serial or node is revoked; the node is offline; the name is wrong | audit `authz.deny` (`phase`, `reason`: `policy_denied`, `revoked`, `node_unavailable`, ...), `gate.forward` `outcome` |
| `jaunt: your certificate has expired, run jaunt login` | the user certificate ended | `jaunt login`; `jaunt status` shows the time left |
| `jaunt: too many open sessions` | 8 streams for the same user and node | `gate.forward` `outcome: limit` |
| `Permission denied (publickey).` straight from the gate (no `jaunt:` text) | the certificate is not signed by a trusted user CA, expired, or the key is not the one in the certificate | audit `gate.auth` with `outcome` and `reason` (`untrusted_ca`, `expired`, `plain_key`, ...) |
| `Permission denied (publickey).` after the gate accepted | the **agent** refused. Agent log `agent.ssh.auth` with `reason`: `no_account`, `account_refused` or `account_failed` (account creation, see [Account creation at first login](#account-creation-at-first-login)), `login` (the login does not match `[a-z_][a-z0-9_.-]{0,31}`), `untrusted_ca` (the agent has an old trust set), `policy_denied`, `revoked`, `session_used`, `inner_login` failures `host_key_mismatch`, `refused`, `connect`, or `not_loopback` | `journalctl -u jaunt-agent`; the server's `authz.deny` when the agent asked the server |
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
| `kube.tls.refused`, `db.tls.refused`, `tcp.tls.refused` (target `jaunt::audit`) | the agent closed a Kubernetes, database or TCP connection before it asked control. `reason`: `unknown_service` or `not_served` (the service is not approved for this node, or the agent has no handler for its kind), `sni_mismatch` or `no_sni` (the TLS server name is not `<service>.<kube\|db\|tcp>.<services.domain>` of the service in the stream), `certificate_unavailable` (control did not issue the server certificate of the service), `handshake_limit`, `service_limit`, `user_limit`, `handshake_timeout`, `no_certificate`, `no_trust` (no user X.509 roots are loaded), `untrusted` (another CA, a node certificate), `expired`, `not_yet_valid` (more than 60 s ahead of the node clock), `user_uri`, `key_type`, `not_client_auth`, `serial`, `malformed`, `not_tls`, `handshake_failed`. `suppressed` counts the same kind and reason held back during the last minute |
| `no user X.509 roots are loaded` | the control plane serves no user X.509 roots (or is older than the third trust version): every Kubernetes, database and TCP client certificate is refused; logged at most once a minute. Roots that have already expired are not loaded. If a control plane that served the third trust version stops serving it, the agent drops its user X.509 roots at the next read and asks for the third version again after each reconnection |
| `the approved services of this node changed` | the agent read `GET /v1/agent/services` (when its tunnel connects, after each accepted announcement and about once a minute) and now serves the listed Kubernetes, database and TCP services that it declares and has a handler for; `served` lists the stream kinds the tunnel accepts |
| `the control plane does not list the approved services of nodes` | the server is older than the agent; the agent serves SSH only and asks again when its tunnel reconnects |
| `reading the approved services of this node failed` | the agent keeps the set it read last and tries again about a minute later |
| `obtaining the server certificate of a service failed` | control did not issue the certificate of an approved service; the agent keeps the previous certificate until it expires and retries with backoff (5 s up to 10 minutes) |
| `a TCP session was refused before the agent connected to the service` | `reason` `service_limit` (256 sessions of the service are open) or `upstream_unavailable` (the last 5 connections to the address failed; new sessions wait 5 s); `suppressed` counts the refusals of the same service and reason held back during the last minute |
| `connecting to a TCP service failed; the session is closed` | the address declared for the service did not answer: `stage` `connect` (with `error_kind`, for example `connection refused`), `connect_timeout` (10 s) or `socket_options` (`TCP_NODELAY` or keepalive could not be set); `failures` counts the failures in a row and `paused` says whether new sessions now wait 5 s; at most one line a minute per service, `suppressed` counts the rest; the address itself is not logged, look it up in the agent configuration by `service` |
| `a TCP session names a service that has no address in the agent configuration; the session is closed` | control routed a session of a TCP service that this agent does not declare with an address; it should not happen, report it; at most one line a minute, `suppressed` counts the rest |
| `a TCP session ended` (debug) | one per session with `reason`, `bytes_up`, `bytes_down` and `duration_ms` |
| `a request to the Kubernetes API server failed; the client got 502` | the agent could not reach the API server of its cluster. `kind`: `connect` (no TCP connection), `connect_timeout` (10 s), `handshake` (TLS failed, for example the API server certificate is not signed by the CA in `ca.crt`, or it offers no HTTP/2 in ALPN and refuses the handshake), `not_http2` (the API server agreed to no application protocol), `http2`, `tls_config`, `ca_read` or `ca_empty` (the CA file of the service account cannot be read or holds no usable certificate), `request` (the request failed after it was sent), `pool_full` or `pool_closed` (no connection to the API server could be used; should not happen). At most once a minute, with `suppressed`; the client sees only a generic 502 `Status` |
| `reading the service account token for the Kubernetes API server failed` | the token file of the service account cannot be read, is empty or holds bytes that cannot be sent in a header. The agent keeps using the token it read last (requests get 502 if it never read one). The file is looked at no more than once a second, read again whenever its size or modification time changes and at least every 60 s. At most once a minute, with `suppressed` and `kept_previous`. The token stays in memory as the header the agent sends; that copy is not wiped |
| `reading the CA file of the Kubernetes API server failed; new connections keep the CA read before` | `ca.crt` changed but cannot be read or holds no usable certificate. The CA file is read again when its size or modification time changes, at the next new connection to the API server; open connections are not affected. Certificates in it that cannot be parsed are skipped (`some certificates in the CA file of the Kubernetes API server cannot be used`) as long as one is usable |
| `the access decision of a Kubernetes session cannot be applied; every request of the connection is refused` (error) | control allowed a Kubernetes session with a user or group that is not a plain Kubernetes name, starts with `system:`, more than 64 users or 64 groups, or no user. Every request of the connection gets 403 and nothing reaches the cluster. `reason`: `no_user`, `invalid_user`, `too_many_users`, `system_user`, `invalid_group`, `system_group`, `too_many_groups`, `invalid_session` |

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

## Account creation at first login

By default a user can log in only as an account that already exists on the node. A node can create the account at the first login instead: the policy still decides who may use which login, and the node decides, with its own rules, whether it will create that account. The operator of the node turns this on; the control plane cannot.

Two programs take part. The agent (`jaunt-agent`, the unprivileged user `jaunt`) notices that the account is missing and asks. The helper (`jaunt-host-users`, root) is started by systemd for each request on the socket `/run/jaunt/host-users.sock` (owner `root`, group `jaunt`, mode 0660), checks the rules in `/etc/jaunt/agent.yaml` itself and runs `useradd`. The helper can create accounts. It cannot change or delete one, and it never creates a login that the rules refuse. [security.md](security.md#account-creation-and-the-root-helper) states what a compromised agent can still do. Supported nodes: Debian 12 and 13, Ubuntu 22.04 and 24.04 and Rocky Linux 9, all with systemd. Alpine is not supported: the installer needs systemd, and BusyBox `adduser` differs from `useradd`.

### Enable it

Put `jaunt-agent` and `jaunt-host-users` together in a directory that only root can change, and install with the flag. The helper must be named `jaunt-host-users` and sit in the directory of the `--binary` path:

```sh
sudo install -d -m 0755 -o root -g root /opt/jaunt/bin
sudo install -m 0755 -o root -g root jaunt-agent jaunt-host-users /opt/jaunt/bin/
sudo /opt/jaunt/bin/jaunt-agent install --dry-run --create-accounts --binary /opt/jaunt/bin/jaunt-agent
sudo /opt/jaunt/bin/jaunt-agent install --create-accounts --binary /opt/jaunt/bin/jaunt-agent
```

With the `.deb` package both binaries are in `/usr/bin` and the second command is `sudo jaunt-agent install --create-accounts --binary /usr/bin/jaunt-agent`. The default `--binary /usr/local/bin/jaunt-agent` is refused on Debian and Ubuntu: `/usr/local` and `/usr/local/bin` are `root:staff` with mode 2775 there, so members of `staff` could replace a binary that root runs. Use the package, use `/opt/jaunt/bin`, or tighten the two directories with `chmod g-w,o-w` when that is safe on your system. The installer refuses, and changes nothing, when the helper is missing, is a link, belongs to another user, is writable by group or others, carries a setuid or setgid bit, or sits below a directory that is not owned by root or is writable by group or others. The error names the path. These checks happen at install time only: after you change the permissions of the helper or of a directory above it, and after every upgrade of the binaries, run `jaunt-agent install --create-accounts` again.

The installer writes the `host_users` section with `enabled: true` and the defaults of [configuration.md](configuration.md#host_users), the units `/etc/systemd/system/jaunt-host-users.socket` and `jaunt-host-users@.service` (the helper runs under `ProtectSystem=strict`, a private `/tmp` and network namespace, `NoNewPrivileges`, a seccomp filter of `@system-service` and only the capabilities `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER` and `CAP_FSETID`), enables the socket and restarts a running agent once. With `--no-service` it writes the files and prints the two `systemctl` commands to run. On a node that is already enrolled run it the same way; the enrolment is not touched.

It also warns about things that would stop the feature from working. Read the warnings:

| Warning | Meaning |
|---|---|
| `sshd -T` shows that AllowUsers is set | the accounts that the agent creates are not in `AllowUsers`, so `sshd` refuses them after the account exists. Add each one, or switch to `AllowGroups` and put a group from `groups` in it |
| `sshd -T` shows that AllowGroups is set | add to it a group listed in `groups` of the section |
| `/etc/nsswitch.conf` takes users from a directory service | creation stays off unless `allow_with_directory: true` is set; see below |
| `useradd`, `userdel` or `getent` not found | the helper refuses to create accounts until they are installed |
| `home_base` does not exist | create it (owned by root, not writable by group or others), or the helper service cannot start |
| SELinux is Enforcing | see the note below |

The section belongs to the operator. `install --create-accounts` keeps every value you wrote in it (it only sets `enabled: true`), and an install without the flag keeps it as it is. The installer does rewrite the rest of the managed `agent.yaml`: another top-level key that you added by hand, for example `recording:`, is lost when you run `install` again, so keep such keys in mind or put them back afterwards. Edit the section in a text editor, keep the file owned by root with mode 0644, and restart the agent. The helper reads the file again for every request; the agent reads it only when it starts, so a change of the uid range, `names`, `groups` or `enabled` needs `sudo systemctl restart jaunt-agent` to take effect on the agent side. If the section is wrong the agent and the helper do not create accounts at all (see "A broken section" below).

### Turn it off

Set `enabled: false` in the section and restart the agent. `install` without the flag never turns creation off. `jaunt-agent uninstall` removes the two helper units and, together with the managed `agent.yaml`, the section; it keeps every created account, their home directories, `/var/lib/jaunt-host-users` and the `jaunt-host-users` binary, and prints how many accounts it kept.

### What a user sees

The agent looks the login up with `getent passwd`. An existing account (including one made by an earlier request or by hand) is used as before and the helper is not asked. Only a missing account starts the creation, and only if the section is on, valid and the helper listens. The first login then takes a little longer: the account is created, then the login goes on.

| Case | Command line (`ssh`) | Web terminal |
|---|---|---|
| account created | the shell opens | a banner "Creating your account ..." while it runs, then "Account created." with the home directory (dismissable) above the terminal; the console never writes into the terminal area |
| creation off or not available | `Permission denied (publickey).` | "There is no account <login> on <node>." with the reference |
| the node refuses the login (name rule, reserved name, existing group of that name, existing home directory, `max_users`, no free uid) | `Permission denied (publickey).` | "Your account could not be created." with the reference |
| the helper failed, or the rate limit of 5 creations a minute was reached | `Permission denied (publickey).` | "The node could not create your account. Try again later." with the reference |
| the account exists but `sshd` refuses it (`AllowUsers`, `AllowGroups`, `DenyUsers`, PAM) | `Permission denied (publickey).` | the generic denial of the console |

On the command line the user never learns why: the text is the same generic refusal as for every other denial. A refusal by the helper is remembered by the agent for 60 seconds: the same login again in that time is refused at once, with the same reference, and the helper is not asked again. The name rules (`names`, reserved names) are checked by the agent first, so such a refusal never reaches the helper, leaves no line in the helper journal and gets a new reference for every attempt.

The reference `H-` plus eight hexadecimal digits identifies one attempt and is the key to the records of one attempt. The agent makes it for each attempt and gives it to the helper and to the control plane. Every attempt that reaches the helper has the reference in all three places below. Two cases have fewer: a refusal by the node rules that the agent checks first (name rule, reserved name) never reaches the helper, so the helper journal has no line; and a login that finds no account while creation is off or unavailable (`agent.host_user.missing`) has no `host_user.*` event in the control audit:

| Where | How to find it |
|---|---|
| agent log | `journalctl -u jaunt-agent -o cat \| grep H-1A2B3C4D`: the lines `agent.host_user.created`, `agent.host_user.refused`, `agent.host_user.helper_failed` and `agent.host_user.missing`, with `session_id` and `login`. The line `agent.ssh.auth` with `outcome=denied` and `reason` `no_account`, `account_refused` or `account_failed` has the same `session_id` |
| helper journal | `journalctl -t jaunt-host-users -o cat \| grep H-1A2B3C4D`: one line per request with `ref`, `session`, `login`, `outcome` (`created`, `exists`, `refused`, `failed`, `disabled`), `reason` or `stage`, `uid`, the exit status of `useradd` and up to 256 bytes of its error output. Only the helper journal has the details of a failure |
| control audit | `host_user.created`, `host_user.refused` and `host_user.helper_failed` carry `ref`. Query `GET /v1/admin/audit?type=host_user.` ([Audit](#audit)) and look at the field. Refusals are limited to a burst of 5 and then 1 every 10 seconds per node, and then counted in `suppressed`; `terminal.denied` for the web terminal has the reasons `no_account`, `account_refused` and `account_failed` |

When several first logins for the same new name arrive together, the agent makes the account once and logs one `agent.host_user.created`. The control audit can hold several `host_user.created` events for that one account with the same `ref`: one for each session that waited for the shared attempt (one to three in the test with eight parallel logins).

### Accounts the helper made

```sh
sudo jaunt-host-users list
sudo jaunt-host-users list --json
```

Columns: `LOGIN`, `STATE`, `UID`, `ACCOUNT`, `CREATED (UTC)`, `REF`, `SESSION`, `HOME`. `STATE` is `active` for a normal account, `pending` for a creation in progress and `unconfirmed` for one that ended in a state the helper could not verify; unconfirmed accounts count against `max_users` and the helper logs them at ERROR level. `ACCOUNT` compares the record with the system: `present`, `missing` (deleted since), `other_uid` (the name now belongs to another uid: the helper no longer treats it as its own), `unbound` (the record has no uid yet and the name exists) or `unknown` (the lookup was not possible). An account that carries a record and the same uid is the helper's; `jaunt` is written in its comment field for people only.

Accounts are never deleted automatically: not at logout, not on a timer, not at `uninstall`. To remove one, with its home directory and mail:

```sh
sudo jaunt-host-users list
sudo userdel --remove <login>
```

Check first that nobody uses the account and that the home directory holds nothing you need. The next request makes the helper forget the record (it logs `forgotten=<login>`) and the account stops counting against `max_users`. A login that was removed can be created again.

### A broken section

The agent reads `agent.yaml` strictly. An unknown key in `host_users`, or a value of the wrong type (`uid_min: abc`, `max_users: -1`, `groups: ops` instead of a list, `home_mode: 750` without quotes), makes it stop when it loads the file: `jaunt-agent run` prints `... is not a valid agent configuration: unknown field ... at line N` (or the type error) and exits with status 1, so the service does not start and `systemctl status jaunt-agent` shows that text. A value of the right type that is out of range or inconsistent (a range smaller than `max_users`, `uid_min` below 1000, `home_mode` of another string, a group that does not exist, a shell that is not in `/etc/shells`) does not stop the agent: it logs the warning `agent.host_user.config_invalid` with the reason, does not announce account creation, and every missing account is refused as `no_account`; the helper answers `disabled` for the same section. Fix the file and restart the agent.

### What the agent announces, and the probe

When its tunnel connects, the agent tells the control plane whether the node creates accounts, and repeats it every minute. The announcement is `true` only if the section is enabled and valid, the helper socket exists and accepts a connection, and the node takes no users from a directory. The console shows the marker "Creates accounts" on such a node only while that agent connection lasts. To check the socket the agent connects to it once for each tunnel connection and closes it without a request. That is one start of the helper unit that ends with exit status 1: `systemctl status` of the instance would show `failed`, the journal holds one warning `outcome=failed stage=request` per tunnel connection, and `CollectMode=inactive-or-failed` removes the instance at once, so no failed units pile up. The socket is probed only then, not every minute: if it appears after the agent connected, the node stays "does not create" until the agent reconnects, so restart the agent after you install the helper (the installer does it for a running agent). After a restart of the agent the marker can appear up to a minute late.

### Time budget of the first login

The agent waits up to 2 seconds for `getent`, 2 seconds for each report to the control plane and 11 seconds for the helper. The helper reads the request for at most 5 seconds, waits at most 2 seconds for its state lock (answers `failed` with the stage `busy` otherwise), gives `useradd` 5 seconds and the rollback with `userdel` 2 seconds more, and ends after at most 30 seconds (`RuntimeMaxSec`). The 45 seconds are the agent's own limit for authenticating a login (`AGENT_AUTH_DEADLINE`); when it runs out, the login ends as the generic refusal. The console's web terminal has a separate, outer bound of 50 seconds (`SETUP_TIMEOUT`) for the whole setup, so the agent's limit is the one that normally ends a slow first login. A first login that takes longer than that ends as the generic refusal; the account may still appear, and the next login finds it.

### Details that matter on a real node

- **UsePAM.** The account gets the password field `*`: password login is impossible, but `sshd` does not treat the account as locked. A locked hash (`!`) would be refused with `UsePAM no`; with `UsePAM yes` the PAM `account` modules decide. Both settings were tested on Debian 13 and Rocky Linux 9. Rocky's `sshd` prints a warning that `UsePAM no` is not supported there.
- **sshd rules still apply.** `AllowUsers`, `AllowGroups`, `DenyUsers`, `DenyGroups`, `/etc/security/access.conf` and PAM can refuse an account that was just created. The user sees the generic refusal, the account stays (within `max_users`), and `sshd` says why in its log (`not allowed because not listed in AllowUsers`).
- **Network directories.** With `passwd: ... sss`, `ldap`, `nis` or `winbind` in `/etc/nsswitch.conf` (for `sss` only while `/etc/sssd/sssd.conf` exists), creation is off and the helper answers `disabled`. With `allow_with_directory: true` the account is created. What the test showed about `sss_cache`: on Debian 13 (systemd 257, `sssd-common` and `sssd-tools` installed, `sssd` itself failed to start in the test container) the helper journal held `sss_cache` errors, `Unable to open config database [/var/lib/sss/db/config.ldb]`, while `useradd` exited 0 and the account was created; the same `sss_cache` command run by root outside the unit exited 0. The message says the SSSD database could not be opened from inside the unit; it does not tell whether `ProtectSystem=strict` or the missing database caused it, and a node with a running SSSD was not tested. On Rocky Linux 9 the same test showed no error. Making `/var/lib/sss` writable for the helper unit with a drop-in was not tested.
- **SELinux.** In containers SELinux is off and the label of the home directory could not be checked. On a node where it is Enforcing, create the first account and run `ls -Zd /home/<login>`: `useradd` sets the label, and the helper does not touch contexts. The installer prints this reminder.
- **Home directories on NFS or autofs.** `useradd --create-home` fails there; set another `home_base`.
- **Account and group numbers.** `useradd` chooses the uid itself within `uid_min` to `uid_max`, and the private group gets a number from the same range. A range without a free id ends as `refused` with the reason `uid_range`.
- **Failures in the middle.** If `useradd` fails after it made the account, the helper rolls back only what it made itself (account, group, home) and logs it (`rollback=removed`). Anything else becomes `unconfirmed`.
