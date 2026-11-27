# End-to-end stand

Runs the real product the way an operator would: the `jauntd` binary (control and gate in one process), two nodes
with a real `sshd` and a real `jaunt-agent`, a fake identity provider, the `jaunt` CLI and the stock OpenSSH client.
Every scenario asserts what a user can see and what the audit trail records.

    just e2e                 # debian:13 and rockylinux:9 as the node images
    just e2e debian:13       # one image
    just e2e-rotation        # the CA rotation scenarios on debian:13, about 15 minutes
    just e2e-systemd         # account creation on a node with systemd as PID 1, debian:13 and rockylinux:9
    just e2e-down            # remove the containers, the network and the volume of an aborted run

`CONTAINER_ENGINE` selects the engine (`podman` by default, `docker` on CI). `E2E_PROJECT` (default `jaunt-e2e`) is the
prefix of every container, network, volume and image tag of a run and of the run directory, so two runs (two worktrees,
or a local run next to CI) do not touch each other; `just e2e-down` takes the same variable. The published ports of
`just e2e-web` (18443, 18444) are fixed, so run only one browser run at a time. `E2E_TRANSFER_MIB` sets the size of the
files moved by scp and rsync (256 by default). `python3 e2e/run.py --help` lists `--keep`, `--only`, `--list`,
`--skip-build`, `--web`, `--rotation` and `--systemd`.

## How it works

`just e2e` builds the Linux binaries with `scripts/linux-build.sh`, the same mechanism as `just ssh-containers`
(`target/installer-linux/release`), builds one image per node base from `e2e/container/Containerfile` and then starts:

| container | role |
|---|---|
| `jaunt-e2e-idp` | `jaunt-fake-idp` (crates/jaunt-fake-idp, a dev-only crate that is never shipped) |
| `jaunt-e2e-edge-web`, `jaunt-e2e-edge-idp` | TLS terminators (`socat`) for `https://jaunt.e2e.test` and `https://idp.e2e.test` |
| `jaunt-e2e-jauntd` | `jauntd run` as uid 65532: control, agents' listener and the SSH gate |
| `jaunt-e2e-client` | OpenSSH client, `jaunt` CLI, users `alice`, `bob`, `carol`, each with an ssh-agent |
| `jaunt-e2e-node-a`, `jaunt-e2e-node-b` | `sshd`, `jaunt-agent` as the unprivileged user `jaunt`, login `deploy` |

The TLS certificates are made by `e2e/container/mkcerts.sh` for every run and never leave `target/e2e/run`; the CA key
is deleted right after signing. The Linux binaries are built as the invoking user (`--user`, with `CARGO_HOME` in `target/cargo-home`) on rootful docker,
so `target/` stays writable for the host scripts; podman and rootless docker map the container root to the user already.
The `jaunt` CLI and `jaunt-agent enrol` trust only the WebPKI roots, so on the client
and on the nodes a loopback `socat` forwards `127.0.0.1` to the plain control port, which both accept for loopback.

The people are `alice` (role `ops`, both nodes, forwarding on, `recordInput` off), `bob` (role `limited`, `node-a` only,
no forwarding), `carol` (no role), `dave` (role `audited`, both nodes, `recordInput` on), `admin` (role `admins`, the web
console and the admin API with every permission) and `viewer` (role `session-viewers`, only `sessions.read`, for the
refusals of the recording endpoints) and `operator` (role `terminal-admins`: `nodes.approve`, `sessions.read`, `sessions.terminate`, `audit.read` and the login `deploy` on both nodes, for the terminal workspace run). The policy files are in
`e2e/fixtures/policy`, the identities of the fake IdP in `e2e/fixtures/idp-users.json`. The `browser` step of a login
is `curl` following the redirects with a cookie jar; the fake IdP completes `authorize` at once for the `login_hint`
that the script appends, and remembers the user in a cookie, so a later sign-in without a hint (`jaunt ensure`, run by
`ssh`) succeeds as long as the IdP session lives.

## Recording scenarios

`scenarios/recording.py` drives interactive sessions through a pseudo-terminal (`stand/interactive.py`) and checks what
the server stored: the strict asciicast v2 reader (`stand/cast.py`), the manifest, `jauntd recordings verify`, the
permissions of the two endpoints, the input rule both ways with a unique secret typed with echo off, metadata-only
recordings (exec without a PTY, scp, sftp), hostile escape sequences and the `recording.viewed` rule.
`scenarios/recording_faults.py` cuts the network of `node-a` (`network disconnect`) for `OUTAGE_SECS` in the middle of a long output,
floods three sessions into an agent that is limited to 1 MiB of recording memory, and turns `recordings.dir` off and on.
The helpers that fetch a cast byte for byte (`engine cp` out of the client, never through a text pipe), find the stored
files in the jauntd volume and read the logs are in `stand/recordings.py`.

Policy confirmed for these scenarios: `ssh -t host bash` (an exec with a PTY) is recorded as a cast, so it cannot be used
to escape recording; an exec without a PTY, scp and sftp leave a metadata-only recording.

### What the recording scenarios cannot prove

- A header-less incomplete cast is never produced here: the overflow step waits until every session shows `receiving`
  (its first chunk, with the cast header, is on the server) before the flood. Without that wait the header chunk can be
  dropped under the memory budget and the stored file has no header; the stand does not pin that product finding.
- The 10-minute pause of the agent after the server answered 404 is observed (a note in the step), not asserted.
- The 24 hour retry cap and the per-session queue cap are not reachable end to end: a single flood is held at about 1 MiB
  by the SSH channel window and never reaches the queue limit. Only the agent-wide memory budget shared by several
  sessions trips, which is why the step floods three sessions at once.
- Persistence of queued recordings across an agent restart is not covered: the agent is restarted between steps, never
  with a recording still waiting for upload.
- Docker, the engine of the CI job, was never run locally for these scenarios (podman only); the semantics of
  `network disconnect` and `network connect --alias` differ between the engines, which is why the outage is verified.

### The network outage

`OUTAGE_SECS` is `TUNNEL_KEEPALIVE_INTERVAL_SECS` (20, `Keepalive::default` in `crates/jaunt-tunnel/src/options.rs`) plus
`TUNNEL_KEEPALIVE_TIMEOUT_SECS` (10) plus `DETECTION_MARGIN_SECS` (30): 60 s. The ping is sent 20 s after the last
answer and waits 10 s, so the gate drops a silent tunnel up to 30 s after the cut, and an outage shorter than that can
leave the established TCP connection unharmed, so no break would happen at all.
After every outage `require_tunnel_break` reads the audit trail from a marker taken just before the cut and fails with
`the tunnel did not break on this engine` unless `agent.disconnected` with the tunnel ALPN appears for the node, then
waits for the matching `agent.connected`. A client session that outlives a verified break is a note, not a failure: the
property under test is that the recording completes whole and matches what the client saw.

## Account creation scenarios

`scenarios/host_users.py` (with the helpers in `host_users_kit.py`) proves account creation at first login on both nodes of the stand with the real stack: real `sshd`, the real agent, the real `jaunt-host-users` binary, real `useradd`. The node containers have no systemd as PID 1, so the helper is started by `systemd-socket-activate --accept --inetd` from the systemd package: that gives the helper what the unit gives it, a fresh process for each connection with the connected socket as standard input, so `SO_PEERCRED` shows the real client (a `socat` pair would not). The socket is `root:jaunt 0660` in `/run/jaunt`, the helper log is `/var/log/jaunt-host-users.log` (standard error of the helper, `<6>INFO ...` lines, plus the launcher's `Communication attempt` line for each connection, which the scenarios count as contacts). The node is set up with the real `jaunt-agent install --create-accounts --no-service` from `/opt/jaunt/bin`, where both binaries belong to root, and the section is then edited the way an operator would. Run it with the scenarios it builds on:

    python3 e2e/run.py debian:13 --only enrol --only logins --only host_users

What it checks, in order: the installer output and the written units; the socket owner and mode; creation off (the default) refuses with the generic denial and never contacts the helper; creation on, with the agent probing the helper once per tunnel connection; the first login and the second login with `UsePAM yes` on `node-a` and `UsePAM no` on `node-b`, with the uid in range, the home mode, `jaunt-host-users list`, the helper journal, the agent audit and the control audit; refusals by the node rules (reserved name, name rule) that never reach the helper; refusals by the helper (group collision, existing home, full quota, no free uid, the sixth creation within a minute), each with its reference found in the agent log and the helper journal, and the repeat within 60 seconds that does not call the helper again; eight parallel first logins of one name; an agent restarted while `useradd` is held by a wrapper; `AllowUsers` blocking a created account with the installer's warning and the section surviving a reinstall; a semantic error in the section (creation off with a warning) and an unknown key (the agent stops at load). The wrapper scripts replace `/usr/sbin/useradd` for the time of one step and are put back in a `finally`.

The reference is checked in the three places: the agent audit lines `agent.host_user.*` (JSON in `/tmp/agent*.log`), the helper journal line with the same `ref=`, and the control audit events `host_user.*` (found by `type=host_user.` and the `ref` field; the audit API has no `ref` filter). The agent announces `creates_accounts` to the control plane; after a restart the flag can appear only on the next announcement a minute later, so the steps that need it wait up to 90 seconds and note a wait longer than 15 seconds.

`just e2e-web` adds one step after the console run: `web-tests/e2e/accounts.mjs` (Chromium, 380 and 1440 px, user `erin` of the role `onboarding`, the admin for the node cards) checks the marker "Creates accounts" on the node card and the picker of `node-a` and not on `node-b`, the creating banner (a wrapper delays `useradd` by 3 seconds so that it can be seen), the created banner with the home directory, that nothing of the console is written into the terminal area, and the refusal banners with their reference for a reserved name, a group collision and a node that does not create accounts. `e2e/scenarios/host_users_web.py` then checks each reference and session against the agent log, the helper journal and the control audit (`host_user.*`, `terminal.denied`).

`just e2e-web` then adds `web-tests/e2e/workspace.mjs` (Chromium, 380 and 1440 px, the jauntd of the stand runs with `web_terminal.idle_timeout_secs: 180`). `operator` pins `node-b` and sees it first after a reload, opens `deploy@node-a` through quick open and checks the connection steps, the `progress` and `ready` frame order, the ready header (session id, latency number after the first pong, recording state) and the `ready.recording` value, opens a second tab and switches with Ctrl+Alt+PageUp and PageDown, closes a live tab through its confirmation (Keep open first), finds the recent pairs, fills the user's limit of 4, opens a fifth terminal from a second browser context and reads the refusal with its numbers and its `D-XXXXXXXX` reference, checks the same refusal as raw HTTP, then on the Sessions page checks the Origin column and both Origin filters and terminates a live terminal with the confirmation, and finds the terminated state in the terminal tab. `dave` leaves one terminal idle in a third context: the warning arrives about 60 s later, Keep open sends one `active` frame and clears it, and some `pong` carries `node_ms`. `e2e/scenarios/terminal_web.py` then checks the audit: `terminal.closed` with reason `client_closed` for each closed tab, `GET /v1/admin/audit?ref=` for each reference (one `terminal.denied` with reason `limit`), `session.terminated` with its reason and `terminal.closed` with reason `terminated`, and the origin `web` and end reason `terminated` on the session detail.

### The systemd stand

`python3 e2e/run.py --systemd debian:13 rockylinux:9` (`just e2e-systemd`) starts one node whose PID 1 is systemd (`--systemd=always`, as in `scripts/test-quickstart.sh`) and runs `scenarios/host_users_systemd.py`: the installer enables the units for real; the socket is activated by the agent's probe; one probe and one `failed` helper instance per tunnel connection, collected at once (`CollectMode=inactive-or-failed`), so `systemctl --failed` stays empty; failed requests leave nothing behind; a user outside the group `jaunt` cannot open the socket; the first login creates the account under the helper unit (a wrapper around `useradd` dumps what the sandbox looks like: `NoNewPrivs`, the seccomp filter, the capability bounding set `0x1b`, a read-only `/usr`, an empty private `/tmp`, and the network namespace where the container allows it) and fills the home from `/etc/skel`; `systemd-analyze security` scores of the helper and the agent unit are printed as notes; with `passwd: files sss` and an `sssd.conf` the agent does not announce the capability and the helper answers `disabled`; and with `allow_with_directory: true` the `sss_cache` result under `ProtectSystem=strict` is printed. Podman only: the `--systemd=always` flag does not exist in docker, so CI does not run this stand.

Known limit: systemd inside a podman container cannot create a network namespace, so `PrivateNetwork=yes` is ignored on Debian 13 in this stand (the journal says so and the step notes it); it is enforced on Rocky Linux 9, where the step proves it. SELinux is off in containers, so the labels of the home directories are not checked.

## The browser run

`just e2e-web` starts the same stand with the TLS edges published on `127.0.0.1:18443` and `:18444`, enrols the nodes,
signs in, opens a live session and two pending enrolments, and then runs `web-tests/e2e/real.mjs` (Playwright,
Chromium) against the real console at 380 and 1440 px: sign-in through the fake IdP, the node list, approval of a
pending enrolment through the UI, the session list, and a revocation from the UI. Before each width it signs in as
`dave` and opens a web terminal on `node-a` as `deploy` through the Terminal screen: `echo hello-$((6*7))` must show
`hello-42`, `seq 1 200000 | tail -n 1` must show `200000`, a window resize must change `stty size` to the size the page
shows, and `exit` must show the ended state with exit status 0. The runner then checks that each of these sessions has a
complete recording whose cast contains `hello-42` and exactly one `terminal.opened` (with `client_addr`) and one
`terminal.closed` event. `web-tests/e2e/recording.mjs` opens
the session detail of a recorded session, presses "Watch recording", reads the typed text from the terminal buffer
(the terminal draws on a canvas, so the script captures the `Terminal` instance with an init script), checks that the page
does not overflow horizontally and that the canvas holds painted text, and fails on any CSP violation, on any console
error and on any HTTP response of 400 or above except 401 and 429 (the 401 is the console probing for a session before
sign-in; both scripts ignore only these two statuses, and the browser's own "Failed to load resource" console line is
dropped because the response check names the URL). The browser ignores TLS errors
(`ignoreHTTPSErrors`) only because the TLS edge of this stand uses a certificate of a throw-away test CA. Screenshots go to
`target/e2e/screenshots/`. Prepare once with `cd web-tests && npm ci && npx playwright install chromium`.

## The CA rotation run

`just e2e-rotation` (`python3 e2e/run.py --rotation debian:13`) runs the rotation scenarios on their own stand with
a 120 s user certificate lifetime and three nodes: `node-a` (the current agent), `node-b` (the current agent, enrolled
but started only during the rotation, so the server counts it as offline) and `node-c` (an agent of an earlier
commit, `22aea38`, which only speaks the first trust version). `e2e/build-old-agent.sh` builds that agent once from
`git archive` of the pinned commit into `target/e2e/old-agent/<full sha>/jaunt-agent`. The commit must be present in
the clone, so CI needs the full history. A step of `rotation_setup` checks by sha256 that `node-c` runs that binary
and `node-a` the current one. `--only` on a rotation scenario also runs every scenario before it, because they build
on each other.

The scenarios, in order: `rotation_setup`, `rotation_user` (user CA A to B), `rotation_host` (host CA A to B),
`rotation_force` (a node that cannot read the trust set, `promote --force`, `retire --force`) and `rotation_audit`.
Every wait is a named step of `Kit.wait` with a deadline that polls `jauntd ca status --json`, the audit or an ssh
probe; the final step prints each wait with the time it took.

### Deadlines

A deadline is the worst case of the product plus the cost of one poll, not the typical time. The watcher of the
daemon runs every 10 s, an agent adds up to 5 s of jitter before it reads a trust set it was told about, and a
poll is one command that can take a few seconds on a loaded machine.

| wait | deadline | why |
|---|---|---|
| live nodes report the new trust id after `add-next` | 25 s | tick 10 s + agent jitter 5 s + polls. The brief said 15 s, which a correct product can miss; this is a deliberate deviation |
| `ca.reloaded` after `promote`, `retire`, `add-next` | 30 s | tick 10 s + audit flush + poll |
| the second `add-next` leaves only `node-b` behind | 35 s | tick + jitter + polls |
| the gate presents the new host key | 30 s | tick 10 s + re-issue + one ssh probe per poll |
| `node-a` and `node-b` renew their host certificates | 420 s | trust tick + jitter 5 s + renewal jitter up to 300 s + poll |
| certificates signed by the old key expire | 240 s | certificate lifetime 120 s |
| `node-c` presents the new key after `enroll --replace` | 90 s | |
| `node-b` loads the trust set after the block is lifted | 90 s | agent retry backoff is capped at 60 s |
| `node-b` connections are reset by the firewall rule | 90 s | agent keepalives, 20 s to 30 s |

### Sessions

An open session ends when the certificate it was opened with expires (the gate disconnects it), so with a 120 s
lifetime one session cannot last the whole run. `Kit.keep_session` opens a session before every change and
`Kit.check_session` accepts only two states: still counting, or ended by the expiry of its certificate no earlier than
that expiry. `rotation_force` restarts the daemon with a 15 minute certificate lifetime first: its forced steps need a
certificate that is still valid after several slow commands, and nothing in them waits for an expiry. The restart
keeps the keys, the database and the enrolments of the agents.

### The stale agent

The step needs `NET_ADMIN` and `iptables` on `node-b`: an `iptables` string match refuses new connections that offer
the agent API protocol (ALPN `jaunt-agent/1`) while the tunnel protocol still connects, and a short blanket reset
removes the existing API connection first. The first step of `rotation_setup` adds and removes both rules and names
the missing kernel module (`xt_string`, `ipt_REJECT`) or capability if the host cannot do it.

What it proves: `promote` is refused with exit 3 naming `node-b`, `node-b` refuses a certificate signed by the new
key with `Permission denied (publickey)` and logs a new `untrusted_ca` denial, and `node-b` loads the trust set within
the deadline without a restart once the block is lifted.

### What this stand does not prove

- The refusal-triggered re-read of the agent (the `wake: untrusted_ca` path of `trust.rs`) is not exercised. While the
  API is blocked the agent stays inside its retry loop, which ignores refusals, and `node-b` recovers through the
  announce retry with backoff. That path is covered only by the agent unit test in `crates/jaunt-agent/src/trust/tests.rs`.
- Pre-rotation certificates with a `NULL` signer (the database is new), the 20 minute rule that makes an agent
  offline (`node-b` is offline only because it never started), the renewal of an old-protocol agent at half of its
  lifetime (see below), the internal CA and the age key of a Kubernetes Secret.
- The gate refusing a certificate of a retired key is shown only with `retire --force`: after a normal `retire` every
  such certificate has expired and the SSH agent has dropped its key.
- One sample of the renewal jitter per run.

### Notes for the owner

- The brief's "K1 keeps working until `retire host`" contradicts the design. `promote host` waits until every
  certificate issued before `add-next host` has expired, so a real client with only the old host key cannot exist at
  promote time. The K1 of this stand is artificial: the old `known_hosts` plus a fresh certificate. The stand shows that
  it works before `promote` and that the gate itself refuses it afterwards (`Host key verification failed`, before
  authentication); that is the reason for the promote check.
- Product finding: an old-protocol node leaves the host-retire block only by re-enrolment (`enroll --replace`). A
  restart does not renew its certificate, because it renews at half of seven days. Until then `retire host` stays
  refused naming the node.
- The first real run of the `e2e-rotation` CI job is unverified: it has only been run locally. The job needs the
  `xt_string` kernel module on the runner and the full git history; the first step of the scenario reports a missing
  module plainly.

## Reading a failed run

Each step prints `PASS` or `FAIL` with its time and the reason. The logs of every container and the node-side files
(`sshd.log`, `agent.log`, `enroll.log`) are written to `target/e2e/logs/<image>/`; CI uploads them. `--keep` leaves the
containers running: `podman exec -it jaunt-e2e-client bash`, `podman logs jaunt-e2e-jauntd` (human log on stderr, audit
JSONL on stdout), then `just e2e-down`.

## Adding a scenario

1. Create `e2e/scenarios/<name>.py` with `def run(stand, report)`; every check is a `with report.step("...") as step:`
   block that calls `step.expect(condition, message)`.
2. Add it to `SCENARIOS` in `e2e/scenarios/__init__.py`; scenarios run in that order and share the logged-in users.
3. Useful helpers on `stand`: `login(user)`, `ssh(user, node, command)`, `ssh_stream(...)` for long sessions,
   `api(method, path, body)` for the admin API with the admin web session, `audit_events()`, `jauntd(...)` for the
   server CLI, `on_node(...)`, `restart_jauntd(cert_ttl_secs)`. `marker = stand.marker()` at the start and
   `audit.after(stand.audit_events(), marker)` (module `stand.audit`) scope audit assertions to one scenario.
4. CA rotation (S30) and further recording cases attach the same way: `jauntd ca ...` runs through `stand.jauntd`,
   interactive sessions through `stand.interactive.Interactive`, and the browser deliverable is `just e2e-web`.
