# End-to-end stand

Runs the real product the way an operator would: the `jauntd` binary (control and gate in one process), two nodes
with a real `sshd` and a real `jaunt-agent`, a fake identity provider, the `jaunt` CLI and the stock OpenSSH client.
Every scenario asserts what a user can see and what the audit trail records.

    just e2e                 # debian:13 and rockylinux:9 as the node images
    just e2e debian:13       # one image
    just e2e-rotation        # the CA rotation scenarios on debian:13, about 15 minutes
    just e2e-down            # remove the containers, the network and the volume of an aborted run

`CONTAINER_ENGINE` selects the engine (`podman` by default, `docker` on CI). `E2E_PROJECT` (default `jaunt-e2e`) is the
prefix of every container, network, volume and image tag of a run and of the run directory, so two runs (two worktrees,
or a local run next to CI) do not touch each other; `just e2e-down` takes the same variable. The published ports of
`just e2e-web` (18443, 18444) are fixed, so run only one browser run at a time. `E2E_TRANSFER_MIB` sets the size of the
files moved by scp and rsync (256 by default). `python3 e2e/run.py --help` lists `--keep`, `--only`, `--list`,
`--skip-build` and `--web`.

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

The people are `alice` (role `ops`, both nodes, forwarding on), `bob` (role `limited`, `node-a` only, no forwarding),
`carol` (no role) and `admin` (role `admins`, the web console and the admin API). The policy files are in
`e2e/fixtures/policy`, the identities of the fake IdP in `e2e/fixtures/idp-users.json`. The `browser` step of a login
is `curl` following the redirects with a cookie jar; the fake IdP completes `authorize` at once for the `login_hint`
that the script appends, and remembers the user in a cookie, so a later sign-in without a hint (`jaunt ensure`, run by
`ssh`) succeeds as long as the IdP session lives.

## The browser run

`just e2e-web` starts the same stand with the TLS edges published on `127.0.0.1:18443` and `:18444`, enrols the nodes,
signs in, opens a live session and two pending enrolments, and then runs `web-tests/e2e/real.mjs` (Playwright,
Chromium) against the real console at 380 and 1440 px: sign-in through the fake IdP, the node list, approval of a
pending enrolment through the UI, the session list, and a revocation from the UI. The browser ignores TLS errors
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
4. Recording (S21), CA rotation (S30) and the web console in a browser (S26) attach the same way: the recordings
   directory is already configured in `jauntd.yaml`, `jauntd ca ...` runs through `stand.jauntd`, and the browser
   deliverable is `just e2e-web`.
