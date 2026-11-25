# End-to-end stand

Runs the real product the way an operator would: the `jauntd` binary (control and gate in one process), two nodes
with a real `sshd` and a real `jaunt-agent`, a fake identity provider, the `jaunt` CLI and the stock OpenSSH client.
Every scenario asserts what a user can see and what the audit trail records.

    just e2e                 # debian:13 and rockylinux:9 as the node images
    just e2e debian:13       # one image
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
