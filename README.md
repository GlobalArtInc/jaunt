<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/lockup-dark.svg">
    <img src="docs/brand/lockup-light.svg" alt="Jaunt" height="64">
  </picture>
</p>

# Jaunt

Identity-aware access gateway for SSH and infrastructure, written in Rust.

Jaunt issues short-lived certificates after a single sign-on, so people reach servers without long-lived keys, bastion hosts or VPNs. Agents connect outward, so protected hosts need no inbound ports.

The logo and brand rules are in [docs/brand](docs/brand/README.md).

## Status

Jaunt runs SSH access end to end and has been exercised by an automated end-to-end stand (a real `sshd`, the OpenSSH client, a fake identity provider) on Debian 13 and Rocky Linux 9. It has no stable release yet: expect changes, back up before you upgrade, and read [docs/operations.md](docs/operations.md) before you use it for anything that matters. There is no high availability: one `jauntd` process serves one database.

What works today:

- Single sign-on with any OpenID Connect provider; the CLI and the console never see the provider's tokens.
- Short-lived OpenSSH user certificates (8 hours by default). `ssh`, `scp`, `rsync` and `sftp` work unchanged through a generated `ssh_config`.
- Agents on the nodes connect outward over TLS 1.3 with client certificates; nodes open no inbound port. The SSH session is end to end between the client and the agent: the gateway forwards bytes it cannot read.
- Enrolment of a node by a one-time code that is shown only on the node, approved in the console or with `jauntd node approve`.
- Access policy as YAML files in a directory (roles, node labels, logins, `-L` forwarding, input recording), reloaded without a restart, with `AccessTest` cases that `jaunt policy check` runs in CI.
- Recording of terminal sessions as asciicast v2 into a directory or an S3-compatible bucket, with a player and `jauntd recordings verify`.
- A web console: nodes, enrolment approval, sessions, recordings, revocations, audit log; and a terminal in the browser.
- Revocation of a user, a certificate or a node, effective within about a second, and an audit trail of JSON events.
- Rotation of the user and host certificate authorities without downtime.
- Rate limits per address, hardened systemd units, static Linux binaries for x86_64 and aarch64 and a macOS client, and a container image recipe.

Not yet:

- Kubernetes access, database access (PostgreSQL first), general TCP forwarding (only `ssh -L`, enabled per role, works today)
- local users with WebAuthn and TOTP, per-session MFA
- live session viewing and joining, access requests
- machine identities for CI, web applications, MCP servers
- high availability
- rotation of the internal certificate authority, `deny` rules, remote (`-R`) and X11 forwarding, a device-code command in the CLI, retention of recordings

## Quickstart

One control host, one node and one laptop, in about 20 minutes: [docs/quickstart.md](docs/quickstart.md). The commands in it are checked by `scripts/test-quickstart.sh`.

## Documentation

| Document | For |
|---|---|
| [docs/quickstart.md](docs/quickstart.md) | a first installation |
| [docs/install.md](docs/install.md) | downloading and verifying the binaries, installing the agent |
| [docs/configuration.md](docs/configuration.md) | every setting of `jauntd.yaml`, `agent.yaml`, the CLI and the policy files |
| [docs/operations.md](docs/operations.md) | revocation, CA rotation, recordings, backup, upgrade, limits, audit, troubleshooting, the web terminal |
| [docs/security.md](docs/security.md) | the trust model, what a compromise gives, hardening |
| [docs/architecture.md](docs/architecture.md) | how the parts fit together |
| [docs/release-process.md](docs/release-process.md) | cutting a release |
| [deploy/](deploy) | a systemd unit, example configuration and policy, a Kubernetes example |
| [e2e/README.md](e2e/README.md), [web-tests/README.md](web-tests/README.md) | the end-to-end stand and the browser tests |
| [SECURITY.md](SECURITY.md) | reporting a vulnerability |

## Goals

- Plain OpenSSH on the client side: `ssh`, `scp`, `rsync` and editors work unchanged.
- OIDC single sign-on from day one.
- Few moving parts: three small binaries (`jauntd`, `jaunt-agent`, `jaunt`) and minimal configuration.
- Access policy as code, kept in Git.
- Open formats for audit events and session recordings.

## License

MIT. See [LICENSE](LICENSE).
