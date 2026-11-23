# Jaunt

Identity-aware access gateway for SSH and infrastructure, written in Rust.

Jaunt issues short-lived certificates after a single sign-on, so people and machines reach servers without long-lived keys, bastion hosts or VPNs. Agents connect outward, so protected hosts need no inbound ports.

## Status

Early design. Nothing here is usable yet.

## Goals

- Plain OpenSSH on the client side: `ssh`, `scp`, `rsync` and editors work unchanged.
- OIDC single sign-on from day one.
- One binary and minimal configuration.
- Access policy as code, kept in Git.
- Open formats for audit events and session recordings.

## License

MIT. See [LICENSE](LICENSE).
