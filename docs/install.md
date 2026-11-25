# Installing Jaunt from a release

Every release at https://github.com/GlobalArtInc/jaunt/releases carries these files. They can be downloaded without signing in.

| File | Contents | Platforms |
|---|---|---|
| `jaunt-agent-<version>-<target>.tar.gz` | the node agent | Linux x86_64 and aarch64 |
| `jaunt-<version>-<target>.tar.gz` | the command-line client | Linux x86_64 and aarch64, macOS Apple silicon and Intel |
| `jauntd-<version>-<target>.tar.gz` | the control daemon, for hosts that do not use the container image | Linux x86_64 and aarch64 |
| `SHA256SUMS` | checksums of all archives | |

The targets are `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin` and `aarch64-apple-darwin`. The Linux binaries are fully static: they do not depend on the host's libc. The macOS binary needs macOS 11 or newer.

The Linux archives are checked in containers of Debian 12 and 13, Rocky Linux 9, Ubuntu 22.04 and 24.04 and Alpine 3.20. The aarch64 archives were verified on these systems on an arm64 machine before the first release; the x86_64 archives are checked by the release workflow itself on every release. The agent installer additionally needs systemd and the OpenSSH server (`sshd`) on the node; the installer was checked on Debian 12 and 13 and Rocky Linux 9.

Each archive holds one directory with the binary, `LICENSE` and `README.txt`.

## Download and verify

```sh
version=<version>
target=x86_64-unknown-linux-musl
base=https://github.com/GlobalArtInc/jaunt/releases/download/v$version
curl -fLO "$base/jaunt-agent-$version-$target.tar.gz"
curl -fLO "$base/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
```

On macOS use `shasum -a 256 -c SHA256SUMS` instead of `sha256sum`; it does not accept `--ignore-missing`, so check just the line of the file you downloaded:

```sh
grep " jaunt-$version-aarch64-apple-darwin.tar.gz\$" SHA256SUMS | shasum -a 256 -c
```

The archives also carry a build provenance attestation that ties each file to the workflow run and the commit that built it. With the GitHub CLI:

```sh
gh attestation verify "jaunt-agent-$version-$target.tar.gz" --repo GlobalArtInc/jaunt
```

The checksum only proves that the file was not damaged in transit. The attestation proves where it was built.

## Install the node agent

On the node, as root:

```sh
tar -xzf "jaunt-agent-$version-$target.tar.gz"
sudo install -m 0755 "jaunt-agent-$version-$target/jaunt-agent" /usr/local/bin/jaunt-agent
```

Enrol the node. The `--ca-pin` value is the hash of the server's internal CA root, in the form `sha256:<64 hex digits>`. With it the agent refuses a server that presents any other CA. The server prints it as the `internal-ca sha256:...` line when the authorities are created with `jauntd ca init`, so keep that output. If `ca init` ran in a one-off container or job, the line is in that job's log for as long as the log is kept. There is no command yet that shows the pin again later (`jauntd ca status` lists only the user and host authorities), so a lost pin cannot be recomputed from the CLI today; a follow-up change to the daemon will add it to `ca status`. Without `--ca-pin` the agent accepts the root the server hands over during enrolment, relying only on the TLS connection to the server, so use the pin whenever you have it.

```sh
sudo jaunt-agent enroll \
  --server https://<host> \
  --name <node> \
  --labels env=prod,role=web \
  --ca-pin sha256:<hash>
```

The command prints a short code and waits (15 minutes by default). An administrator approves the node by that code, either in the console or on the server:

```sh
jauntd node approve <code>
```

Approval can replace the proposed labels (`--labels`). When the node is approved the agent stores its identity under `/var/lib/jaunt` and exits.

Then install the service and the sshd drop-in:

```sh
sudo jaunt-agent install --dry-run
sudo jaunt-agent install
```

`--dry-run` shows what would change without touching the system. `install` creates the `jaunt` service account, the systemd unit, `/etc/jaunt/agent.yaml` and an sshd drop-in that trusts the Jaunt user CA, reloads sshd and enables the unit. The installer does not start the service; start it yourself:

```sh
sudo systemctl start jaunt-agent
```

Use `--no-service` to skip systemd.

## Install the command-line client

```sh
tar -xzf "jaunt-$version-$target.tar.gz"
sudo install -d /usr/local/bin
sudo install -m 0755 "jaunt-$version-$target/jaunt" /usr/local/bin/jaunt
jaunt login --server https://<host>
```

On macOS a downloaded binary can be blocked by Gatekeeper because it is not notarised. Remove the quarantine flag once after you have verified the checksum and the attestation:

```sh
xattr -d com.apple.quarantine /usr/local/bin/jaunt
```

`curl` does not set that flag, so it is usually not needed when you download from a terminal.

## Upgrade

Download and verify the new archive, then replace the binary and restart the service:

```sh
sudo install -m 0755 "jaunt-agent-$version-$target/jaunt-agent" /usr/local/bin/jaunt-agent
sudo systemctl restart jaunt-agent
```

Enrolment is not repeated: the identity under `/var/lib/jaunt` is kept.

## Uninstall

```sh
sudo jaunt-agent uninstall --dry-run
sudo jaunt-agent uninstall
sudo jaunt-agent uninstall --purge
```

The first form shows the plan, the second removes the service and the sshd drop-in and keeps the state, the third also removes the state directory with the stored identity and the `jaunt` account. Then delete `/usr/local/bin/jaunt-agent`.

## Caveats of the static Linux binaries

- The binaries are linked against musl libc, which does not read `/etc/nsswitch.conf`. The agent never looks users up through libc itself: the installer asks the system with `getent passwd` and `getent group`, so LDAP, SSSD and other NSS sources are seen as on any other tool. Logins themselves are handled by the host's own `sshd`.
- Host names are resolved by musl's own resolver, which reads `/etc/hosts` and `/etc/resolv.conf` only. Names that come from NSS plugins (mDNS, `systemd-resolved` through `nss-resolve`) are not resolved. A normal DNS server or the `systemd-resolved` stub at 127.0.0.53 works.
- musl's allocator is slower than glibc's under heavy multi-threaded load. This matters for `jauntd` on a busy server; for that case use the container image, which is built against glibc.
- The release version in the file names is the tag. `--version` still prints the version from `Cargo.toml`.
- The archives are built with fixed file order, owners and times, and the build flags and toolchain are pinned, so the binaries inside are meant to be reproducible with `scripts/release-build.sh`. The bytes of the `.tar.gz` files depend on the zlib of the Python that packs them, so compare the extracted binaries, not the archives.
