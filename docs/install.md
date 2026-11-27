# Installing Jaunt from a release

Every release at https://github.com/GlobalArtInc/jaunt/releases carries these files. They can be downloaded without signing in.

| File | Contents | Platforms |
|---|---|---|
| `jaunt-agent-<version>-<target>.tar.gz` | the node agent | Linux x86_64 and aarch64 |
| `jaunt-host-users-<version>-<target>.tar.gz` | the helper that creates accounts at first login; only for nodes that use `jaunt-agent install --create-accounts` | Linux x86_64 and aarch64 |
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

Install the service and the `sshd` drop-in first, then enrol. `install` creates the `jaunt` service account, the state directory `/var/lib/jaunt`, the systemd unit, `/etc/jaunt/agent.yaml` and an sshd drop-in that trusts only the node's own internal CA, and only for connections from loopback. It checks the effective `sshd` configuration, reloads sshd and enables the unit. It does not start the service, and it refuses a state directory that `enroll` has already filled.

```sh
sudo jaunt-agent install --dry-run
sudo jaunt-agent install
```

`--dry-run` shows what would change without touching the system. Use `--no-service` to skip systemd.

Enrol the node. The `--ca-pin` value is the hash of the server's internal CA root, in the form `sha256:<64 hex digits>`. With it the agent refuses a server that presents any other CA. The server prints it as the `internal-ca sha256:...` line when the authorities are created with `jauntd ca init`, so keep that output. `jauntd ca status` does not show it, but the root certificate is public and stored as a file, so the pin can be recomputed on the server at any time: `sudo sh -c 'sha256sum /var/lib/jauntd/ca/internal/*.root.der'` prints the 64 hex digits (adjust the path to your `data_dir`). Without `--ca-pin` the agent accepts the root the server hands over during enrolment, relying only on the TLS connection to the server, so use the pin whenever you have it.

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

Approval can replace the proposed labels (`--labels`). When the node is approved the agent stores its identity under `/var/lib/jaunt` and exits. Then start the service:

```sh
sudo systemctl start jaunt-agent
```

### Create accounts at first login (optional)

A node can create the operating-system account of a user the first time that user logs in. This needs the second binary, `jaunt-host-users` (a small program that runs as root, see [security.md](security.md#account-creation-and-the-root-helper)), and the flag `--create-accounts` on `install`. What the feature does, how to run it and how to turn it off is in [operations.md](operations.md#account-creation-at-first-login); the keys are in [configuration.md](configuration.md#host_users). This page covers only the installation.

The helper must be named `jaunt-host-users` and lie in the same directory as the agent binary that you pass with `--binary`. Because root runs it, the installer refuses to continue unless the helper is a regular file of root, not writable by group or others, without setuid or setgid bits, and every directory above it belongs to root and is not writable by group or others. Nothing is changed when it refuses, and the error names the path and the fix.

On Debian and Ubuntu `/usr/local` and `/usr/local/bin` are `root:staff` with mode 2775, so the default `--binary /usr/local/bin/jaunt-agent` is refused with `--create-accounts`. Use the `.deb` package (both binaries are installed in `/usr/bin`), or put both binaries in a directory that you create for them, or run `chmod g-w,o-w` on the two directories if that is safe on your system:

```sh
sudo install -d -m 0755 -o root -g root /opt/jaunt/bin
sudo install -m 0755 -o root -g root jaunt-agent jaunt-host-users /opt/jaunt/bin/
sudo /opt/jaunt/bin/jaunt-agent install --create-accounts --binary /opt/jaunt/bin/jaunt-agent
```

The check is made when `install` runs. After you change the permissions of the helper or of a directory above it, and after you replace the binaries in an upgrade, run the same `install --create-accounts` command again: the installer checks again and refuses an unsafe state. Running it again is safe: the `host_users` section that you edited is kept. The installer rewrites the rest of the managed `/etc/jaunt/agent.yaml` as before, so other top-level keys that you added by hand (for example `recording:`) are lost; the `host_users` section is the exception.

`install --create-accounts` writes the section with `enabled: true`, the units `jaunt-host-users.socket` and `jaunt-host-users@.service` in `/etc/systemd/system`, enables the socket and restarts a running agent once. With `--no-service` it writes the files only and tells you which `systemctl` commands to run. It prints a warning when `sshd -T` shows `AllowUsers` or `AllowGroups`, when `/etc/nsswitch.conf` takes users from a directory, when `useradd`, `userdel` or `getent` is missing and when SELinux is enforcing. Alpine is not supported.

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

## Install from the apt repository

For Debian 12 and 13. The repository holds two packages, `jaunt-agent` and `jaunt`, built from the same static binaries as the release archives for amd64 and arm64. The address of the repository (`<repository-url>`) and the fingerprint of its signing key come from whoever publishes the repository. Check the fingerprint before you add the key.

Download the public signing key and print its fingerprint:

```sh
sudo apt-get install -y curl gnupg
repo=<repository-url>
curl -fsSL -o jaunt.asc "$repo/jaunt-archive-keyring.asc"
gpg --show-keys --with-fingerprint jaunt.asc
```

Continue only if the fingerprint is the one you were given. The key is downloaded from the same host as the packages, so the comparison is what ties it to the publisher. Then put the key in `/etc/apt/keyrings` and add the repository; the `signed-by` option limits the key to this repository only:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 jaunt.asc /etc/apt/keyrings/jaunt.asc
echo "deb [signed-by=/etc/apt/keyrings/jaunt.asc] $repo ./" | sudo tee /etc/apt/sources.list.d/jaunt.list
sudo apt-get update
```

Install the packages you need:

```sh
sudo apt-get install jaunt-agent
sudo apt-get install jaunt
```

The packages install files only: `/usr/bin/jaunt-agent` (or `/usr/bin/jaunt`) and, for the agent, the unit file `/usr/lib/systemd/system/jaunt-agent.service` and the account helper `/usr/bin/jaunt-host-users`, which does nothing until you install with `--create-accounts`. They do not enrol the node, create the `jaunt` account, change the sshd configuration or start anything. Set the node up yourself, in this order: run the installer first, enrol second, start the service last. The installer needs to know where the packaged binary is. The `enroll` options are described in [Install the node agent](#install-the-node-agent).

```sh
sudo jaunt-agent install --dry-run --binary /usr/bin/jaunt-agent
sudo jaunt-agent install --binary /usr/bin/jaunt-agent
sudo jaunt-agent enroll --server https://<host> --name <node> --ca-pin sha256:<hash>
sudo systemctl start jaunt-agent
```

If an earlier tarball install left `/usr/local/bin/jaunt-agent` on the node, delete it: it comes first in `PATH` and would shadow the packaged binary.

To upgrade, run `sudo apt-get update && sudo apt-get install --only-upgrade jaunt-agent jaunt`. The package does not restart the service, so run `sudo systemctl restart jaunt-agent` afterwards. To remove the agent, run `sudo jaunt-agent uninstall` first (see [Uninstall](#uninstall)), then `sudo apt-get remove jaunt-agent`. The package does not stop the service or remove the sshd drop-in itself.

Pre-release versions such as `1.2.0-rc.1` are written `1.2.0~rc.1` in the package, so that they sort before `1.2.0`.

## Upgrade

Download and verify the new archive, then replace the binary and restart the service:

```sh
sudo install -m 0755 "jaunt-agent-$version-$target/jaunt-agent" /usr/local/bin/jaunt-agent
sudo systemctl restart jaunt-agent
```

Enrolment is not repeated: the identity under `/var/lib/jaunt` is kept. On a node that creates accounts, replace `jaunt-host-users` next to the agent and run `sudo jaunt-agent install --create-accounts --binary <path>` again before the restart.

## Uninstall

```sh
sudo jaunt-agent uninstall --dry-run
sudo jaunt-agent uninstall
sudo jaunt-agent uninstall --purge
```

The first form shows the plan, the second removes the service and the sshd drop-in and keeps the state, the third also removes the state directory with the stored identity and the `jaunt` account. Then delete `/usr/local/bin/jaunt-agent`.

On a node that creates accounts, `uninstall` also removes the two helper units and, together with the managed `agent.yaml`, the `host_users` section. It keeps every account that was created, their home directories, `/var/lib/jaunt-host-users` and the `jaunt-host-users` binary, and prints how many accounts it kept and the command that lists them (`jaunt-host-users list`). Remove accounts by hand if you want them gone ([operations.md](operations.md#account-creation-at-first-login)).

## Caveats of the static Linux binaries

- The binaries are linked against musl libc, which does not read `/etc/nsswitch.conf`. The agent never looks users up through libc itself: the installer asks the system with `getent passwd` and `getent group`, so LDAP, SSSD and other NSS sources are seen as on any other tool. Logins themselves are handled by the host's own `sshd`.
- Host names are resolved by musl's own resolver, which reads `/etc/hosts` and `/etc/resolv.conf` only. Names that come from NSS plugins (mDNS, `systemd-resolved` through `nss-resolve`) are not resolved. A normal DNS server or the `systemd-resolved` stub at 127.0.0.53 works.
- musl's allocator is slower than glibc's under heavy multi-threaded load. This matters for `jauntd` on a busy server; for that case use the container image, which is built against glibc.
- The release version in the file names is the tag. `--version` still prints the version from `Cargo.toml`.
- The archives are built with fixed file order, owners and times, and the build flags and toolchain are pinned, so the binaries inside are meant to be reproducible with `scripts/release-build.sh`. The bytes of the `.tar.gz` files depend on the zlib of the Python that packs them, so compare the extracted binaries, not the archives.
