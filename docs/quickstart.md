# Quickstart

This guide takes one control host, one node and one laptop from nothing to `ssh web-01.nodes.example.com` through Jaunt. It takes about 20 minutes. The commands are copy-pasteable; replace the values in the variables block first.

## What you need

| Machine | Needs |
|---|---|
| control host | Linux with systemd, root access, outbound HTTPS to your identity provider, inbound TCP 443 (console), 8444 (agents) and 2222 (SSH gate) |
| node | Linux with systemd and OpenSSH `sshd` listening on `127.0.0.1:22`, root access, outbound TCP to the control host on 443 and 8444. It needs no inbound port |
| laptop | Linux or macOS with OpenSSH 7.3 or newer (for `ProxyJump`) |
| identity provider | Any OpenID Connect provider that issues `email` and a username claim, and lets you register a confidential client |

Three things are outside Jaunt and you must supply them:

- **An identity provider.** Register a confidential client (client id and client secret). Its only redirect URI is `https://<control host name>/v1/login/callback`. Jaunt asks for the scopes `openid email profile groups` by default (`oidc.scopes` changes them), reads the user name from the `preferred_username` claim and the groups from the `groups` claim, and by default refuses users whose `email_verified` is not true (`oidc.require_verified_email: false` turns that off). If your provider uses other claim names or has no `groups` scope, set `oidc.username_claim`, `oidc.groups_claim` and `oidc.scopes`; see [configuration.md](configuration.md#oidc). The script that checks this guide uses a fake provider (`crates/jaunt-fake-idp`) instead, because it cannot sign in to a real one.
- **One DNS name for the control host**, for example `jaunt.example.com`. The console, the agent endpoint and the SSH gate can all use it. The node names (`web-01.nodes.example.com`) need no DNS record: the SSH client sends them through the gate, which maps them to nodes. The suffix (`nodes.example.com`) must be a name with at least two labels; it is only a naming convention.
- **A TLS certificate that browsers and the `jaunt` CLI trust for that name.** `jauntd` serves the console on a plain HTTP port and expects a TLS terminator in front of it. The CLI and the agent trust only the public web roots; there is no setting for a private CA. The agent port 8444 is different: `jauntd` terminates TLS there itself with its own internal CA, and the agent checks that CA by the pin you will save in step 3.

## 1. Get the binaries

Follow [install.md](install.md) to download and verify the three archives. In short, `jauntd` goes on the control host, `jaunt-agent` on the node and `jaunt` on the laptop, each in `/usr/local/bin`.

```sh quickstart-manual install
tar -xzf "jauntd-$version-$target.tar.gz"
sudo install -m 0755 "jauntd-$version-$target/jauntd" /usr/local/bin/jauntd
```

## 2. Set the variables

Set these in the shell of each machine you use. Replace every value.

```sh quickstart-vars
export JAUNT_HOST=jaunt.example.com
export JAUNT_URL=https://$JAUNT_HOST
export JAUNT_SUFFIX=nodes.example.com
export OIDC_ISSUER=https://idp.example.com
export OIDC_CLIENT_ID=jaunt
export OIDC_CLIENT_SECRET=replace-with-the-client-secret
export ADMIN_EMAIL=you@example.com
export NODE_NAME=web-01
export NODE_LOGIN=deploy
export version=replace-with-the-release-version
export target=x86_64-unknown-linux-musl
export DEPLOY_BASE=https://raw.githubusercontent.com/GlobalArtInc/jaunt/v$version/deploy
```

`version` and `target` pick the release archives of step 1 and the matching `deploy` files, so the systemd unit you install is the one of your release, not the development branch. `NODE_LOGIN` is an existing Linux account on the node. A login must match `[a-z_][a-z0-9_.-]{0,31}`: lower-case letters only. The agent refuses any other name.

## 3. Set up the control host

Create the service account and the directories. `jauntd` keeps its database, its CA keys and the recordings under `/var/lib/jauntd`, readable only by its account.

```sh quickstart-step control accounts
sudo useradd --system --home-dir /var/lib/jauntd --shell /usr/sbin/nologin jauntd
sudo install -d -o jauntd -g jauntd -m 0700 /var/lib/jauntd
sudo install -d -m 0755 /etc/jaunt /etc/jaunt/policy
```

Write the configuration. [configuration.md](configuration.md) explains every key.

```sh quickstart-step control config
sudo tee /etc/jaunt/jauntd.yaml >/dev/null <<EOF
data_dir: /var/lib/jauntd
listen: 127.0.0.1:8443
agents_listen: 0.0.0.0:8444
public_url: https://$JAUNT_HOST
agent_endpoint: $JAUNT_HOST:8444
ssh_suffix: $JAUNT_SUFFIX
gate_endpoint: $JAUNT_HOST:2222
policy_dir: /etc/jaunt/policy
ssh_gate:
  listen: 0.0.0.0:2222
  hostnames: [$JAUNT_HOST]
oidc:
  issuer_url: $OIDC_ISSUER
  client_id: $OIDC_CLIENT_ID
  client_secret_file: /etc/jaunt/oidc-client-secret
client_ip_header: X-Forwarded-For
client_ip_trusted_proxies: [127.0.0.1/32]
recordings:
  dir: /var/lib/jauntd/recordings
EOF
printf '%s\n' "$OIDC_CLIENT_SECRET" | sudo install -m 0640 -o root -g jauntd /dev/stdin /etc/jaunt/oidc-client-secret
```

Note: `client_ip_header` and `client_ip_trusted_proxies` tell `jauntd` to read the real client address from the `X-Forwarded-For` header that the TLS terminator on the same host adds. Without them every client looks like `127.0.0.1`: all users share one rate limit and the approval screen shows a useless source address. Only a header that arrives from a trusted network is believed.

Note: `public_url` must be `https`, must not end with a slash and must not contain a path. `jauntd` refuses to start otherwise.

Write one policy file. It gives you, identified by e-mail, access to every node labelled `env=eval` as the login `NODE_LOGIN`, and all admin permissions in the console. Without a role nobody can do anything: access is denied by default.

```sh quickstart-step control policy
sudo tee /etc/jaunt/policy/roles.yaml >/dev/null <<EOF
apiVersion: jaunt/v1
kind: Role
metadata: { name: operators }
spec:
  members:
    users: [$ADMIN_EMAIL]
  ssh:
    nodes: { env: [eval] }
    logins: [$NODE_LOGIN]
  admin: [nodes.approve, sessions.read, recordings.read, revocations.write, audit.read]
EOF
```

Create the certificate authorities. This command prints three lines. **Save them now**, in particular the `internal-ca` line: it is the pin that nodes use to trust the server, and no `jauntd` command prints it again (see [operations.md](operations.md#internal-ca-pin)).

```sh quickstart-step control ca-init
sudo -u jauntd jauntd ca init --generate-identity --config /etc/jaunt/jauntd.yaml | tee ~/jaunt-ca-init.txt
export CA_PIN=$(awk '$1 == "internal-ca" { print $2 }' ~/jaunt-ca-init.txt)
```

```text
user-ca ssh-ed25519 AAAA...
host-ca ssh-ed25519 AAAA...
internal-ca sha256:3f2a...
```

`--generate-identity` also wrote the key that encrypts the CA keys, `/var/lib/jauntd/ca/age-identity.txt`, and a warning says so. Anyone who holds that file and the CA directory can issue certificates. For this trial it stays where it is. For production, move it away as [security.md](security.md#secrets) describes.

Put a TLS terminator in front of port 8443. Install Caddy from your distribution or from its own package repository first. Caddy obtains a certificate for the name by itself, which needs the name to resolve publicly to this host and ports 80 and 443 to be reachable from the internet. Its whole configuration is:

```sh quickstart-manual caddy
curl -fsSL "$DEPLOY_BASE/caddy/Caddyfile" | sed "s/jaunt.example.com/$JAUNT_HOST/" | sudo tee /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Install the unit and start the daemon. The unit runs `jauntd` as the `jauntd` account with the sandboxing options listed in [security.md](security.md#hardening-checklist).

```sh quickstart-step control service
sudo curl -fsSLo /etc/systemd/system/jauntd.service "$DEPLOY_BASE/systemd/jauntd.service"
sudo systemctl daemon-reload
sudo systemctl enable --now jauntd
curl --retry 15 --retry-connrefused --retry-delay 1 -fsS http://127.0.0.1:8443/healthz
```

The last command prints `ok`; while the daemon starts it may first print one `Failed to connect` line and retry. If it never answers, read `journalctl -u jauntd`: the first lines name the configuration key at fault.

Open `https://<control host name>/` in a browser and sign in. You see the console. Your account has every admin permission, so the Nodes, Sessions, Audit log and Revocations pages are there. This step needs your real identity provider and is not covered by the check script.

## 4. Enrol the node

On the node, install `jaunt-agent` (step 1) and set `CA_PIN` to the `internal-ca` line from step 3, together with `NODE_NAME` and `JAUNT_URL`. Make sure the account in `NODE_LOGIN` exists and `sshd` is running.

Install the service first. `jaunt-agent install` creates the `jaunt` account, the state directory `/var/lib/jaunt`, the systemd unit and the `sshd` drop-in that trusts the node's internal CA on loopback only. It checks the effective `sshd` configuration, reloads `sshd` and does not start the agent. Run it before `enroll`: it refuses a state directory that `enroll` has already filled.

```sh quickstart-step node install
sudo jaunt-agent install
```

Enrolment has two sides. The node asks, an administrator approves by a code that is shown only on the node. Start the request. It prints a code and waits for up to 15 minutes:

```sh quickstart-step node enroll background
sudo jaunt-agent enroll --server "$JAUNT_URL" --name "$NODE_NAME" --labels env=eval --ca-pin "$CA_PIN"
```

```text
code:         WXYZ-2345
tls key:      sha256:...
ssh host key: SHA256:...
expires at:   2026-11-26T12:15:00Z
An administrator must run `jauntd node approve WXYZ-2345` on the server and check that both fingerprints match.
waiting up to 900 seconds for an administrator to approve the request
```

Approve it in another terminal. In the console, open Nodes, choose Approve a new node, type the code and check the fingerprints. Or on the control host, set `ENROLL_CODE` to the code that `enroll` printed in its first line and approve:

```sh quickstart-vars
export ENROLL_CODE=WXYZ-2345
```

```sh quickstart-step control approve
sudo -u jauntd jauntd node approve "$ENROLL_CODE" --config /etc/jaunt/jauntd.yaml --yes
```

The `enroll` command on the node then stores its identity in `/var/lib/jaunt` and exits. Start the agent:

```sh quickstart-step node start
sudo systemctl start jaunt-agent
```

Check that the node is approved and connected:

```sh quickstart-step control nodes
sudo -u jauntd jauntd node list --config /etc/jaunt/jauntd.yaml
sudo journalctl -u jauntd --no-pager | grep agent.connected | tail -n 1
```

```text
NAME    STATE   CERT       LABELS    APPROVED BY  CREATED
web-01  active  delivered  env=eval  cli:jauntd   2026-11-26T18:39:22Z
{"v":1,"id":"...","type":"agent.connected","time":"2026-11-26T18:39:25.338Z","actor":"node:...","fields":{"alpn":"jaunt-tunnel/1",...}}
```
## 5. Sign in and connect

On the laptop, install `jaunt` (step 1), then sign in. A browser opens on your identity provider. `--accept-ssh-config` lets `jaunt` add one `Include` line to `~/.ssh/config`; without it `jaunt` asks first.

```sh quickstart-step client login
jaunt login --server "$JAUNT_URL" --accept-ssh-config
jaunt status
jaunt ls
```

```text
Signed in as you@example.com; certificate valid until 2026-11-27T02:39:29+00:00 (serial 3).
Signed in as you@example.com (user 5719e732-72df-4621-be8a-c773c850aebc)
Server: https://jaunt.example.com
Certificate serial: 3
Valid until: 2026-11-27T02:39:29+00:00 (8h 0m left)
Key in ssh-agent: yes
SSH setup: ready (hosts *.nodes.example.com through jaunt.example.com:2222)
Auto sign-in: on (ssh signs you in again when the certificate expires)
NAME                       LABELS
web-01.nodes.example.com   env=eval
ssh <login>@web-01.nodes.example.com
```

`jaunt login` also wrote `~/.jaunt/default/ssh_config`, `known_hosts` and the certificate. `Auto sign-in` means that `ssh` runs `jaunt ensure` when the certificate has expired and signs you in again.

Now plain OpenSSH works. The name is `<node>.<suffix>`:

```sh quickstart-step client ssh
ssh "$NODE_LOGIN@$NODE_NAME.$JAUNT_SUFFIX" 'echo hello from $(hostname)'
```

```sh quickstart-step client transfer
head -c 1048576 /dev/urandom > /tmp/qs-payload
scp /tmp/qs-payload "$NODE_LOGIN@$NODE_NAME.$JAUNT_SUFFIX:/tmp/qs-payload"
rsync -a /tmp/qs-payload "$NODE_LOGIN@$NODE_NAME.$JAUNT_SUFFIX:/tmp/qs-payload-rsync"
ssh "$NODE_LOGIN@$NODE_NAME.$JAUNT_SUFFIX" 'sha256sum /tmp/qs-payload /tmp/qs-payload-rsync'
sha256sum /tmp/qs-payload
```

The three sums are equal. `ssh -L` works when the role sets `portForwarding: true`. Remote forwarding (`-R`), X11 and agent forwarding are not supported.

### The web terminal

In the console open Terminal, choose the node and the login, and press Open terminal. This needs a browser and your identity provider, so the check script does not cover it. The terminal is another SSH client run by the server; see [operations.md](operations.md#web-terminal).

## 6. Look at the recording

A shell with a terminal is recorded on the node and uploaded while the session runs. Open one, then find it on the control host:

```sh quickstart-step client recorded
ssh -tt "$NODE_LOGIN@$NODE_NAME.$JAUNT_SUFFIX" 'echo recorded-by-jaunt'
```

```sh quickstart-step control recording
sleep 5
export SESSION_ID=$(sudo find /var/lib/jauntd/recordings -name '*.cast' -printf '%f\n' | head -n 1 | sed 's/\.cast$//')
sudo -u jauntd jauntd recordings verify "$SESSION_ID" --config /etc/jaunt/jauntd.yaml
sudo sh -c "grep -c recorded-by-jaunt /var/lib/jauntd/recordings/*/*/$SESSION_ID.cast"
```

The `verify` line reads `recording <id> verified: 1 chunks, 222 bytes, complete, cast sha256 ...`, and the last command prints a count of at least 1. In the console, Sessions lists the session and its Watch recording button plays it. `exec` commands and file transfers leave a metadata record, not a cast.

## 7. Undo everything

```sh quickstart-step client undo
jaunt logout
rm -f /tmp/qs-payload
```

```sh quickstart-step node undo
sudo systemctl stop jaunt-agent
sudo jaunt-agent uninstall --purge
sudo rm -f /tmp/qs-payload /tmp/qs-payload-rsync
```

```sh quickstart-step control undo
sudo systemctl disable --now jauntd
sudo rm -f /etc/systemd/system/jauntd.service
sudo systemctl daemon-reload
sudo rm -rf -- /var/lib/jauntd /etc/jaunt
sudo userdel jauntd
rm -f ~/jaunt-ca-init.txt
```

If you installed Caddy for this guide, remove its configuration too:

```sh quickstart-manual undo-caddy
sudo rm -f /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

`jaunt logout` removes the key from the ssh-agent and the files under `~/.jaunt/default`. It leaves the `Include` line in `~/.ssh/config`. Delete the `Include ~/.jaunt/*/ssh_config` line by hand. If `~/.ssh/config` existed before `jaunt login`, a copy from before the change is next to it as `config.jaunt-backup`.

## How this guide is checked

`scripts/test-quickstart.sh` extracts the fenced blocks tagged `quickstart-step` from this file and runs them in order, each in the container named by its second word, in four containers of Debian 13 with systemd: the control host, the node, the laptop and a fake identity provider.

```sh
scripts/test-quickstart.sh
```

It needs Podman and the Linux binaries in `target/installer-linux/release` (run `e2e/build-binaries.sh` to build them). It replaces these things, none of which can be tested with a real counterpart:

| Real | In the check |
|---|---|
| your identity provider | `jaunt-fake-idp`, which signs a user in at once for the `login_hint` the browser stub appends |
| a public certificate, Caddy and DNS | a throw-away test CA, `socat` terminators and container network aliases; the CLI and the agent reach `jauntd` over `http://127.0.0.1`, which they accept for loopback |
| the browser | a stub `xdg-open` that follows the redirects with `curl` |
| the archives of step 1 | the binaries copied into the containers |
| the provider's certificate | `oidc.extra_root_certificates_file`, added to the written configuration so that `jauntd` trusts the test CA of the fake provider |

The blocks tagged `quickstart-manual` (installing the binaries, Caddy), the console sign-in, the approval in the console and the web terminal are not run. Blocks tagged `quickstart-vars` are replaced by variables that suit the containers.
