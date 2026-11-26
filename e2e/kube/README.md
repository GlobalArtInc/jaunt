# Kubernetes stand

A single-node k3s cluster in one privileged container. Later Kubernetes slices run their end-to-end checks against it.

    just kube-stand                 # same as: scripts/kube-stand.sh up
    just kube-stand kubeconfig      # refresh the kubeconfig and print its path
    just kube-stand kubectl v1.29.15
    just kube-stand down            # remove the container, its anonymous volumes and the kubeconfig
    just kube-stand down --purge    # also empty the kubectl cache

`up` takes an optional directory (`target/kube-stand` by default) and writes `kubeconfig` there with mode 0600. The file holds
cluster-admin credentials of a throwaway cluster: it is never printed by the script and never leaves `target/`.
The script makes a directory it creates itself mode 0700 and marks it; an existing directory keeps its mode (the script only
warns when it is open to other users). `down` removes only `kubeconfig` and, if the script created the directory and nothing
else is in it, the directory.

    KUBECONFIG=target/kube-stand/kubeconfig kubectl get nodes

## How it works

- Image: `rancher/k3s`, pinned by tag and digest in `scripts/kube-stand.sh` (`K3S_TAG`, `K3S_DIGEST`). `KUBE_STAND_K3S_IMAGE`
  replaces it, for example to test against an older cluster. Traefik, the service load balancer, metrics-server and local
  storage are off; CoreDNS and flannel stay, so `kubernetes.default.svc` resolves inside the cluster.
- The container runs `--privileged` with `--tmpfs /run --tmpfs /var/run`. The API server (6443) is published on a free
  loopback port, so several stands with different `KUBE_STAND_PROJECT` values can run side by side.
- `up` is ready when `kubectl get --raw /readyz` answers inside the container, a node is Ready, the `default` service account
  exists and the published port answers from the host. Every wait has a hard deadline (150 s for the API server, 90 s for the
  node and the service account) and a failed `up` prints the tail of the k3s log and removes the container.
- A second `up` on a healthy stand only rewrites the kubeconfig; an unhealthy or stopped one is replaced. A healthy stand
  that runs another image than the script asks for is an error, not a silent "already up".
- The container carries the label `jaunt.kube-stand=1`. `up` and `down` refuse to replace or remove a container of the same
  name without it. The only volumes removed are the anonymous ones of that container (`rm --volumes`); the stand creates no
  named volumes.
- `KUBE_STAND_PROJECT` (letters, digits, `_`, `.`, `-`) is the prefix of the container name, so stands do not collide.
- `kubectl VERSION` downloads that release from `dl.k8s.io` into `target/kube-stand-cache/bin/VERSION/` and stores the
  published sha256 next to it. A cached binary whose sum matches the stored one is used without any network access. The sum
  from dl.k8s.io protects against a damaged download, not against a tampered mirror.

## Older clusters

    KUBE_STAND_PROJECT=jaunt-kube-130 \
    KUBE_STAND_K3S_IMAGE=docker.io/rancher/k3s:v1.30.14-k3s1@sha256:cbed71f50f16fc98a7f64c6ecf21fd8fc04efc41ad7d664fb46b199c7bd3fda7 \
      just kube-stand up target/kube-stand-130

Use the same `KUBE_STAND_PROJECT` for `down`. Without a separate project name `up` refuses to reuse the running stand.

## What kubectl sends (measured against k3s 1.35, 1.30 and 1.29)

- exec and attach: kubectl 1.29 uses SPDY (`POST`, `Upgrade: SPDY/3.1`); from 1.30 it uses WebSocket (`GET`,
  `Sec-WebSocket-Protocol: v5.channel.k8s.io`) and the API server accepts it from 1.30.
- port-forward: SPDY up to 1.30; WebSocket (`SPDY/3.1+portforward.k8s.io`) from kubectl 1.31 against an API server 1.31 or
  newer. `KUBECTL_REMOTE_COMMAND_WEBSOCKETS` and `KUBECTL_PORT_FORWARD_WEBSOCKETS` switch each on or off.
- logs -f and get -w are plain HTTP/2 requests; upgrades come as HTTP/1.1.
- Against an API server 1.29, kubectl 1.31 and newer get 403 for the WebSocket exec and attach and 400 for the WebSocket
  port-forward, then repeat the request over SPDY.

## Container engine

`CONTAINER_ENGINE` selects it: `podman` if installed, else `docker`.
Verified only with podman on macOS, through the rootful connection of the main machine. The docker path has never been run:
the script uses only subcommands common to both engines, nothing more is claimed, and no CI job uses it yet.
k3s needs a rootful engine. A rootless podman fails with `failed to find cpuset cgroup (v2)`, so on macOS the script
uses the rootful connection of the running machine (`<default connection>-root`, which podman creates for every machine)
and refuses to start on a rootless engine. `KUBE_STAND_PODMAN_CONNECTION` names another connection.
The containers of that connection live in the root storage of the machine and do not mix with rootless ones. Podman on
macOS runs only one machine at a time, so a separate machine for the stand cannot run next to the default one.

The first `up` pulls the k3s image (about 250 MB); later runs reuse it.
