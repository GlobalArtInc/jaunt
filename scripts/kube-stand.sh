#!/usr/bin/env bash
set -euo pipefail

K3S_TAG=v1.35.10-k3s1
K3S_DIGEST=sha256:8262ca99a558dca0c0437443421986480b2359f9118f2371359f88a41514522f
K3S_IMAGE=${KUBE_STAND_K3S_IMAGE:-docker.io/rancher/k3s:${K3S_TAG}@${K3S_DIGEST}}
API_PORT=6443
PULL_DEADLINE=600
READY_DEADLINE=150
NODE_DEADLINE=90
DOWNLOAD_DEADLINE=180

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROJECT=${KUBE_STAND_PROJECT:-jaunt-kube}
NAME=$PROJECT-k3s
LABEL=jaunt.kube-stand
DIR_MARKER=.kube-stand-dir
DEFAULT_DIR=$ROOT/target/kube-stand
CACHE_DIR=${KUBE_STAND_CACHE:-$ROOT/target/kube-stand-cache}

engine=()
container_created=0
finished=0

usage() {
  cat <<EOF
usage: kube-stand.sh up [DIR]
       kube-stand.sh down [--purge] [DIR]
       kube-stand.sh kubeconfig [DIR]
       kube-stand.sh kubectl VERSION

up         start k3s ($K3S_TAG) and write DIR/kubeconfig; a healthy stand is left running
down       remove the container, its anonymous volumes and DIR/kubeconfig; --purge also empties the kubectl cache
kubeconfig refresh DIR/kubeconfig from the running stand and print its path
kubectl    download kubectl VERSION (for example v1.29.15) into the cache, verify the published sha256, print the path

DIR defaults to target/kube-stand. Environment: CONTAINER_ENGINE, KUBE_STAND_PROJECT, KUBE_STAND_PODMAN_CONNECTION,
KUBE_STAND_CACHE, KUBE_STAND_K3S_IMAGE (another k3s image, for tests against an older cluster).
EOF
}

die() {
  echo "kube-stand: $*" >&2
  exit 1
}

choose_engine() {
  local name=${CONTAINER_ENGINE:-}
  if [ -z "$name" ]; then
    if command -v podman >/dev/null 2>&1; then
      name=podman
    elif command -v docker >/dev/null 2>&1; then
      name=docker
    else
      die "neither podman nor docker is installed"
    fi
  fi
  command -v "$name" >/dev/null 2>&1 || die "$name is not installed"
  engine=("$name")
  if [ "$name" != podman ]; then
    return
  fi
  local connection=${KUBE_STAND_PODMAN_CONNECTION:-}
  if [ -z "$connection" ]; then
    local rootless
    rootless=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null) || die "podman is not reachable (is the machine running?)"
    if [ "$rootless" = true ]; then
      local default_connection
      default_connection=$(podman system connection list --format '{{.Name}} {{.Default}}' | awk '$2 == "true" { print $1; exit }')
      [ -n "$default_connection" ] || die "podman is rootless and has no default connection to derive a rootful one from; set KUBE_STAND_PODMAN_CONNECTION"
      connection=$default_connection-root
    fi
  fi
  if [ -n "$connection" ]; then
    podman system connection list --format '{{.Name}}' | grep -Fxq -- "$connection" || die "podman connection $connection does not exist; k3s needs a rootful podman"
    engine=(podman --connection "$connection")
  fi
  local still_rootless
  still_rootless=$("${engine[@]}" info --format '{{.Host.Security.Rootless}}') || die "the container engine is not reachable"
  [ "$still_rootless" != true ] || die "k3s needs a rootful container engine; set KUBE_STAND_PODMAN_CONNECTION to a rootful connection"
}

require_project() {
  [[ $PROJECT =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || die "KUBE_STAND_PROJECT must match ^[a-zA-Z0-9][a-zA-Z0-9_.-]*\$"
}

require_tools() {
  require_project
  command -v curl >/dev/null 2>&1 || die "curl is required"
  choose_engine
}

container_exists() {
  "${engine[@]}" container inspect "$NAME" >/dev/null 2>&1
}

container_label() {
  "${engine[@]}" inspect --format "{{index .Config.Labels \"$LABEL\"}}" "$NAME" 2>/dev/null || true
}

remove_container() {
  [ "$(container_label)" = 1 ] || die "container $NAME exists but was not created by kube-stand (label $LABEL is missing); refusing to remove it, use another KUBE_STAND_PROJECT"
  "${engine[@]}" rm --force --volumes "$NAME" >/dev/null
}

same_image() {
  local container_id image_id
  container_id=$("${engine[@]}" inspect --format '{{.Image}}' "$NAME" 2>/dev/null || true)
  image_id=$("${engine[@]}" image inspect --format '{{.Id}}' "$K3S_IMAGE" 2>/dev/null || true)
  [ -n "$container_id" ] && [ "${container_id#sha256:}" = "${image_id#sha256:}" ]
}

container_running() {
  [ "$("${engine[@]}" inspect --format '{{.State.Running}}' "$NAME" 2>/dev/null || true)" = true ]
}

host_port() {
  "${engine[@]}" port "$NAME" "$API_PORT/tcp" | head -n 1 | sed 's/.*://'
}

in_stand() {
  "${engine[@]}" exec "$NAME" "$@"
}

host_ready() {
  local port=$1
  curl --silent --insecure --max-time 3 "https://127.0.0.1:$port/readyz" 2>/dev/null | grep -Eq '^ok$|"kind": *"Status"'
}

show_logs() {
  echo "last log lines of $NAME:" >&2
  "${engine[@]}" logs --tail 20 "$NAME" 2>&1 | cut -c 1-200 >&2 || true
}

write_kubeconfig() {
  local dir=$1 port=$2 tmp
  if [ -d "$dir" ]; then
    local mode
    mode=$(stat -c %a "$dir" 2>/dev/null || stat -f %Lp "$dir" 2>/dev/null || echo 700)
    if [ "${mode: -2}" != 00 ]; then
      echo "kube-stand: warning: $dir is accessible to other users; the kubeconfig inside is 0600" >&2
    fi
  else
    mkdir -p -- "$dir"
    chmod 700 "$dir"
    : >"$dir/$DIR_MARKER"
  fi
  tmp=$(umask 077 && mktemp "$dir/.kubeconfig.XXXXXX")
  if ! in_stand cat /etc/rancher/k3s/k3s.yaml | sed "s#https://127.0.0.1:$API_PORT#https://127.0.0.1:$port#" >"$tmp"; then
    rm -f -- "$tmp"
    die "could not read the kubeconfig from $NAME"
  fi
  chmod 600 "$tmp"
  mv -f -- "$tmp" "$dir/kubeconfig"
}

ensure_image() {
  if "${engine[@]}" image inspect "$K3S_IMAGE" >/dev/null 2>&1; then
    return
  fi
  echo "pulling $K3S_IMAGE"
  "${engine[@]}" pull --quiet "$K3S_IMAGE" >/dev/null &
  local pid=$! started=$SECONDS
  while kill -0 "$pid" 2>/dev/null; do
    if [ $((SECONDS - started)) -ge "$PULL_DEADLINE" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      die "the image pull did not finish in ${PULL_DEADLINE}s"
    fi
    sleep 1
  done
  wait "$pid" || die "the image pull failed"
}

cleanup_on_failure() {
  if [ "$finished" -eq 0 ] && [ "$container_created" -eq 1 ]; then
    show_logs
    "${engine[@]}" rm --force --volumes "$NAME" >/dev/null 2>&1 || true
  fi
}

cmd_up() {
  local dir=${1:-$DEFAULT_DIR}
  require_tools
  if container_exists; then
    [ "$(container_label)" = 1 ] || die "container $NAME exists but was not created by kube-stand (label $LABEL is missing); refusing to replace it, use another KUBE_STAND_PROJECT"
    if container_running; then
      local existing_port
      existing_port=$(host_port || true)
      if [ -n "$existing_port" ] && host_ready "$existing_port" && in_stand kubectl get --raw /readyz >/dev/null 2>&1; then
        same_image || die "the stand $NAME is already up with another image; run down, or use another KUBE_STAND_PROJECT"
        write_kubeconfig "$dir" "$existing_port"
        echo "stand is already up: https://127.0.0.1:$existing_port, kubeconfig $dir/kubeconfig"
        return
      fi
    fi
    echo "replacing an unhealthy stand"
    remove_container
  fi

  ensure_image
  trap cleanup_on_failure EXIT
  "${engine[@]}" run --detach --name "$NAME" \
    --label $LABEL=1 \
    --privileged \
    --tmpfs /run --tmpfs /var/run \
    --publish "127.0.0.1::$API_PORT" \
    "$K3S_IMAGE" server \
    --disable=traefik --disable=servicelb --disable=metrics-server --disable=local-storage \
    --kubelet-arg='eviction-hard=imagefs.available<1%,nodefs.available<1%' \
    >/dev/null
  container_created=1

  local started=$SECONDS
  until in_stand kubectl get --raw /readyz >/dev/null 2>&1; do
    if [ $((SECONDS - started)) -ge "$READY_DEADLINE" ]; then
      die "the API server did not answer /readyz in ${READY_DEADLINE}s"
    fi
    container_running || die "the k3s container stopped"
    sleep 1
  done

  started=$SECONDS
  until [ "$(in_stand kubectl get nodes --no-headers 2>/dev/null | awk '$2 == "Ready"' | wc -l | tr -d ' ')" -ge 1 ]; do
    if [ $((SECONDS - started)) -ge "$NODE_DEADLINE" ]; then
      die "no node became Ready in ${NODE_DEADLINE}s"
    fi
    sleep 1
  done

  started=$SECONDS
  until in_stand kubectl --namespace default get serviceaccount default >/dev/null 2>&1; do
    if [ $((SECONDS - started)) -ge "$NODE_DEADLINE" ]; then
      die "the default service account did not appear in ${NODE_DEADLINE}s"
    fi
    sleep 1
  done

  local port
  port=$(host_port)
  [ -n "$port" ] || die "the API port is not published"
  started=$SECONDS
  until host_ready "$port"; do
    if [ $((SECONDS - started)) -ge 30 ]; then
      die "the published API port $port does not answer from the host"
    fi
    sleep 1
  done

  write_kubeconfig "$dir" "$port"
  finished=1
  echo "stand is up: https://127.0.0.1:$port, kubeconfig $dir/kubeconfig"
}

cmd_kubeconfig() {
  local dir=${1:-$DEFAULT_DIR}
  require_tools
  container_running || die "the stand is not running; run: kube-stand.sh up"
  local port
  port=$(host_port)
  [ -n "$port" ] || die "the API port is not published"
  write_kubeconfig "$dir" "$port"
  echo "$dir/kubeconfig"
}

cmd_down() {
  local purge=0 dir=$DEFAULT_DIR
  while [ $# -gt 0 ]; do
    case $1 in
      --purge) purge=1 ;;
      *) dir=$1 ;;
    esac
    shift
  done
  require_project
  rm -f -- "${dir:?}/kubeconfig"
  if [ -f "$dir/$DIR_MARKER" ] && [ "$(find "$dir" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" -eq 1 ]; then
    rm -f -- "${dir:?}/$DIR_MARKER"
    rmdir -- "$dir"
  fi
  if [ "$purge" -eq 1 ]; then
    rm -rf -- "${CACHE_DIR:?}/bin"
    rmdir -- "$CACHE_DIR" 2>/dev/null || true
  fi
  if [ -z "${CONTAINER_ENGINE:-}" ] && ! command -v podman >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
    echo "no container engine is installed: removed only the kubeconfig"
    return
  fi
  choose_engine
  if container_exists; then
    remove_container
    echo "stand is down"
  else
    echo "no stand $NAME to remove"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

cmd_kubectl() {
  local version=${1:-}
  [ -n "$version" ] || die "kubectl needs a version, for example v1.29.15"
  case $version in
    v*) ;;
    *) version=v$version ;;
  esac
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "the version must look like v1.29.15"
  command -v curl >/dev/null 2>&1 || die "curl is required"

  local os arch
  case $(uname -s) in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) die "unsupported OS $(uname -s)" ;;
  esac
  case $(uname -m) in
    x86_64 | amd64) arch=amd64 ;;
    arm64 | aarch64) arch=arm64 ;;
    *) die "unsupported CPU $(uname -m)" ;;
  esac

  local dest_dir=$CACHE_DIR/bin/$version dest sum_file url expected actual tmp
  dest=$dest_dir/kubectl
  sum_file=$dest_dir/kubectl.sha256
  url=https://dl.k8s.io/release/$version/bin/$os/$arch/kubectl
  if [ -x "$dest" ] && [ -f "$sum_file" ] && [ "$(sha256_of "$dest")" = "$(tr -d '[:space:]' <"$sum_file")" ]; then
    echo "$dest"
    return
  fi

  expected=$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 30 "$url.sha256" | tr -d '[:space:]') ||
    die "could not download the checksum of kubectl $version"
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "the published checksum of kubectl $version is malformed"
  tmp=$(mktemp)
  if ! curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time "$DOWNLOAD_DEADLINE" --output "$tmp" "$url"; then
    rm -f -- "$tmp"
    die "could not download kubectl $version"
  fi
  actual=$(sha256_of "$tmp")
  if [ "$actual" != "$expected" ]; then
    rm -f -- "$tmp"
    die "the sha256 of the downloaded kubectl $version does not match the published one"
  fi
  mkdir -p -- "$dest_dir"
  chmod 755 "$tmp"
  mv -f -- "$tmp" "$dest_dir/.kubectl.new"
  mv -f -- "$dest_dir/.kubectl.new" "$dest"
  echo "$expected" >"$sum_file"
  echo "$dest"
}

main() {
  local command=${1:-}
  [ $# -gt 0 ] && shift
  case $command in
    up) cmd_up "$@" ;;
    down) cmd_down "$@" ;;
    kubeconfig) cmd_kubeconfig "$@" ;;
    kubectl) cmd_kubectl "$@" ;;
    -h | --help | help | "") usage ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
