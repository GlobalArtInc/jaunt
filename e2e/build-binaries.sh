#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
engine=${CONTAINER_ENGINE:-podman}
source "$repo/scripts/linux-build.sh"
build_linux_binaries -p jauntd -p jaunt-agent -p jaunt -p jaunt-fake-idp
