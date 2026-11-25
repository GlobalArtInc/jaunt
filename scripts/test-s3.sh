#!/usr/bin/env bash
set -euo pipefail

IMAGE=${JAUNT_S3_TEST_IMAGE:-cgr.dev/chainguard/minio@sha256:f6243be11aaaa2fe654d260558e2b3fcef50135e78a3abfd0db802b13444f059}
BUCKET=jaunt-recordings
REGION=us-east-1
DEADLINE=60
NAME=jaunt-s3-test-$$

container_started=0

cleanup() {
  if [ "$container_started" -eq 1 ]; then
    podman rm --force --volumes "$NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

command -v podman >/dev/null || { echo "podman is required"; exit 1; }
command -v curl >/dev/null || { echo "curl is required"; exit 1; }

access_key=jaunt-test-$(openssl rand -hex 6)
secret_key=$(openssl rand -hex 24)

podman run --detach --name "$NAME" \
  --publish 127.0.0.1::9000 \
  --mount type=tmpfs,destination=/data,tmpfs-mode=1777 \
  --env MINIO_ROOT_USER="$access_key" \
  --env MINIO_ROOT_PASSWORD="$secret_key" \
  "$IMAGE" server /data >/dev/null
container_started=1

port=$(podman port "$NAME" 9000/tcp | head -n 1 | sed 's/.*://')
endpoint=http://127.0.0.1:$port

waited=0
until curl --silent --fail --max-time 2 "$endpoint/minio/health/ready" >/dev/null 2>&1; do
  waited=$((waited + 1))
  if [ "$waited" -ge "$DEADLINE" ]; then
    echo "the object store did not become ready in ${DEADLINE}s"
    podman logs "$NAME" 2>&1 | tail -n 20
    exit 1
  fi
  sleep 1
done

curl --silent --show-error --fail --max-time 10 --request PUT \
  --aws-sigv4 "aws:amz:$REGION:s3" --user "$access_key:$secret_key" \
  "$endpoint/$BUCKET" >/dev/null

echo "object store image: $IMAGE"
JAUNT_S3_TEST_ENDPOINT=$endpoint \
JAUNT_S3_TEST_BUCKET=$BUCKET \
JAUNT_S3_TEST_ACCESS_KEY=$access_key \
JAUNT_S3_TEST_SECRET_KEY=$secret_key \
  cargo test -p jaunt-recording-s3 --locked --test s3 -- --ignored --test-threads=4
JAUNT_S3_TEST_ENDPOINT=$endpoint \
JAUNT_S3_TEST_BUCKET=$BUCKET \
JAUNT_S3_TEST_ACCESS_KEY=$access_key \
JAUNT_S3_TEST_SECRET_KEY=$secret_key \
  cargo test -p jauntd --locked --lib recordings::tests::the_verify_command_reads -- --ignored
