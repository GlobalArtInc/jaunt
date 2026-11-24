fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

test:
    cargo test --workspace --locked
    cargo test --release -p jaunt-ca --locked

deny:
    cargo deny check

boundaries:
    scripts/check-boundaries.sh

ci:
    cargo fmt --all --check
    just lint
    just test
    just deny
    just boundaries

installer-containers:
    scripts/test-installer.sh debian:12 debian:13 rockylinux:9

ssh-containers:
    scripts/test-ssh-bridge.sh debian:13

pg-migrations:
    : "${DATABASE_URL:?DATABASE_URL is required}"; for file in crates/jaunt-store/migrations/*.sql; do psql "$DATABASE_URL" -1 -v ON_ERROR_STOP=1 -q -f "$file" || exit 1; done

image:
    scripts/build-image.sh image

image-binaries:
    scripts/build-image.sh binaries
