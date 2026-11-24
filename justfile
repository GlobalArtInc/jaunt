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

fuzz-run target seconds:
    test -n "$(ls fuzz/seeds/{{target}} 2>/dev/null)" || { echo "fuzz target {{target}} has no seeds in fuzz/seeds"; exit 1; }
    mkdir -p fuzz/corpus/{{target}}
    CARGO_INCREMENTAL=0 cargo +nightly fuzz run {{target}} fuzz/corpus/{{target}} fuzz/seeds/{{target}} -- -max_total_time={{seconds}} -timeout=10 -rss_limit_mb=2048

fuzz-smoke:
    targets="$(cargo +nightly fuzz list)" && test -n "$targets" && for target in $targets; do just fuzz-run "$target" 60 || exit 1; done

installer-containers:
    scripts/test-installer.sh debian:12 debian:13 rockylinux:9

ssh-containers *images="debian:13 rockylinux:9":
    scripts/test-ssh-bridge.sh {{images}}

pg-migrations:
    : "${DATABASE_URL:?DATABASE_URL is required}"; for file in crates/jaunt-store/migrations/*.sql; do psql "$DATABASE_URL" -1 -v ON_ERROR_STOP=1 -q -f "$file" || exit 1; done

image:
    scripts/build-image.sh image

image-binaries:
    scripts/build-image.sh binaries
