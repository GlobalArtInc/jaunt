fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

test:
    cargo test --workspace --locked

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
