ARG RUST_IMAGE=rust-pinned

FROM docker.io/library/rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS rust-pinned

FROM ${RUST_IMAGE} AS builder
ENV CARGO_INCREMENTAL=0
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eu \
    && RUSTUP_TOOLCHAIN=$(cd / && rustup toolchain list | awk 'NR == 1 { print $1 }') \
    && test -n "$RUSTUP_TOOLCHAIN" \
    && export RUSTUP_TOOLCHAIN \
    && cargo build --release --locked -p jauntd -p jaunt-agent -p jaunt \
    && install -d /out \
    && install -m 0755 target/release/jauntd target/release/jaunt-agent target/release/jaunt /out/

FROM scratch AS binaries
COPY --from=builder /out/jauntd /out/jaunt-agent /out/jaunt /

FROM docker.io/library/debian:13-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0 AS jauntd
RUN groupadd --system --gid 65532 jaunt \
    && useradd --system --uid 65532 --gid 65532 --no-create-home --home-dir /var/lib/jaunt --shell /usr/sbin/nologin jaunt \
    && install -d -m 0755 /etc/jaunt \
    && install -d -m 0700 -o 65532 -g 65532 /var/lib/jaunt
COPY --from=builder /out/jauntd /usr/local/bin/jauntd
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="jauntd" \
      org.opencontainers.image.description="Jaunt control daemon" \
      org.opencontainers.image.source="https://github.com/GlobalArtInc/jaunt" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"
USER 65532:65532
WORKDIR /var/lib/jaunt
EXPOSE 8443 8444
ENTRYPOINT ["/usr/local/bin/jauntd"]
CMD ["run"]
