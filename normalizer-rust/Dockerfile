FROM rust:1.79-slim AS build
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release --bin threatmesh-normalizer

FROM debian:bookworm-slim
COPY --from=build /app/target/release/threatmesh-normalizer /usr/local/bin/threatmesh-normalizer
ENV NORMALIZER_ADDR=0.0.0.0:8090
EXPOSE 8090
CMD ["threatmesh-normalizer"]
