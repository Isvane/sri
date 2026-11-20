FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM alpine:latest

RUN apk add --no-cache ca-certificates \
    && adduser -D -s /bin/sh appuser

USER appuser

WORKDIR /app
COPY --from=builder /app/target/release/sri /usr/local/bin/sri

EXPOSE 3000

CMD ["sri"]
