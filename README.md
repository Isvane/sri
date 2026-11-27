# sri

Minimal burn-after-reading secret sharing API built with Axum and Redis. Secrets are encrypted with `XChaCha20-Poly1305` using a random key returned only to the creator and never stored on the server.

## Quick Start

```sh
docker compose up --build -d
```

