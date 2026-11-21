use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, Key, KeyInit},
};
use redis::{AsyncTypedCommands, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    redis: ConnectionManager,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateSecretRequest {
    secret: String,
    expiry: Option<u16>,
}

#[derive(Debug, Serialize)]
struct CreateSecretResponse {
    identifier: String,
    enc_decrypted_key: String,
    expiry: Option<u16>,
}

#[tokio::main]
async fn main() {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let client = redis::Client::open(redis_url).unwrap();
    let redis = client.get_connection_manager().await.unwrap();

    let state = AppState { redis };

    let app = Router::new()
        .route("/secrets", post(create_secret))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn create_secret(
    State(mut state): State<AppState>,
    Json(payload): Json<CreateSecretRequest>,
) -> Result<Json<CreateSecretResponse>, StatusCode> {
    let key = Key::<XChaCha20Poly1305>::generate();
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XNonce::generate();
    let ciphertext = cipher
        .encrypt(&nonce, payload.secret.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);

    let identifier = Uuid::new_v4().to_string();
    let ttl_secs = u64::from(payload.expiry.unwrap_or(1800));
    let encoded_payload = URL_SAFE_NO_PAD.encode(&combined);

    state
        .redis
        .set_ex(&identifier, encoded_payload, ttl_secs)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateSecretResponse {
        identifier,
        enc_decrypted_key: URL_SAFE_NO_PAD.encode(key),
        expiry: payload.expiry,
    }))
}
