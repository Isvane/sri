use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, Key, KeyInit},
};
use redis::{AsyncCommands, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    redis: ConnectionManager,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateSecretRequest {
    secret: String,
    expiry: Option<u64>,
}

#[derive(Debug, Serialize)]
struct CreateSecretResponse {
    identifier: String,
    encoded_key: String,
    expiry: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RevealSecretRequest {
    decryption_key: String,
}

#[derive(Debug, Serialize)]
struct RevealSecretResponse {
    secret: String,
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
        .route("/reveal/{identifier}", post(reveal_secret))
        .route("/status/{identifier}", get(status))
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
    let ttl_secs = payload.expiry.unwrap_or(1800);
    let clamped_ttl = ttl_secs.clamp(600, 604800);

    let _: () = state
        .redis
        .set_ex(&identifier, combined, clamped_ttl)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateSecretResponse {
        identifier,
        encoded_key: URL_SAFE_NO_PAD.encode(key),
        expiry: Some(clamped_ttl),
    }))
}

async fn status(
    State(mut state): State<AppState>,
    Path(identifier): Path<String>,
) -> Result<String, StatusCode> {
    let exp: i64 = state
        .redis
        .expire_time(&identifier)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match exp {
        -2 => Err(StatusCode::NOT_FOUND),
        ts => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .as_secs() as i64;

            let remaining = ts - now;
            let hours = remaining / 3600;
            let mins = (remaining % 3600) / 60;
            let secs = remaining % 60;
            Ok(format!("Expires in {hours}h {mins}m {secs}s"))
        }
    }
}

async fn reveal_secret(
    State(mut state): State<AppState>,
    Path(identifier): Path<String>,
    Json(payload): Json<RevealSecretRequest>,
) -> Result<Json<RevealSecretResponse>, StatusCode> {
    let key_bytes = URL_SAFE_NO_PAD
        .decode(&payload.decryption_key)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| StatusCode::BAD_REQUEST)?;

    let key = Key::<XChaCha20Poly1305>::from(key_array);
    let cipher = XChaCha20Poly1305::new(&key);

    let combined: Vec<u8> = state
        .redis
        .get_del(&identifier)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if combined.len() < 24 {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let nonce_array: [u8; 24] = combined[..24]
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let nonce = XNonce::from(nonce_array);
    let ciphertext = &combined[24..];

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let secret = String::from_utf8(plaintext).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(RevealSecretResponse { secret }))
}
