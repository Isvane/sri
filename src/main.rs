use axum::{Router, extract::State, routing::get};
use redis::{AsyncTypedCommands, aio::ConnectionManager};

#[derive(Clone)]
struct AppState {
    redis: ConnectionManager,
}

#[tokio::main]
async fn main() {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let client = redis::Client::open(redis_url).unwrap();
    let redis = client.get_connection_manager().await.unwrap();

    let state = AppState { redis };

    let app = Router::new().route("/", get(handler)).with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handler(State(mut state): State<AppState>) -> String {
    let _: () = state.redis.set_ex("key", "value", 1800).await.unwrap();
    state
        .redis
        .get_del("key")
        .await
        .unwrap()
        .expect("Key should exist after SET")
}
