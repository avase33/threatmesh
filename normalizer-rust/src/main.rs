//! threatmesh normalizer service (axum) + `--stdin` CLI mode.
//!
//!   threatmesh-normalizer                 # serve on :8090
//!   echo '<logline>' | threatmesh-normalizer --stdin

use std::io::Read;

use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use threatmesh_normalizer::parse;

#[derive(Deserialize)]
struct NormReq {
    lines: Vec<String>,
}

async fn normalize(Json(req): Json<NormReq>) -> Json<serde_json::Value> {
    let records = parse::normalize(&req.lines);
    Json(serde_json::json!({ "records": records }))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "normalizer" }))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--stdin") {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).ok();
        let lines: Vec<String> = buf.lines().map(|s| s.to_string()).collect();
        let records = parse::normalize(&lines);
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "records": records })).unwrap()
        );
        return;
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/normalize", post(normalize));
    let addr = std::env::var("NORMALIZER_ADDR").unwrap_or_else(|_| "0.0.0.0:8090".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("threatmesh normalizer listening on {addr}");
    axum::serve(listener, app).await.expect("serve");
}
