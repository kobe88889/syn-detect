use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use serde_json::json;
use std::time::Duration;
use crate::stats::Stats;
use futures_util::{StreamExt, SinkExt};

pub async fn run_server(stats_rx: tokio::sync::watch::Receiver<Stats>) {
    let listener = TcpListener::bind("127.0.0.1:8082").await.unwrap();
    while let Ok((stream, _)) = listener.accept().await {
        let ws_stream = accept_async(stream).await.unwrap();
        let (mut write, _read) = ws_stream.split();
        let mut rx = stats_rx.clone();
        while rx.changed().await.is_ok() {
            let stats = rx.borrow().clone();
            let msg = Message::Text(json!({
    "bps": stats.bits_per_sec,
    "entropy": stats.entropy,
    "alert": stats.alert
}).to_string());
            if let Err(_) = write.send(msg).await {
    // 浏览器断开时忽略错误，继续服务其他人
}
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }
}