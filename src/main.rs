use pcap::{Capture, Device};
use std::collections::HashMap;
use std::time::{Duration, Instant};
mod stats;
mod ws_push;
use tokio::sync::watch;
use stats::Stats;

#[tokio::main]
async fn main() {
    let (tx, rx) = watch::channel(Stats {
    bits_per_sec: 0,
    entropy: 0.0,
    alert: false,
});
    tokio::spawn(ws_push::run_server(rx));
    old_main(tx);
}


fn old_main(tx: watch::Sender<Stats>) {
    let dev = Device::list()
        .unwrap_or_default()
        .into_iter()
        .find(|d| d.desc.as_ref().map_or(false, |s| s.contains("Wi-Fi")))
        .or_else(|| Device::lookup().ok().flatten())
        .expect("没有可用网卡");

    println!("用网卡：{}", dev.desc.clone().unwrap_or_else(|| "无描述".into()));

    let mut cap = Capture::from_device(dev).unwrap().immediate_mode(true).open().unwrap();
    cap.filter("tcp[tcpflags] & tcp-syn != 0", true).unwrap();

    let mut counter = HashMap::<String, u32>::new();
    let mut last = Instant::now();

    while let Ok(pkt) = cap.next_packet() {
        if pkt.data.len() > 34 {
            let src = format!("{}.{}.{}.{}", pkt.data[26], pkt.data[27], pkt.data[28], pkt.data[29]);
            *counter.entry(src).or_insert(0) += 1;
        }
        if last.elapsed() >= Duration::from_secs(1) {
    let total = counter.values().sum::<u32>();

    let dst = format!("{}.{}.{}.{}", pkt.data[30], pkt.data[31], pkt.data[32], pkt.data[33]);
*counter.entry(dst).or_insert(0) += 1;

    // ① 先算熵
    let total_f = total as f32;
    let mut entropy = 0_f32;
    for &c in counter.values() {
        let p = c as f32 / total_f;
        entropy -= p * p.log2();
    }
    let alert = entropy > 2.5;

    // ② 再打印
    println!("=== {} syn/s  entropy={:.1}  alert={} ===", total, entropy, alert);

    // ③ 最后发送
    tx.send(Stats {
        bits_per_sec: (total as u64) * 8,
        entropy,
        alert,
    }).ok();

    counter.clear();
    last = Instant::now();
}
    }
}