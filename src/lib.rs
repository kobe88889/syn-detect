pub mod stats;
pub use stats::entropy_from_counts;
pub use stats::Stats;

use std::collections::HashMap;

pub fn calc_entropy(counter: &HashMap<String, u32>) -> f32 {
    let total: f32 = counter.values().sum::<u32>() as f32;
    if total == 0.0 { return 0.0; }
    let mut entropy = 0.0;
    for &c in counter.values() {
        let p = c as f32 / total;
        entropy -= p * p.log2();
    }
    entropy
}

pub fn alert_threshold(entropy: f32) -> bool {
    entropy > 2.0   // 临时阈值，论文写 7
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    pub fn update_stats(counter: &HashMap<String, u32>) -> (u32, f32, bool) {
    let total = counter.values().sum::<u32>();
    let counts: Vec<u64> = counter.values().map(|&v| v as u64).collect();
    let entropy = entropy_from_counts(&counts);
    let alert = alert_threshold(entropy);
    (total, entropy, alert)
}

    #[test]
    fn pipeline_60pct() {
        let mut m = HashMap::new();
        m.insert("A".to_string(), 5);
        m.insert("B".to_string(), 5);
        m.insert("C".to_string(), 5);
        m.insert("D".to_string(), 5);
        let (total, entropy, alert) = update_stats(&m);
        assert_eq!(total, 20);
        assert!(entropy > 1.9);
        assert!(!alert);
    }
}