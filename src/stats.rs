#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Stats {
    pub bits_per_sec: u64,
    pub entropy:      f32,
    pub alert:        bool,
}

pub fn entropy_from_counts(counts: &[u64]) -> f32 {
    let total: u64 = counts.iter().sum();
    if total == 0 { return 0.0; }
    let total_f = total as f32;
    let mut entropy = 0.0;
    for &c in counts {
        if c == 0 { continue; }
        let p = c as f32 / total_f;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    // 原来就有的 3 个
    #[test]
    fn entropy_zero() {
        let counts = vec![10];
        assert_eq!(entropy_from_counts(&counts), 0.0);
    }

    #[test]
    fn entropy_max() {
        let counts = vec![5, 5, 5, 5];
        let h = entropy_from_counts(&counts);
        assert!((h - 2.0).abs() < 0.01);
    }

    #[test]
    fn alert_true() {
        let s = Stats { bits_per_sec: 100, entropy: 2.8, alert: true };
        assert!(s.alert);
    }

    // 新加的 2 个
    use std::collections::HashMap;
    #[test]
    fn entropy_4_ip() {
        let mut m = HashMap::new();
        m.insert("A".to_string(), 5);
        m.insert("B".to_string(), 5);
        m.insert("C".to_string(), 5);
        m.insert("D".to_string(), 5);
        assert!((crate::calc_entropy(&m) - 2.0).abs() < 0.01);
    }

    #[test]
    fn alert_at_2() {
        assert!(crate::calc_entropy(&HashMap::new()) >= 0.0);
        assert!(crate::alert_threshold(2.1));
        assert!(!crate::alert_threshold(1.9));
    }
}