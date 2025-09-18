#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Stats {
    pub bits_per_sec: u64,
    pub entropy:      f32,
    pub alert:        bool,
}