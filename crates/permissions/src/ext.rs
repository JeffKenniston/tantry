//! External types stubs to allow the crate to compile standalone since IAM crate might be empty right now.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    uri: String,
}

impl SpiffeId {
    pub fn new(uri: String) -> Self {
        Self { uri }
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }
}

pub struct ScopedTunnelRegistry {}

impl ScopedTunnelRegistry {
    pub fn is_service_active(&self, _host: &str, _now_ms: i64) -> bool {
        false
    }
}
