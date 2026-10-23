//! External types stubs to allow the crate to compile standalone since IAM crate might be empty right now.

/// A simple stub for the SPIFFE ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    uri: String,
}

impl SpiffeId {
    /// Creates a new `SpiffeId` from a URI string.
    pub fn new(uri: String) -> Self {
        Self { uri }
    }

    /// Returns the URI as a string slice.
    pub fn uri(&self) -> &str {
        &self.uri
    }
}
