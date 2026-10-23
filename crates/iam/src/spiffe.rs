use crate::error::IamError;
use url::Url;

/// Represents a validated SpiffeId URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    uri: Url,
}

impl SpiffeId {
    /// Parses a raw string into a validated SpiffeId.
    /// Returns an IamError if the scheme is not `spiffe://`,
    /// or if there are invalid path segments.
    pub fn parse(uri_str: &str) -> Result<Self, IamError> {
        if uri_str.contains("/../") || uri_str.ends_with("/..") {
             return Err(IamError::InvalidSpiffeId("Path segments cannot be . or ..".to_string()));
        }

        let uri = Url::parse(uri_str).map_err(|_| IamError::InvalidSpiffeId("Invalid URL format".to_string()))?;

        if uri.scheme() != "spiffe" {
            return Err(IamError::InvalidSpiffeId("Scheme must be spiffe://".to_string()));
        }

        if uri.host_str().is_none() || uri.host_str().unwrap().is_empty() {
            return Err(IamError::InvalidSpiffeId("Trust domain (host) cannot be empty".to_string()));
        }

        let path = uri.path();
        if path.is_empty() || path == "/" {
            return Err(IamError::InvalidSpiffeId("Path cannot be empty".to_string()));
        }

        for segment in uri.path_segments().unwrap_or("".split('/')) {
            if segment.is_empty() {
                return Err(IamError::InvalidSpiffeId("Path segments cannot be empty".to_string()));
            }
            if segment == "." || segment == ".." {
                return Err(IamError::InvalidSpiffeId("Path segments cannot be . or ..".to_string()));
            }
        }

        Ok(Self { uri })
    }

    /// Derives a new SpiffeId subagent from the current parent ID.
    /// Ensures the resulting child URI correctly starts with the parent URI prefix.
    pub fn derive_subagent(&self, subagent_name: &str, child_task_id: &str) -> Result<Self, IamError> {
        let mut new_uri = self.uri.clone();
        let mut path = new_uri.path().to_string();
        if path.ends_with('/') {
            path.pop();
        }

        path.push_str(&format!("/subagent/{}/task/{}", subagent_name, child_task_id));
        new_uri.set_path(&path);

        let expected_prefix = format!("{}/subagent/", self.uri.as_str());
        if !new_uri.as_str().starts_with(&expected_prefix) {
            return Err(IamError::HierarchyViolation {
                parent: self.uri.to_string(),
                child: new_uri.to_string()
            });
        }

        Ok(Self { uri: new_uri })
    }

    /// Returns the underlying SpiffeId URI as a string slice.
    pub fn uri(&self) -> &str {
        self.uri.as_str()
    }
}
