use crate::error::IamError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    uri: String,
}

impl SpiffeId {
    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn parse(uri: &str) -> Result<Self, IamError> {
        if !uri.starts_with("spiffe://") {
            return Err(IamError::InvalidSpiffeId("Must start with spiffe:// scheme".to_string()));
        }

        let without_scheme = &uri["spiffe://".len()..];
        if without_scheme.is_empty() {
            return Err(IamError::InvalidSpiffeId("Empty trust domain".to_string()));
        }

        let mut parts = without_scheme.split('/');
        let trust_domain = parts.next().ok_or_else(|| IamError::InvalidSpiffeId("Missing trust domain".to_string()))?;

        if trust_domain.is_empty() {
            return Err(IamError::InvalidSpiffeId("Empty trust domain".to_string()));
        }

        // Simple RFC 3986 trust domain check (just alphanum, -, . for now, but not checking strictly unless needed)
        // Ensure no empty segments and no . or ..
        for segment in parts {
            if segment.is_empty() {
                return Err(IamError::InvalidSpiffeId("Empty path segment".to_string()));
            }
            if segment == "." || segment == ".." {
                return Err(IamError::InvalidSpiffeId("Path traversal segments not allowed".to_string()));
            }
        }

        Ok(SpiffeId {
            uri: uri.to_string(),
        })
    }

    pub fn derive_subagent(&self, subagent_name: &str, child_task_id: &str) -> Result<Self, IamError> {
        if subagent_name.is_empty() || child_task_id.is_empty() || subagent_name.contains('/') || child_task_id.contains('/') {
            return Err(IamError::InvalidSpiffeId("Invalid subagent name or task id".to_string()));
        }
        if subagent_name == "." || subagent_name == ".." || child_task_id == "." || child_task_id == ".." {
            return Err(IamError::InvalidSpiffeId("Path traversal segments not allowed".to_string()));
        }

        let child_uri = format!("{}/subagent/{}/task/{}", self.uri, subagent_name, child_task_id);

        let expected_prefix = format!("{}/subagent/", self.uri);
        if !child_uri.starts_with(&expected_prefix) {
            return Err(IamError::HierarchyViolation {
                parent: self.uri.clone(),
                child: child_uri,
            });
        }

        // Verify the newly generated child URI is a valid SpiffeId
        Self::parse(&child_uri)
    }
}
