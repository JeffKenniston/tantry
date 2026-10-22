use crate::error::IamError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpiffeId {
    uri: String,
    trust_domain: String,
}

impl SpiffeId {
    pub fn parse(uri: &str) -> Result<Self, IamError> {
        if !uri.starts_with("spiffe://") {
            return Err(IamError::InvalidSpiffeId("Missing spiffe:// scheme".into()));
        }
        let rest = &uri["spiffe://".len()..];
        if rest.is_empty() {
            return Err(IamError::InvalidSpiffeId("Empty trust domain".into()));
        }

        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        let trust_domain = parts[0];
        if trust_domain.is_empty() {
            return Err(IamError::InvalidSpiffeId("Empty trust domain".into()));
        }

        if uri.contains("/./") || uri.contains("/../") {
            return Err(IamError::InvalidSpiffeId("Contains . or .. segments".into()));
        }

        Ok(Self {
            uri: uri.to_string(),
            trust_domain: trust_domain.to_string(),
        })
    }

    pub fn derive_subagent(&self, subagent_name: &str, child_task_id: &str) -> Result<Self, IamError> {
        let child_uri = format!("{}/subagent/{}/task/{}", self.uri, subagent_name, child_task_id);
        if !child_uri.starts_with(&format!("{}/subagent/", self.uri)) {
            return Err(IamError::HierarchyViolation {
                parent: self.uri.clone(),
                child: child_uri,
            });
        }
        Self::parse(&child_uri)
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }
}

impl std::fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.uri)
    }
}
