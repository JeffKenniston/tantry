use crate::error::IamError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    uri: String,
    trust_domain: String,
    workload_path: String,
}

impl SpiffeId {
    pub fn parse(uri: &str) -> Result<Self, IamError> {
        if !uri.starts_with("spiffe://") {
            return Err(IamError::InvalidSpiffeId("must start with spiffe://".to_string()));
        }

        let stripped = &uri["spiffe://".len()..];
        let mut parts = stripped.splitn(2, '/');
        let trust_domain = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");

        if trust_domain.is_empty() {
            return Err(IamError::InvalidSpiffeId("trust domain cannot be empty".to_string()));
        }

        for c in trust_domain.chars() {
            if !((c.is_ascii_alphanumeric() && !c.is_ascii_uppercase()) || c == '.' || c == '-') {
                return Err(IamError::InvalidSpiffeId("invalid trust domain format".to_string()));
            }
        }

        let segments: Vec<&str> = path.split('/').collect();
        if segments.is_empty() || segments[0] != "agent" {
            return Err(IamError::InvalidSpiffeId("invalid path prefix".to_string()));
        }

        for segment in &segments {
            if segment.is_empty() || *segment == "." || *segment == ".." {
                return Err(IamError::InvalidSpiffeId("invalid path segment".to_string()));
            }
        }

        if segments.len() < 4 || segments[2] != "task" {
            return Err(IamError::InvalidSpiffeId("must have at least agent and task segments".to_string()));
        }

        let mut idx = 4;
        while idx < segments.len() {
            if segments.len() < idx + 4 {
                return Err(IamError::InvalidSpiffeId("incomplete subagent segments".to_string()));
            }
            if segments[idx] != "subagent" || segments[idx+2] != "task" {
                return Err(IamError::InvalidSpiffeId("invalid subagent format".to_string()));
            }
            idx += 4;
        }

        if idx != segments.len() {
            return Err(IamError::InvalidSpiffeId("trailing segments".to_string()));
        }

        Ok(Self {
            uri: uri.to_string(),
            trust_domain: trust_domain.to_string(),
            workload_path: path.to_string(),
        })
    }

    pub fn new_root_agent(trust_domain: &str, agent_name: &str, task_id: &str) -> Result<Self, IamError> {
        let uri = format!("spiffe://{}/agent/{}/task/{}", trust_domain, agent_name, task_id);
        Self::parse(&uri)
    }

    pub fn derive_subagent(&self, subagent_name: &str, child_task_id: &str) -> Result<Self, IamError> {
        if subagent_name.is_empty() || child_task_id.is_empty() {
            return Err(IamError::InvalidSpiffeId("empty derivation segments".to_string()));
        }
        if subagent_name.contains('/') || subagent_name.contains('.') || child_task_id.contains('/') || child_task_id.contains('.') {
            return Err(IamError::InvalidSpiffeId("invalid derivation segments".to_string()));
        }
        let child_uri = format!("{}/subagent/{}/task/{}", self.uri, subagent_name, child_task_id);
        let child = Self::parse(&child_uri)?;

        let prefix = format!("{}/subagent/", self.uri);
        if !child.uri.starts_with(&prefix) {
            return Err(IamError::HierarchyViolation { parent: self.uri.clone(), child: child.uri.clone() });
        }

        Ok(child)
    }

    pub fn verify_attenuation(&self, child: &SpiffeId) -> Result<(), IamError> {
        let prefix = format!("{}/subagent/", self.uri);
        if child.trust_domain == self.trust_domain && child.uri.starts_with(&prefix) {
            Ok(())
        } else {
            Err(IamError::HierarchyViolation { parent: self.uri.clone(), child: child.uri.clone() })
        }
    }

    pub fn is_subagent(&self) -> bool {
        self.uri.contains("/subagent/")
    }

    pub fn workload_path(&self) -> &str {
        &self.workload_path
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
}
