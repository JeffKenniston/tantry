use crate::error::IamError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    uri: String,
}

impl SpiffeId {
    pub fn parse(uri_str: &str) -> Result<Self, IamError> {
        let prefix = "spiffe://";
        if !uri_str.starts_with(prefix) {
            return Err(IamError::InvalidSpiffeId(
                "Scheme must be spiffe://".to_string(),
            ));
        }

        let without_scheme = &uri_str[prefix.len()..];
        let Some(slash_idx) = without_scheme.find('/') else {
            return Err(IamError::InvalidSpiffeId(
                "Missing path after trust domain".to_string(),
            ));
        };

        let trust_domain = &without_scheme[..slash_idx];
        let path = &without_scheme[slash_idx..];

        if trust_domain.is_empty() {
            return Err(IamError::InvalidSpiffeId(
                "Trust domain cannot be empty".to_string(),
            ));
        }

        for c in trust_domain.chars() {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '.' && c != '-' {
                return Err(IamError::InvalidSpiffeId(
                    "Invalid characters in trust domain".to_string(),
                ));
            }
        }

        if path.is_empty() || path == "/" {
            return Err(IamError::InvalidSpiffeId(
                "Path cannot be empty".to_string(),
            ));
        }

        let path_to_split = if path.starts_with('/') { &path[1..] } else { path };
        let segments: Vec<&str> = path_to_split.split('/').collect();

        if segments.len() < 4 || segments[0] != "agent" || segments[2] != "task" {
            return Err(IamError::InvalidSpiffeId(
                "Path must follow /agent/{agent_name}/task/{task_id}".to_string(),
            ));
        }

        if segments.len() % 4 != 0 {
            return Err(IamError::InvalidSpiffeId(
                "Path must only contain root agent and pairs of /subagent/{name}/task/{id}".to_string(),
            ));
        }

        let mut i = 4;
        while i < segments.len() {
            if segments[i] != "subagent" || segments[i + 2] != "task" {
                return Err(IamError::InvalidSpiffeId(
                    "Path suffix must be strictly pairs of /subagent/{name}/task/{id}".to_string(),
                ));
            }
            i += 4;
        }

        for segment in &segments {
            if *segment == "." || *segment == ".." || segment.is_empty() {
                return Err(IamError::InvalidSpiffeId(
                    "Path segments cannot be empty, ., or ..".to_string(),
                ));
            }
        }

        Ok(Self { uri: uri_str.to_string() })
    }

    pub fn new_root_agent(trust_domain: &str, agent_name: &str, task_id: &str) -> Result<Self, IamError> {
        let uri = format!("spiffe://{trust_domain}/agent/{agent_name}/task/{task_id}");
        Self::parse(&uri)
    }

    pub fn derive_subagent(
        &self,
        subagent_name: &str,
        child_task_id: &str,
    ) -> Result<Self, IamError> {
        if subagent_name.is_empty() || child_task_id.is_empty() {
            return Err(IamError::InvalidSpiffeId("subagent_name or child_task_id is empty".to_string()));
        }
        for segment in [subagent_name, child_task_id] {
            if segment.contains('/') || segment.contains('.') || segment == ".." {
                return Err(IamError::InvalidSpiffeId(
                    "Segments cannot contain '/', '.', or '..'".to_string(),
                ));
            }
        }

        let mut base_str = self.uri.clone();
        if base_str.ends_with('/') {
            base_str.pop();
        }

        let new_uri = format!("{}/subagent/{}/task/{}", base_str, subagent_name, child_task_id);
        let expected_prefix = format!("{}/subagent/", base_str);

        let child = Self::parse(&new_uri)?;

        if !child.uri().starts_with(&expected_prefix) {
            return Err(IamError::HierarchyViolation {
                parent: self.uri.clone(),
                child: new_uri,
            });
        }

        Ok(child)
    }

    pub fn verify_attenuation(&self, child: &SpiffeId) -> Result<(), IamError> {
        if child.trust_domain() == self.trust_domain() && child.uri().starts_with(&format!("{}/subagent/", self.uri())) {
            Ok(())
        } else {
            Err(IamError::HierarchyViolation {
                parent: self.uri().to_string(),
                child: child.uri().to_string(),
            })
        }
    }

    pub fn is_subagent(&self) -> bool {
        self.uri.contains("/subagent/")
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn trust_domain(&self) -> &str {
        let prefix = "spiffe://";
        if self.uri.starts_with(prefix) {
            let without_scheme = &self.uri[prefix.len()..];
            if let Some(slash_idx) = without_scheme.find('/') {
                return &without_scheme[..slash_idx];
            }
        }
        ""
    }

    pub fn workload_path(&self) -> &str {
        let prefix = "spiffe://";
        if self.uri.starts_with(prefix) {
            let without_scheme = &self.uri[prefix.len()..];
            if let Some(slash_idx) = without_scheme.find('/') {
                return &without_scheme[slash_idx + 1..];
            }
        }
        ""
    }
}
