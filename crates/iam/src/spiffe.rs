use crate::error::IamError;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    uri: Url,
}

impl SpiffeId {
    pub fn parse(uri_str: &str) -> Result<Self, IamError> {
        let uri = Url::parse(uri_str)
            .map_err(|_| IamError::InvalidSpiffeId("Invalid URL format".to_string()))?;

        if uri.scheme() != "spiffe" {
            return Err(IamError::InvalidSpiffeId(
                "Scheme must be spiffe://".to_string(),
            ));
        }

        if uri.host_str().is_none() || uri.host_str().unwrap().is_empty() {
            return Err(IamError::InvalidSpiffeId(
                "Trust domain (host) cannot be empty".to_string(),
            ));
        }

        let path = uri.path();
        if path.is_empty() || path == "/" {
            return Err(IamError::InvalidSpiffeId(
                "Path cannot be empty".to_string(),
            ));
        }

        for segment in uri.path_segments().unwrap_or("".split('/')) {
            if segment == "." || segment == ".." {
                return Err(IamError::InvalidSpiffeId(
                    "Path segments cannot be . or ..".to_string(),
                ));
            }
        }

        Ok(Self { uri })
    }

    pub fn derive_subagent(
        &self,
        subagent_name: &str,
        child_task_id: &str,
    ) -> Result<Self, IamError> {
        let mut new_uri = self.uri.clone();
        let mut path = new_uri.path().to_string();
        if path.ends_with('/') {
            path.pop();
        }

        path.push_str(&format!(
            "/subagent/{}/task/{}",
            subagent_name, child_task_id
        ));
        new_uri.set_path(&path);

        let expected_prefix = format!("{}/subagent/", self.uri.as_str());
        if !new_uri.as_str().starts_with(&expected_prefix) {
            return Err(IamError::HierarchyViolation {
                parent: self.uri.to_string(),
                child: new_uri.to_string(),
            });
        }

        Ok(Self { uri: new_uri })
    }

    pub fn uri(&self) -> &str {
        self.uri.as_str()
    }
}
