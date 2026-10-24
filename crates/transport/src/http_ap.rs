/// Agent Protocol HTTP Transport Module


use reqwest::Client;
use serde_json::Value;

use crate::TransportError;

/// Agent Protocol HTTP Transport
#[derive(Debug)]
pub struct AgentProtocolHttpTransport {
    client: Client,
    base_url: String,
}

impl AgentProtocolHttpTransport {
    /// Creates a new AgentProtocolHttpTransport
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    /// POST /threads
    pub async fn create_thread(&self) -> Result<Value, TransportError> {
        let url = format!("{}/threads", self.base_url);
        self.client.post(&url)
            .send()
            .await
            .map_err(|e| TransportError::Internal(e.to_string()))?
            .json()
            .await
            .map_err(|e| TransportError::Internal(e.to_string()))
    }

    /// POST /threads/{thread_id}/runs
    pub async fn create_run(&self, thread_id: &str, input: Value) -> Result<Value, TransportError> {
        let url = format!("{}/threads/{}/runs", self.base_url, thread_id);
        self.client.post(&url)
            .json(&input)
            .send()
            .await
            .map_err(|e| TransportError::Internal(e.to_string()))?
            .json()
            .await
            .map_err(|e| TransportError::Internal(e.to_string()))
    }

    /// GET /threads/{thread_id}/runs/{run_id}
    pub async fn get_run(&self, thread_id: &str, run_id: &str) -> Result<Value, TransportError> {
        let url = format!("{}/threads/{}/runs/{}", self.base_url, thread_id, run_id);
        self.client.get(&url)
            .send()
            .await
            .map_err(|e| TransportError::Internal(e.to_string()))?
            .json()
            .await
            .map_err(|e| TransportError::Internal(e.to_string()))
    }

    /// POST /threads/{thread_id}/runs/{run_id}/cancel
    pub async fn cancel_run(&self, thread_id: &str, run_id: &str) -> Result<Value, TransportError> {
        let url = format!("{}/threads/{}/runs/{}/cancel", self.base_url, thread_id, run_id);
        self.client.post(&url)
            .send()
            .await
            .map_err(|e| TransportError::Internal(e.to_string()))?
            .json()
            .await
            .map_err(|e| TransportError::Internal(e.to_string()))
    }
}
