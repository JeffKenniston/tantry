use permissions::ext::SpiffeId;
use permissions::zenoh_guard::evaluate_zenoh_topic;
use permissions::lattice::PermissionMode;
use zenoh::config::Config;
use zenoh::Session;
use thiserror::Error;
use zenoh::pubsub::Subscriber;
use zenoh::sample::Sample;
use zenoh::handlers::FifoChannelHandler;
use zenoh::query::{Query, Queryable, Reply};

/// TransportError enum
#[derive(Debug, Error, PartialEq)]
pub enum TransportError {
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
    /// Authorization error
    #[error("Authorization error: {0}")]
    AuthorizationError(String),
}

/// Zenoh 1.10.1 Mesh Transport
pub struct ZenohBusTransport {
    session: Session,
    svid: SpiffeId,
}

impl ZenohBusTransport {
    /// Creates a new ZenohBusTransport
    pub async fn new(svid: SpiffeId, task_id: &str, is_termux_or_local: bool) -> Result<Self, TransportError> {
        let mut config = Config::default();
        if is_termux_or_local {
            let prefix = std::env::var("PREFIX").unwrap_or_else(|_| "".to_string());
            let path = format!("\"unixsock-stream/{}/var/run/tantry/zenoh-{}.sock\"", prefix, task_id);
            config.insert_json5("listen/endpoints", &format!("[{}]", path)).map_err(|_| TransportError::Internal("invalid endpoint".into()))?;
        } else {
            // For remote peers, configures zenoh 1.10.1 TLS/QUIC locators using SPIFFE X.509-SVID mTLS
            config.insert_json5("transport/link/tls/enable", "true").map_err(|_| TransportError::Internal("invalid tls enable".into()))?;
            config.insert_json5("transport/link/tls/certificate", "\"spiffe-cert.pem\"").map_err(|_| TransportError::Internal("invalid tls cert".into()))?;
            config.insert_json5("transport/link/tls/private_key", "\"spiffe-key.pem\"").map_err(|_| TransportError::Internal("invalid tls key".into()))?;
            config.insert_json5("transport/link/tls/root_ca_certificate", "\"spiffe-ca.pem\"").map_err(|_| TransportError::Internal("invalid root ca".into()))?;
            config.insert_json5("transport/link/quic/enable", "true").map_err(|_| TransportError::Internal("invalid quic enable".into()))?;
        }

        let session = zenoh::open(config).await.map_err(|_| TransportError::Internal("failed to open zenoh session".into()))?;

        Ok(Self {
            session,
            svid,
        })
    }

    /// Publishes a payload to a Zenoh topic
    pub async fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<(), TransportError> {
        if evaluate_zenoh_topic(&self.svid, topic, true) != PermissionMode::Allow {
            return Err(TransportError::AuthorizationError("zenoh publish denied".into()));
        }
        self.session.put(topic, payload).await.map_err(|_| TransportError::Internal("zenoh put failed".into()))?;
        Ok(())
    }

    /// Subscribes to a Zenoh topic
    pub async fn subscribe(&self, topic: &str) -> Result<Subscriber<FifoChannelHandler<Sample>>, TransportError> {
        if evaluate_zenoh_topic(&self.svid, topic, false) != PermissionMode::Allow {
            return Err(TransportError::AuthorizationError("zenoh subscribe denied".into()));
        }
        self.session.declare_subscriber(topic).await.map_err(|_| TransportError::Internal("zenoh subscribe failed".into()))
    }

    /// Queries a Zenoh topic
    pub async fn get(&self, topic: &str) -> Result<zenoh::handlers::FifoChannelHandler<Reply>, TransportError> {
        if evaluate_zenoh_topic(&self.svid, topic, false) != PermissionMode::Allow {
            return Err(TransportError::AuthorizationError("zenoh get denied".into()));
        }
        self.session.get(topic).await.map_err(|_| TransportError::Internal("zenoh get failed".into()))
    }

    /// Declares a queryable on a Zenoh topic
    pub async fn declare_queryable(&self, topic: &str) -> Result<Queryable<FifoChannelHandler<Query>>, TransportError> {
        if evaluate_zenoh_topic(&self.svid, topic, true) != PermissionMode::Allow {
            return Err(TransportError::AuthorizationError("zenoh declare_queryable denied".into()));
        }
        self.session.declare_queryable(topic).await.map_err(|_| TransportError::Internal("zenoh declare_queryable failed".into()))
    }
}
