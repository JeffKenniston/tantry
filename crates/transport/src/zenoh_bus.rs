use permissions::ext::SpiffeId;
use permissions::zenoh_guard::evaluate_zenoh_topic;
use permissions::lattice::PermissionMode;
use zenoh::config::Config;
use zenoh::Session;
use thiserror::Error;
use zenoh::pubsub::Subscriber;
use zenoh::sample::Sample;
use zenoh::handlers::FifoChannelHandler;

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
}
