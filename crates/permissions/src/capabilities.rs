use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum FsCapability {
    Base,
    Composite {
        parent: Arc<FsCapability>,
        child: Arc<FsCapability>,
    },
}

#[derive(Debug, Clone)]
pub enum NetCapability {
    Base,
    Composite {
        parent: Arc<NetCapability>,
        child: Arc<NetCapability>,
    },
}

#[derive(Debug, Clone)]
pub enum EnvCapability {
    Base,
    Composite {
        parent: Arc<EnvCapability>,
        child: Arc<EnvCapability>,
    },
}

#[derive(Debug, Clone)]
pub enum McpCapability {
    Base {
        max_spend_micros: u64,
        effective_max_spend_micros: u64,
    },
    Composite {
        parent: Arc<McpCapability>,
        child: Arc<McpCapability>,
        max_spend_micros: u64,
        effective_max_spend_micros: u64,
    },
}

impl McpCapability {
    pub fn max_spend_micros(&self) -> u64 {
        match self {
            Self::Base { max_spend_micros, .. } => *max_spend_micros,
            Self::Composite { max_spend_micros, .. } => *max_spend_micros,
        }
    }
}
