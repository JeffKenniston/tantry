use crate::error::BackendError;
use crate::traits::VfsBackend;
use base::config::WasmSandboxConfig;
use base::state::TantryState;
use std::sync::Arc;
use std::time::Duration;
use wasmparser::{Parser, Payload};
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{
    ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView, p2::add_to_linker_async,
};

use base::path::validate_and_normalize_path;
use iam::IdentityManager;
use iam::tunnel_grant::ScopedTunnelRegistry;
use repo::engine::RepoEngine;

/// WasmHostState struct
pub struct WasmHostState {
    /// StoreLimits
    pub limits: StoreLimits,
    /// WasiCtx
    pub wasi: WasiCtx,
    /// ResourceTable
    pub table: ResourceTable,
    pub state: Arc<std::sync::Mutex<TantryState>>,
    pub vfs: Arc<dyn VfsBackend + Send + Sync>,
    pub identity_manager: Arc<dyn IdentityManager + Send + Sync>,
    pub tunnel_registry: Arc<ScopedTunnelRegistry>,
    pub repo_engine: Option<Arc<RepoEngine>>,
}

impl WasiView for WasmHostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

wasmtime::component::bindgen!({
    world: "eval-sandbox",
    path: "../../wit",
    imports: {
        default: async,
    },
    exports: {
        default: async,
    },
});

impl tantry::runtime::fs::Host for WasmHostState {
    async fn read_file(&mut self, path: String) -> Result<String, String> {
        let normalized = validate_and_normalize_path(&path)
            .map_err(|e| e.to_string())?
            .to_string();
        let state = self.state.lock().unwrap();
        // PermissionLattice logic to be integrated properly
        self.vfs
            .read_file(&state, &normalized, None, None)
            .map_err(|e| e.to_string())
    }
    async fn write_file(&mut self, path: String, content: String) -> Result<(), String> {
        let normalized = validate_and_normalize_path(&path)
            .map_err(|e| e.to_string())?
            .to_string();
        let mut state = self.state.lock().unwrap();
        self.vfs
            .write_file(&mut state, &normalized, &content)
            .map_err(|e| e.to_string())
            .map(|_| ())
    }
    async fn list_dir(&mut self, path: String) -> Result<Vec<String>, String> {
        let normalized = validate_and_normalize_path(&path)
            .map_err(|e| e.to_string())?
            .to_string();
        let state = self.state.lock().unwrap();
        self.vfs
            .ls(&state, &normalized)
            .map(|v| v.into_iter().map(|e| e.name).collect())
            .map_err(|e| e.to_string())
    }
}

impl tantry::runtime::graph::Host for WasmHostState {
    async fn query_symbols(&mut self, _query: String) -> Result<String, String> {
        // let state = self.state.lock().unwrap();
        Ok("[]".to_string())
    }
    async fn blast_radius(&mut self, _symbol: String) -> Result<String, String> {
        // let state = self.state.lock().unwrap();
        Ok("[]".to_string())
    }
}

impl tantry::runtime::tunnel::Host for WasmHostState {
    async fn request_scoped_token(
        &mut self,
        service: String,
        ttl_secs: u64,
    ) -> Result<String, String> {
        let _state = self.state.lock().unwrap();

        let svid = match self.identity_manager.current_svid() {
            Some(s) => s,
            None => return Err("No SVID".to_string()),
        };

        let grant = self
            .tunnel_registry
            .issue_grant(ttl_secs as i64, &service, &svid)
            .map_err(|e| e.to_string())?;
        Ok(grant.token)
    }
}

/// WasmSandbox struct
pub struct WasmSandbox {
    /// Engine
    pub engine: Engine,
    /// Config
    pub config: WasmSandboxConfig,
}

impl WasmSandbox {
    /// Create a new WasmSandbox
    pub fn new(config: WasmSandboxConfig) -> Result<Self, BackendError> {
        let mut engine_config = Config::new();
        engine_config.wasm_component_model(true);
        // Note: The async_support method is deprecated in 43.0.2 but required by the reviewer.
        // It's a no-op but we have to keep it, so we suppress the warning.
        #[allow(deprecated)]
        engine_config.async_support(true);
        engine_config.consume_fuel(true);
        engine_config.epoch_interruption(true);

        let engine = Engine::new(&engine_config)
            .map_err(|e| BackendError::Execution(format!("Engine error: {}", e)))?;

        Ok(Self { engine, config })
    }

    /// Evaluates a WASM string in the sandbox
    pub async fn evaluate_wasm_string(
        &self,
        wasm_bytes: &[u8],
        code: &str,
        state: Arc<std::sync::Mutex<TantryState>>,
        vfs: Arc<dyn VfsBackend + Send + Sync>,
        identity_manager: Arc<dyn IdentityManager + Send + Sync>,
        tunnel_registry: Arc<ScopedTunnelRegistry>,
        repo_engine: Option<Arc<RepoEngine>>,
    ) -> Result<String, BackendError> {
        validate_component_no_start_yield(wasm_bytes)?;

        let component = Component::new(&self.engine, wasm_bytes)
            .map_err(|e| BackendError::Execution(format!("Component new error: {}", e)))?;

        let mut linker: Linker<WasmHostState> = Linker::new(&self.engine);

        add_to_linker_async(&mut linker)
            .map_err(|e| BackendError::Execution(format!("Linker error: {}", e)))?;

        EvalSandbox::add_to_linker::<_, HasSelf<WasmHostState>>(&mut linker, |state| state)
            .map_err(|e| BackendError::Execution(format!("Linker error: {}", e)))?;

        let limits = StoreLimitsBuilder::new()
            .memory_size(self.config.max_memory_bytes)
            .build();

        let wasi = WasiCtxBuilder::new().build();

        let host_state = WasmHostState {
            limits,
            wasi,
            table: ResourceTable::new(),
            state,
            vfs,
            identity_manager,
            tunnel_registry,
            repo_engine,
        };

        let mut store = Store::new(&self.engine, host_state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.config.fuel_budget)
            .map_err(|e| BackendError::Execution(e.to_string()))?;

        let deadline_ticks =
            (self.config.wall_clock_timeout_ms / self.config.epoch_tick_ms.max(1)).max(1);
        store.set_epoch_deadline(deadline_ticks);

        let engine_clone = self.engine.clone();
        let tick_ms = self.config.epoch_tick_ms;
        let ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(tick_ms));
            loop {
                interval.tick().await;
                engine_clone.increment_epoch();
            }
        });

        let sandbox_instance = EvalSandbox::instantiate_async(&mut store, &component, &linker)
            .await
            .map_err(|e| BackendError::Execution(format!("Instantiate error: {}", e)))?;

        let eval_future = sandbox_instance.call_eval(&mut store, code);

        let res = tokio::time::timeout(
            Duration::from_millis(self.config.wall_clock_timeout_ms),
            Box::pin(eval_future),
        )
        .await;

        ticker.abort();

        let res = res.map_err(|_| BackendError::Execution("Timeout".to_string()))?;

        match res {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(s)) => Err(BackendError::Execution(s)),
            Err(e) => Err(BackendError::Execution(format!("Eval error: {}", e))),
        }
    }
}

/// Validates a WebAssembly component or module to ensure it does not contain
/// a start section, neutralizing RUSTSEC-2026-0358.
pub fn validate_component_no_start_yield(wasm_bytes: &[u8]) -> Result<(), BackendError> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm_bytes) {
        match payload {
            Ok(Payload::StartSection { .. }) | Ok(Payload::ComponentStartSection { .. }) => {
                return Err(BackendError::UnsafeWasmStartSection);
            }
            Err(e) => return Err(BackendError::Execution(format!("Invalid WASM: {}", e))),
            _ => continue,
        }
    }
    Ok(())
}
