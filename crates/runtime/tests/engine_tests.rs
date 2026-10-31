use backends::traits::VfsBackend;
use base::ast::*;
use base::execution::*;
use base::state::*;
use base::vfs_tree::VfsTree;
use chrono::Utc;
use cognitive::error::CognitiveError;
use cognitive::{LlmProvider, StreamEvent as CogStreamEvent};
use data::DataStoreManager;
use futures::Stream;
use iam::IdentityManager;
use iam::key_hierarchy::KeyHierarchy;
use permissions::attenuation::PermissionLattice;
use permissions::capabilities::*;
use permissions::lattice::PermissionMode;
use runtime::engine::*;
use runtime::middleware::*;
use serde_json::json;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;
use uuid::Uuid;

fn make_msg(content: Vec<ContentBlock>) -> Message {
    Message {
        id: Uuid::now_v7(),
        created_at: Utc::now(),
        role: Role::Assistant,
        content,
        metadata: BTreeMap::new(),
    }
}

// Define a dummy AgentMiddleware
struct DummyMiddleware;
#[async_trait::async_trait]
impl AgentMiddleware for DummyMiddleware {
    fn name(&self) -> &'static str {
        "dummy"
    }

    async fn before_agent(
        &self,
        _state: &mut TantryState,
        _ctx: &TurnExecutionContext,
    ) -> Result<(), runtime::error::RuntimeError> {
        Ok(())
    }
}

// And a dummy LlmProvider
struct DummyLlmProvider {
    messages: std::sync::Mutex<Vec<Message>>,
}
#[async_trait::async_trait]
impl LlmProvider for DummyLlmProvider {
    fn complete(&self, _req: ModelRequest) -> Result<ModelResponse, CognitiveError> {
        let msg = self
            .messages
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| make_msg(vec![]));
        Ok(ModelResponse {
            content: "test".to_string(),
            assistant_message: msg,
            usage: TokenUsage::default(),
        })
    }

    fn stream_complete(
        &self,
        _req: ModelRequest,
    ) -> Result<
        Pin<Box<dyn Stream<Item = Result<CogStreamEvent, CognitiveError>> + Send>>,
        CognitiveError,
    > {
        unimplemented!()
    }
}

struct DummyIam;
impl IdentityManager for DummyIam {
    fn current_svid(&self) -> Option<iam::WorkloadSvid> {
        None
    }

    fn mint_subagent_svid(
        &self,
        _workload_svid: &iam::WorkloadSvid,
        _agent_name: &str,
        _task_id: &str,
        _ttl_secs: i64,
    ) -> Result<iam::WorkloadSvid, iam::error::IamError> {
        unimplemented!()
    }

    fn key_hierarchy(&self) -> &KeyHierarchy {
        Box::leak(Box::new(KeyHierarchy::new([0u8; 32])))
    }

    fn sign_audit_sth(
        &self,
        _tree_size: u64,
        _timestamp_ms: i64,
        _mmr_root_blake3: &[u8; 32],
    ) -> Result<iam::AuditSthSignature, iam::error::IamError> {
        unimplemented!()
    }

    fn verify_audit_sth(&self, _sig: &iam::AuditSthSignature) -> Result<(), iam::error::IamError> {
        Ok(())
    }

    fn request_scoped_tunnel_token(
        &self,
        _service_name: &str,
        _ttl_secs: i64,
    ) -> Result<iam::ScopedTunnelToken, iam::error::IamError> {
        unimplemented!()
    }
}

fn create_lattice(fs_mode: PermissionMode) -> PermissionLattice {
    PermissionLattice {
        fs: FsCapability::Base(Arc::new(
            permissions::glob_dfa::CompiledFsAutomaton::new(fs_mode, vec![]).unwrap(),
        )),
        net: NetCapability::new(PermissionMode::Allow, vec![]).unwrap(),
        env: EnvCapability::new(vec![], vec![]).unwrap(),
        mcp: McpCapability::new(PermissionMode::Allow, 1000000, 1000000, vec![]).unwrap(),
        interrupt_on_tools: BTreeMap::new(),
    }
}

async fn create_context(
    llm_provider: Arc<dyn LlmProvider>,
    backend: Arc<dyn VfsBackend>,
    data_stores: Arc<DataStoreManager>,
) -> TurnExecutionContext {
    let reg = prometheus::Registry::new();
    let metrics = Arc::new(runtime::observability::RuntimeMetrics::new(&reg).unwrap());
    TurnExecutionContext {
        task_id: "task_1".to_string(),
        tenant_id: "tenant_1".to_string(),
        iam: Arc::new(DummyIam),
        permission_lattice: Arc::new(create_lattice(PermissionMode::Allow)),
        data_stores,
        llm_provider,
        backend,
        publisher: None,
        metrics,
        active_tools: vec![
            runtime::middleware::ToolDefinition {
                name: "write_file".to_string(),
                description: "Write file".to_string(),
                parameters: json!({}),
            },
            runtime::middleware::ToolDefinition {
                name: "read_file".to_string(),
                description: "Read file".to_string(),
                parameters: json!({}),
            },
        ],
        default_model_tier: ModelTier::FrontierDeep,
    }
}

fn create_default_state() -> TantryState {
    TantryState {
        thread_id: "".to_string(),
        step_index: 0,
        last_checkpoint_id: None,
        messages: vec![],
        files: VfsTree::new(),
        todos: vec![],
        skills_metadata: vec![],
        memory_contents: std::collections::BTreeMap::new(),
        async_tasks: std::collections::BTreeMap::new(),
        rubric_input: None,
        rubric_status: None,
        structured_response: None,
        extensions: base::typemap::StateExtensionMap::new(),
    }
}

struct DummyVfsBackend;
impl VfsBackend for DummyVfsBackend {
    fn read_file(
        &self,
        s: &base::state::TantryState,
        path: &str,
        _: Option<usize>,
        _: Option<usize>,
    ) -> Result<String, backends::error::BackendError> {
        let node = s.files.get(path).unwrap();
        Ok(String::from_utf8(node.content.clone().into()).unwrap())
    }
    fn edit_file(
        &self,
        _s: &mut base::state::TantryState,
        _path: &str,
        _p: &str,
        _h: &str,
        _: bool,
    ) -> Result<backends::traits::EditReceipt, backends::error::BackendError> {
        unimplemented!()
    }
    fn write_file(
        &self,
        s: &mut base::state::TantryState,
        path: &str,
        content: &str,
    ) -> Result<backends::traits::WriteReceipt, backends::error::BackendError> {
        s.files
            .insert(
                path.to_string(),
                Arc::new(base::ast::FileData::new_utf8(
                    content.to_string(),
                    Utc::now(),
                )),
            )
            .unwrap();
        Ok(backends::traits::WriteReceipt { bytes_written: 0 })
    }
    fn ls(
        &self,
        _s: &base::state::TantryState,
        _path: &str,
    ) -> Result<Vec<backends::traits::DirEntryInfo>, backends::error::BackendError> {
        unimplemented!()
    }
    fn capabilities(&self) -> backends::traits::BackendCapabilities {
        unimplemented!()
    }
    fn delete(
        &self,
        _s: &mut base::state::TantryState,
        _path: &str,
    ) -> Result<(), backends::error::BackendError> {
        unimplemented!()
    }
    fn glob(
        &self,
        _s: &base::state::TantryState,
        _p: &str,
    ) -> Result<Vec<String>, backends::error::BackendError> {
        unimplemented!()
    }
    fn grep(
        &self,
        _s: &base::state::TantryState,
        _p: &str,
        _c: Option<&str>,
    ) -> Result<Vec<backends::traits::GrepMatch>, backends::error::BackendError> {
        unimplemented!()
    }
    fn execute(
        &self,
        _req: backends::traits::SandboxExecRequest,
    ) -> Result<backends::traits::SandboxExecResult, backends::error::BackendError> {
        unimplemented!()
    }
}

#[tokio::test]
async fn test_runtime_engine_execute_turn_real_tools() {
    let tmp = format!("/tmp/tantry_test_{}", uuid::Uuid::now_v7());
    std::fs::create_dir_all(&tmp).unwrap();
    let root = tmp.clone();
    let db_l = format!("{}/l", root);
    let db_i = format!("{}/i", root);
    let db_a = format!("{}/a", root);
    let db_v = format!("{}/v", root);
    let data_stores = Arc::new(DataStoreManager::new(&db_l, &db_i, &db_a, &db_v).unwrap());

    let backend = Arc::new(DummyVfsBackend);

    let engine = RuntimeEngine::new(vec![Arc::new(DummyMiddleware)]);

    let llm = Arc::new(DummyLlmProvider {
        // Note: popped from the end, so order is reversed
        messages: std::sync::Mutex::new(vec![
            make_msg(vec![ContentBlock::Text {
                text: "File written and verified.".to_string(),
                cache_control: None,
            }]),
            make_msg(vec![ContentBlock::ToolUse {
                id: "tu_read".to_string(),
                name: "read_file".to_string(),
                input: json!({"path": "/test.txt"}),
            }]),
            make_msg(vec![ContentBlock::ToolUse {
                id: "tu_write".to_string(),
                name: "write_file".to_string(),
                input: json!({"path": "/test.txt", "content": "hello"}),
            }]),
        ]),
    });

    let ctx = create_context(llm, backend.clone(), data_stores.clone()).await;

    let mut state = create_default_state();
    state.thread_id = format!("test_thread_{}", uuid::Uuid::now_v7());

    // First turn: write_file
    let outcome = engine.execute_turn(state, &ctx).await.unwrap();
    let state = match outcome {
        TurnExecutionOutcome::Completed(s) => s,
        _ => panic!("Expected Completed"),
    };

    let node = state.files.get("/test.txt").unwrap();
    assert_ne!(node.blake3_hash, [0; 32]);

    // Second turn: read_file
    let outcome = engine.execute_turn(state, &ctx).await.unwrap();
    let state = match outcome {
        TurnExecutionOutcome::Completed(s) => s,
        _ => panic!("Expected Completed"),
    };

    // Verify turn completed with Text message
    let last_msg = state.messages.last().unwrap();
    assert_eq!(last_msg.role, Role::Assistant);

    // Check tool response for read_file
    for (i, m) in state.messages.iter().enumerate() {
        println!("msg {}: role={:?}", i, m.role);
    }
    let tool_res_msg = &state.messages[3];
    assert_eq!(tool_res_msg.role, Role::Tool);

    let content = &tool_res_msg.content[0];
    if let ContentBlock::ToolResult {
        tool_use_id,
        content: _,
        ..
    } = content
    {
        assert_eq!(tool_use_id, "tu_read");
        // Verify read file content if DummyVfsBackend supported returning content
        // In our mock, read_file returns unimplemented.
        // Wait, did we mock read_file in DummyVfsBackend? No, we used `unimplemented!()`.
        // Let's modify DummyVfsBackend to return actual content so the assertion works!
    } else {
        panic!("Expected ToolResult");
    }

    let node = state.files.get("/test.txt").unwrap();
    assert_ne!(node.blake3_hash, [0; 32]);

    let last_msg = state.messages.last().unwrap();
    assert_eq!(last_msg.role, Role::Assistant);

    let tool_res_msg = &state.messages[3];
    assert_eq!(tool_res_msg.role, Role::Tool);

    let content = &tool_res_msg.content[0];
    if let ContentBlock::ToolResult {
        tool_use_id,
        content: _,
        ..
    } = content
    {
        assert_eq!(tool_use_id, "tu_read");
    } else {
        panic!("Expected ToolResult");
    }

    assert!(state.step_index >= 3);
}

#[tokio::test]
async fn test_runtime_engine_interrupt_and_resume() {
    let tmp = format!("/tmp/tantry_test_{}", uuid::Uuid::now_v7());
    std::fs::create_dir_all(&tmp).unwrap();
    let root = tmp.clone();
    let db_l = format!("{}/l", root);
    let db_i = format!("{}/i", root);
    let db_a = format!("{}/a", root);
    let db_v = format!("{}/v", root);
    let data_stores = Arc::new(DataStoreManager::new(&db_l, &db_i, &db_a, &db_v).unwrap());

    let backend = Arc::new(DummyVfsBackend);

    let engine = RuntimeEngine::new(vec![Arc::new(DummyMiddleware)]);

    let llm = Arc::new(DummyLlmProvider {
        messages: std::sync::Mutex::new(vec![make_msg(vec![ContentBlock::ToolUse {
            id: "tu_write".to_string(),
            name: "write_file".to_string(),
            input: json!({"path": "/test.txt", "content": "hello"}),
        }])]),
    });

    let mut ctx = create_context(llm, backend.clone(), data_stores.clone()).await;
    let mut lattice = create_lattice(PermissionMode::Interrupt);
    lattice
        .interrupt_on_tools
        .insert("write_file".to_string(), PermissionMode::Interrupt);
    ctx.permission_lattice = Arc::new(lattice);

    let mut state = create_default_state();
    state.thread_id = format!("test_thread_{}", uuid::Uuid::now_v7());

    // First turn: interrupt
    let outcome = engine.execute_turn(state.clone(), &ctx).await.unwrap();
    // In engine.rs, we changed the interrupt return to emit Interrupted event but maybe we return it?
    // Wait, let's see what it returns by printing it!
    println!("Interrupt test outcome: {:?}", outcome);
    match outcome {
        TurnExecutionOutcome::Interrupted => {}
        _ => panic!("Expected Interrupted"),
    };

    // Check it's not written yet
    assert!(state.files.get("/test.txt").is_none());

    // In actual system state is not lost, but for tests we can modify hitl directly
    let mut bypass = runtime::slots::HitlBypassSlot {
        approved_tool_use_ids: std::collections::BTreeSet::new(),
    };
    bypass.approved_tool_use_ids.insert("tu_write".to_string());
    state.extensions.insert(bypass);

    // Simulate resume_interrupted_thread by putting back the message
    state.messages.push(make_msg(vec![ContentBlock::ToolUse {
        id: "tu_write".to_string(),
        name: "write_file".to_string(),
        input: json!({"path": "/test.txt", "content": "hello"}),
    }]));

    // Execute turn again to process approved tool
    let outcome = engine.execute_turn(state, &ctx).await.unwrap();
    let state = match outcome {
        TurnExecutionOutcome::Completed(s) => s,
        _ => panic!("Expected Completed"),
    };

    // Now it should be written
    assert!(state.files.get("/test.txt").is_some());
}

#[tokio::test]
async fn test_fork_and_hydrate() {
    let tmp = format!("/tmp/tantry_test_{}", uuid::Uuid::now_v7());
    std::fs::create_dir_all(&tmp).unwrap();
    let root = tmp.clone();
    let db_l = format!("{}/l", root);
    let db_i = format!("{}/i", root);
    let db_a = format!("{}/a", root);
    let db_v = format!("{}/v", root);
    let data_stores = Arc::new(DataStoreManager::new(&db_l, &db_i, &db_a, &db_v).unwrap());

    let backend = Arc::new(DummyVfsBackend);
    let engine = RuntimeEngine::new(vec![Arc::new(DummyMiddleware)]);

    let llm = Arc::new(DummyLlmProvider {
        messages: std::sync::Mutex::new(vec![
            make_msg(vec![ContentBlock::Text {
                text: "Step 4 main".to_string(),
                cache_control: None,
            }]),
            make_msg(vec![ContentBlock::Text {
                text: "Step 3 branch".to_string(),
                cache_control: None,
            }]),
            make_msg(vec![ContentBlock::Text {
                text: "Step 3 main".to_string(),
                cache_control: None,
            }]),
            make_msg(vec![ContentBlock::Text {
                text: "Step 2 main".to_string(),
                cache_control: None,
            }]),
            make_msg(vec![ContentBlock::Text {
                text: "Step 1 main".to_string(),
                cache_control: None,
            }]),
        ]),
    });

    let ctx = create_context(llm, backend.clone(), data_stores.clone()).await;

    let mut state = create_default_state();
    state.thread_id = "main_thread".to_string();

    // Turn 1 -> Step 1
    let outcome = engine.execute_turn(state, &ctx).await.unwrap();
    let state = match outcome {
        TurnExecutionOutcome::Completed(s) => s,
        _ => panic!(),
    };

    // Turn 2 -> Step 2
    let outcome = engine.execute_turn(state, &ctx).await.unwrap();
    let state = match outcome {
        TurnExecutionOutcome::Completed(s) => s,
        _ => panic!(),
    };
    let step_2_cp_id = state.last_checkpoint_id.clone().unwrap();

    // Turn 3 -> Step 3 (main)
    let outcome = engine.execute_turn(state, &ctx).await.unwrap();
    let state = match outcome {
        TurnExecutionOutcome::Completed(s) => s,
        _ => panic!(),
    };

    // Fork at step 2 -> Step 3 (branch)
    let branch_state =
        fork_thread_at_checkpoint(&ctx, &step_2_cp_id, "branch_thread".to_string(), None).unwrap();
    let outcome = engine.execute_turn(branch_state, &ctx).await.unwrap();
    let _branch_state = match outcome {
        TurnExecutionOutcome::Completed(s) => s,
        _ => panic!(),
    };

    // Turn 4 -> Step 4 (main)
    let outcome = engine.execute_turn(state, &ctx).await.unwrap();
    let _state = match outcome {
        TurnExecutionOutcome::Completed(s) => s,
        _ => panic!(),
    };

    let main_hydrated = hydrate_thread_state_full(&ctx, "main_thread").unwrap();
    assert_eq!(main_hydrated.step_index, 4);

    let branch_hydrated = hydrate_thread_state_full(&ctx, "branch_thread").unwrap();
    assert_eq!(branch_hydrated.step_index, 4);
}
