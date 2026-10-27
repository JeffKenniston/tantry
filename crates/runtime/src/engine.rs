use base::state::TantryState;
use base::ast::{ToolCallId, ToolArtifact, ExecuteArtifact, TodoItem, TodoStatus, AsyncTaskHandle, AsyncTaskStatus};
use crate::middleware::{TurnExecutionContext, AgentMiddleware, ToolExecutionOutput};
use crate::error::RuntimeError;
use backends::traits::SandboxExecRequest;
use std::sync::Arc;
use serde_json::Value;
use chrono::Utc;

pub async fn execute_single_tool(
    state: &mut TantryState,
    tool_use_id: &ToolCallId,
    tool_name: &str,
    tool_input: &Value,
    ctx: &TurnExecutionContext,
    middlewares: &[Arc<dyn AgentMiddleware>],
) -> Result<ToolExecutionOutput, RuntimeError> {
    match tool_name {
        "ls" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            match ctx.backend.ls(state, path) {
                Ok(entries) => {
                    let mut lines = Vec::new(); for e in entries { lines.push(format!("{} (dir: {}, size: {})", e.name, e.is_dir, e.size)); } let output = lines.join("\n");
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "read_file" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let offset_line = tool_input.get("offset_line").and_then(|v| v.as_u64()).map(|v| v as usize);
            let limit_lines = tool_input.get("limit_lines").and_then(|v| v.as_u64()).map(|v| v as usize);
            match ctx.backend.read_file(state, path, offset_line, limit_lines) {
                Ok(content) => {
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &content, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "write_file" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let content = tool_input.get("content").and_then(|v| v.as_str()).unwrap_or("");
            match ctx.backend.write_file(state, path, content) {
                Ok(receipt) => {
                    let output = format!("Write successful. {} bytes written.", receipt.bytes_written);
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "edit_file" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let old_string = tool_input.get("old_string").and_then(|v| v.as_str()).unwrap_or("");
            let new_string = tool_input.get("new_string").and_then(|v| v.as_str()).unwrap_or("");
            let replace_all = tool_input.get("replace_all").and_then(|v| v.as_bool()).unwrap_or(false);
            match ctx.backend.edit_file(state, path, old_string, new_string, replace_all) {
                Ok(receipt) => {
                    let output = format!("Edit successful. {} occurrences replaced.", receipt.occurrences_replaced);
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "delete" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or("");
            match ctx.backend.delete(state, path) {
                Ok(_) => {
                    let output = format!("Successfully deleted {}", path);
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "glob" => {
            let pattern = tool_input.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            match ctx.backend.glob(state, pattern) {
                Ok(paths) => {
                    let output = serde_json::to_string_pretty(&paths).unwrap_or_default();
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "grep" => {
            let pattern = tool_input.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            let path_glob = tool_input.get("path_glob").and_then(|v| v.as_str());
            match ctx.backend.grep(state, pattern, path_glob) {
                Ok(matches) => {
                    let mut lines = Vec::new();
                    for m in matches {
                        lines.push(format!("{}:{}: {}", m.path, m.line_number, m.content));
                    }
                    let output = lines.join("\n");
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());
                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "execute" => {
            let command = tool_input.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let args = tool_input.get("args").and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();

            let start = std::time::Instant::now();
            match ctx.backend.execute(SandboxExecRequest { command, args }) {
                Ok(res) => {
                    let duration = start.elapsed();
                    let output = format!("Exit Code: {}\nStdout:\n{}\nStderr:\n{}", res.exit_code, res.stdout, res.stderr);
                    let final_out = base::tools_meta::maybe_offload_tool_output(tool_use_id, &output, &mut state.files, Utc::now());

                    let artifact = ToolArtifact::Execute(ExecuteArtifact {
                        exit_code: res.exit_code,
                        timed_out: false,
                        duration_ms: duration.as_millis() as u64,
                        peak_rss_bytes: None,
                        sandbox_id: String::new(),
                        isolation_tier: String::new(),
                    });

                    Ok(ToolExecutionOutput { raw_output: final_out, is_error: res.exit_code != 0, artifact: Some(artifact) })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: e.to_string(), is_error: true, artifact: None })
            }
        }
        "write_todos" => {
            if let Some(todos_arr) = tool_input.get("todos").and_then(|v| v.as_array()) {
                state.todos.clear();
                for t in todos_arr {
                    if let Some(obj) = t.as_object() {
                        let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let content = obj.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let status_str = obj.get("status").and_then(|v| v.as_str()).unwrap_or("Pending");
                        let status = match status_str {
                            "InProgress" => TodoStatus::InProgress,
                            "Completed" => TodoStatus::Completed,
                            "Cancelled" => TodoStatus::Cancelled,
                            _ => TodoStatus::Pending,
                        };
                        state.todos.push(TodoItem { id, content, status });
                    }
                }
                Ok(ToolExecutionOutput { raw_output: "Todos updated successfully.".to_string(), is_error: false, artifact: None })
            } else {
                Ok(ToolExecutionOutput { raw_output: "Missing or invalid 'todos' array.".to_string(), is_error: true, artifact: None })
            }
        }
        "read_todos" => {
            let output = serde_json::to_string_pretty(&state.todos).unwrap_or_default();
            Ok(ToolExecutionOutput { raw_output: output, is_error: false, artifact: None })
        }
        "update_memory" => {
            let path = tool_input.get("path").and_then(|v| v.as_str()).unwrap_or("/memories/AGENTS.md");
            let content = tool_input.get("content").and_then(|v| v.as_str()).unwrap_or("");
            state.memory_contents.insert(path.to_string(), content.to_string());

            match ctx.backend.write_file(state, "/memories/AGENTS.md", content) {
                Ok(_) => Ok(ToolExecutionOutput { raw_output: "Memory updated.".to_string(), is_error: false, artifact: None }),
                Err(e) => Ok(ToolExecutionOutput { raw_output: format!("Failed to write to VFS: {}", e), is_error: true, artifact: None })
            }
        }
        "ephemeral_tunnel" => {
            let service_name = tool_input.get("service_name").and_then(|v| v.as_str()).unwrap_or("");
            let ttl_secs = tool_input.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600);
            match ctx.iam.request_scoped_tunnel_token(service_name, ttl_secs) {
                Ok(grant) => {
                    let output = serde_json::to_string_pretty(&grant.token).unwrap_or_default();
                    Ok(ToolExecutionOutput { raw_output: output, is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: format!("IAM Error: {:?}", e), is_error: true, artifact: None })
            }
        }
        "launch_async_task" | "update_async_task" => {
            match serde_json::from_value::<AsyncTaskHandle>(tool_input.clone()) {
                Ok(handle) => {
                    state.async_tasks.insert(handle.task_id.clone(), handle);
                    Ok(ToolExecutionOutput { raw_output: "Task saved successfully.".to_string(), is_error: false, artifact: None })
                }
                Err(e) => Ok(ToolExecutionOutput { raw_output: format!("Invalid task handle: {}", e), is_error: true, artifact: None })
            }
        }
        "cancel_async_task" => {
            let task_id = tool_input.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(task) = state.async_tasks.get_mut(task_id) {
                task.status = AsyncTaskStatus::Cancelled;
                Ok(ToolExecutionOutput { raw_output: "Task cancelled.".to_string(), is_error: false, artifact: None })
            } else {
                Ok(ToolExecutionOutput { raw_output: "Task not found.".to_string(), is_error: true, artifact: None })
            }
        }
        "check_async_task" => {
            let task_id = tool_input.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(task) = state.async_tasks.get(task_id) {
                let output = serde_json::to_string_pretty(task).unwrap_or_default();
                Ok(ToolExecutionOutput { raw_output: output, is_error: false, artifact: None })
            } else {
                Ok(ToolExecutionOutput { raw_output: "Task not found.".to_string(), is_error: true, artifact: None })
            }
        }
        "list_async_tasks" => {
            let output = serde_json::to_string_pretty(&state.async_tasks).unwrap_or_default();
            Ok(ToolExecutionOutput { raw_output: output, is_error: false, artifact: None })
        }
        _ => {
            for middleware in middlewares {
                if let Some(out) = middleware.execute_tool(state, tool_use_id, tool_name, tool_input, ctx).await? {
                    return Ok(out);
                }
            }
            Ok(ToolExecutionOutput { raw_output: format!("Unknown tool: {}", tool_name), is_error: true, artifact: None })
        }
    }
}
