use crate::ext::SpiffeId;
use crate::lattice::PermissionMode;

pub fn evaluate_zenoh_topic(svid: &SpiffeId, key_expr: &str, is_publish: bool) -> PermissionMode {
    if key_expr.contains("..") || key_expr.contains('\0') || key_expr.starts_with('/') || key_expr.ends_with('/') {
        return PermissionMode::Deny;
    }

    let uri = svid.uri();

    // Parse spiffe://{td}/agent/{a}/task/{tid} or subagent
    // First, strip spiffe://
    if !uri.starts_with("spiffe://") {
        return PermissionMode::Deny;
    }

    let without_scheme = &uri["spiffe://".len()..];
    let mut parts = without_scheme.split('/');

    let td = match parts.next() {
        Some(t) => t,
        None => return PermissionMode::Deny,
    };

    // root agent: spiffe://{td}/agent/{a}/task/{tid}
    // subagent: spiffe://{td}/agent/{a}/task/{tid}/subagent/{s}/task/{child_tid}

    let is_subagent;
    let mut sub_s = "";
    let mut child_tid = "";

    let remaining: Vec<&str> = parts.collect();
    if remaining.len() >= 4 && remaining[0] == "agent" && remaining[2] == "task" {
        if remaining.len() == 4 {
            // Root agent
            is_subagent = false;
        } else if remaining.len() == 8 && remaining[4] == "subagent" && remaining[6] == "task" {
            // Subagent
            is_subagent = true;
            sub_s = remaining[5];
            child_tid = remaining[7];
        } else {
            return PermissionMode::Deny;
        }
    } else {
        return PermissionMode::Deny;
    }

    if !is_subagent {
        let prefix = format!("tantry/{}/", td);
        if key_expr.starts_with(&prefix) || key_expr == format!("tantry/{}", td) {
            return PermissionMode::Allow;
        }
        return PermissionMode::Deny;
    } else {
        if is_publish {
            let events_path = format!("tantry/{}/subagents/{}/tasks/{}/events", td, sub_s, child_tid);
            let state_path = format!("tantry/{}/subagents/{}/tasks/{}/state", td, sub_s, child_tid);
            if key_expr == events_path || key_expr == state_path {
                return PermissionMode::Allow;
            }
            return PermissionMode::Deny;
        } else {
            let cmd_path = format!("tantry/{}/subagents/{}/tasks/{}/cmd", td, sub_s, child_tid);
            if key_expr == cmd_path {
                return PermissionMode::Allow;
            }
            return PermissionMode::Deny;
        }
    }
}
