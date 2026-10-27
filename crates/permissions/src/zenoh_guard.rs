use crate::lattice::PermissionMode;
use iam::spiffe::SpiffeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZenohAction {
    Publish,
    Subscribe,
}

/// Evaluates whether a given Zenoh key expression is permitted for a given SPIFFE ID.
///
/// Ensures compliance with strict Zenoh topic structure:
/// - Rejects `..`, `\0`, or leading/trailing slashes.
/// - Root agents (`spiffe://{td}/agent/{a}/task/{tid}`) can access `tantry/{td}/**`.
/// - Subagents (`spiffe://{td}/agent/{a}/task/{tid}/subagent/{s}/task/{child_tid}`)
///   can ONLY publish to `.../events` and `.../state`, and can ONLY subscribe to `.../cmd`.
pub fn evaluate_zenoh_topic(svid: &SpiffeId, action: ZenohAction, topic: &str) -> PermissionMode {
    if topic.contains("..")
        || topic.contains('\0')
        || topic.starts_with('/')
        || topic.ends_with('/')
    {
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
        if topic.starts_with(&prefix) || topic == format!("tantry/{}", td) {
            return PermissionMode::Allow;
        }
        PermissionMode::Deny
    } else {
        if action == ZenohAction::Publish {
            let events_path = format!(
                "tantry/{}/subagents/{}/tasks/{}/events",
                td, sub_s, child_tid
            );
            let state_path = format!(
                "tantry/{}/subagents/{}/tasks/{}/state",
                td, sub_s, child_tid
            );
            if topic == events_path || topic == state_path {
                return PermissionMode::Allow;
            }
            PermissionMode::Deny
        } else {
            let cmd_path = format!("tantry/{}/subagents/{}/tasks/{}/cmd", td, sub_s, child_tid);
            if topic == cmd_path {
                return PermissionMode::Allow;
            }
            PermissionMode::Deny
        }
    }
}
