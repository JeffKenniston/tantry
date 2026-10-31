use crate::lattice::PermissionMode;
use iam::spiffe::SpiffeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZenohAction {
    Publish,
    Subscribe,
}

pub fn evaluate_zenoh_topic(svid: &SpiffeId, action: ZenohAction, topic: &str) -> PermissionMode {
    if topic.is_empty() || topic.starts_with('/') || topic.ends_with('/') {
        return PermissionMode::Deny;
    }
    if topic.contains("//") || topic.contains("..") || topic.contains('\0') || topic.contains('\\') || topic.contains('*') || topic.contains('?') || topic.contains('$') {
        return PermissionMode::Deny;
    }

    let uri = svid.uri();
    if !uri.starts_with("spiffe://") {
        return PermissionMode::Deny;
    }

    let without_scheme = &uri["spiffe://".len()..];
    let mut parts = without_scheme.split('/');
    let td = match parts.next() {
        Some(t) => t,
        None => return PermissionMode::Deny,
    };

    let remaining: Vec<&str> = parts.collect();
    let is_subagent;
    let mut sub_s = "";
    let mut child_tid = "";

    if remaining.len() >= 4 && remaining[0] == "agent" && remaining[2] == "task" {
        if remaining.len() == 4 {
            is_subagent = false;
        } else if remaining.len() == 8 && remaining[4] == "subagent" && remaining[6] == "task" {
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
            let events_path = format!("tantry/{}/subagents/{}/tasks/{}/events", td, sub_s, child_tid);
            let state_path = format!("tantry/{}/subagents/{}/tasks/{}/state", td, sub_s, child_tid);
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
