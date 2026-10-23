use crate::ext::SpiffeId;
use crate::lattice::PermissionMode;

pub fn evaluate_zenoh_topic(svid: &SpiffeId, key_expr: &str, is_publish: bool) -> PermissionMode {
    if key_expr.contains("..")
        || key_expr.contains('\0')
        || key_expr.starts_with('/')
        || key_expr.ends_with('/')
    {
        return PermissionMode::Deny;
    }

    let uri = svid.uri();

    if uri.starts_with("spiffe://") {
        let parts: Vec<&str> = uri.split('/').collect();

        let is_subagent = uri.contains("/subagent/");

        if parts.len() < 3 {
            return PermissionMode::Deny;
        }
        let td = parts[2];

        if !is_subagent {
            let prefix = format!("tantry/{}/", td);
            if key_expr.starts_with(&prefix) || key_expr == format!("tantry/{}", td) {
                return PermissionMode::Allow;
            }
        } else {
            if parts.len() == 9
                && parts[3] == "agent"
                && parts[5] == "subagent"
                && parts[7] == "task"
            {
                let s = parts[6];
                let child_tid = parts[8];

                let events_topic =
                    format!("tantry/{}/subagents/{}/tasks/{}/events", td, s, child_tid);
                let state_topic =
                    format!("tantry/{}/subagents/{}/tasks/{}/state", td, s, child_tid);
                let cmd_topic = format!("tantry/{}/subagents/{}/tasks/{}/cmd", td, s, child_tid);

                if is_publish {
                    if key_expr == events_topic || key_expr == state_topic {
                        return PermissionMode::Allow;
                    }
                } else {
                    if key_expr == cmd_topic {
                        return PermissionMode::Allow;
                    }
                }
            }
        }
    }

    PermissionMode::Deny
}
