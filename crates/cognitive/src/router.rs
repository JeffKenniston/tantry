use base::execution::ModelTier;
use base::typemap::{CodecTag, SlotVisibility, StateSlot};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug, PartialEq))]
/// PendingBanditFeedbackSlot struct for bandit feedback
pub struct PendingBanditFeedbackSlot {
    pub selected_tier: ModelTier,
    pub context_x: [f64; 12],
    pub cost_micros: u64,
    pub latency_ms: u64,
}

impl StateSlot for PendingBanditFeedbackSlot {
    const WIRE_KEY: &'static str = "tantry.cognitive.bandit_feedback";
    const VISIBILITY: SlotVisibility = SlotVisibility::Private;
    const CODEC_TAG: CodecTag = CodecTag::RkyvAligned;

    fn encode_payload(&self) -> Result<Vec<u8>, base::error::ExtensionError> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map_err(|e| base::error::ExtensionError::SerializationFailed(e.to_string()))?;
        Ok(bytes.into_vec())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, base::error::ExtensionError> {
        let archived = rkyv::access::<rkyv::Archived<Self>, rkyv::rancor::Error>(bytes)
            .map_err(|e| base::error::ExtensionError::DeserializationFailed(e.to_string()))?;
        let value = rkyv::deserialize::<Self, rkyv::rancor::Error>(archived)
            .map_err(|e| base::error::ExtensionError::DeserializationFailed(e.to_string()))?;
        Ok(value)
    }
}

/// Gaussian sample function
fn sample_standard_normal() -> f64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let u1: f64 = rng.gen_range(0.0..1.0);
    let u2: f64 = rng.gen_range(0.0..1.0);
    let r: f64 = (-2.0 * u1.max(f64::EPSILON).ln()).sqrt();
    let theta = 2.0 * std::f64::consts::PI * u2;
    r * theta.cos()
}

/// Computes a composite reward
pub fn compute_reward(
    tools_succeeded_and_lint_clean: bool,
    cost_micros: u64,
    latency_ms: u64,
) -> f64 {
    let success = if tools_succeeded_and_lint_clean {
        1.0
    } else {
        0.0
    };
    let cost_penalty = 1.0 - (cost_micros as f64 / 50000.0).min(1.0);
    let latency_penalty = 1.0 - (latency_ms as f64 / 15000.0).min(1.0);

    0.55 * success + 0.25 * cost_penalty + 0.20 * latency_penalty
}

/// Generates a 12D contextual feature vector
#[allow(clippy::too_many_arguments)]
pub fn generate_context_vector(
    tokens_ctx: usize,
    blast_radius_risk: f64,
    has_vfs_conflict: bool,
    consec_errors: u32,
    cyclomatic: u32,
    todos: usize,
    read_only_loop: bool,
    budget_rem_ratio: f64,
    depth: u32,
    structured_schema: bool,
    is_utility_call: bool,
) -> [f64; 12] {
    [
        1.0,
        (tokens_ctx as f64 / 128000.0).min(1.0),
        blast_radius_risk,
        if has_vfs_conflict { 1.0 } else { 0.0 },
        (consec_errors as f64 / 3.0).min(1.0),
        (cyclomatic as f64 / 50.0).min(1.0),
        (todos as f64 / 10.0).min(1.0),
        if read_only_loop { 1.0 } else { 0.0 },
        budget_rem_ratio,
        (depth as f64 / 25.0).min(1.0),
        if structured_schema { 1.0 } else { 0.0 },
        if is_utility_call { 1.0 } else { 0.0 },
    ]
}

/// Gauss-Jordan inversion of 12x12 matrix with partial pivoting and Tikhonov jitter.
fn invert_matrix(mut a: [[f64; 12]; 12]) -> [[f64; 12]; 12] {
    let mut inv = [[0.0; 12]; 12];
    for i in 0..12 {
        inv[i][i] = 1.0;
        a[i][i] += 1e-6; // Tikhonov jitter
    }

    for i in 0..12 {
        let mut pivot = i;
        for j in i + 1..12 {
            if a[j][i].abs() > a[pivot][i].abs() {
                pivot = j;
            }
        }

        if pivot != i {
            a.swap(i, pivot);
            inv.swap(i, pivot);
        }

        let diag = a[i][i];
        if diag.abs() < 1e-9 {
            // singular matrix handling
            return inv;
        }

        for j in 0..12 {
            a[i][j] /= diag;
            inv[i][j] /= diag;
        }

        for k in 0..12 {
            if k != i {
                let factor = a[k][i];
                for j in 0..12 {
                    a[k][j] -= factor * a[i][j];
                    inv[k][j] -= factor * inv[i][j];
                }
            }
        }
    }
    inv
}

/// 12D Contextual Disjoint LinUCB + Projected Thompson Sampling Router
pub struct Router {
    arms: HashMap<String, ([[f64; 12]; 12], [f64; 12])>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    /// new fn
    pub fn new() -> Self {
        let mut arms = HashMap::new();
        let tiers = vec![
            ModelTier::FrontierDeep,
            ModelTier::ReasoningPro,
            ModelTier::FastExecution,
            ModelTier::CompactLite,
        ];

        for tier in tiers {
            let mut a = [[0.0; 12]; 12];
            for i in 0..12 {
                a[i][i] = 1.0;
            }
            arms.insert(tier.as_str().to_string(), (a, [0.0; 12]));
        }

        Self { arms }
    }

    /// Selects best arm based on context
    pub fn select_arm(
        &self,
        context_x: [f64; 12],
        tier_override: Option<ModelTier>,
        is_utility_call: bool,
        has_vfs_conflict: bool,
        blast_radius_risk: f64,
        consec_errors: u32,
        read_only_loop: bool,
        tokens_ctx: usize,
        todos_count: usize,
        deterministic: bool,
    ) -> ModelTier {
        let mut valid_arms = Vec::new();

        // Safety guardrails
        if let Some(tier) = tier_override {
            valid_arms.push(tier);
        } else if is_utility_call {
            valid_arms.push(ModelTier::CompactLite);
        } else if has_vfs_conflict || blast_radius_risk >= 0.75 || consec_errors >= 2 {
            valid_arms.push(ModelTier::FrontierDeep);
        } else if read_only_loop && tokens_ctx < 16000 && todos_count > 0 {
            valid_arms.push(ModelTier::FastExecution);
            valid_arms.push(ModelTier::ReasoningPro);
        } else {
            valid_arms.push(ModelTier::FrontierDeep);
            valid_arms.push(ModelTier::ReasoningPro);
            valid_arms.push(ModelTier::FastExecution);
            valid_arms.push(ModelTier::CompactLite);
        }

        if valid_arms.len() == 1 {
            return valid_arms[0].clone();
        }

        let alpha_ucb = 0.25;
        let alpha_ts = if deterministic { 0.0 } else { 0.05 };

        let mut best_arm = valid_arms[0].clone();
        let mut best_score = f64::NEG_INFINITY;

        for arm in valid_arms {
            let (a, b) = self.arms.get(arm.as_str()).unwrap();
            let a_inv = invert_matrix(*a);

            // Calculate theta_hat = A^-1 * b
            let mut theta_hat = [0.0; 12];
            for i in 0..12 {
                for j in 0..12 {
                    theta_hat[i] += a_inv[i][j] * b[j];
                }
            }

            // Calculate score
            let mut dot_product = 0.0;
            let mut variance = 0.0;

            for i in 0..12 {
                dot_product += theta_hat[i] * context_x[i];
                let mut temp = 0.0;
                for j in 0..12 {
                    temp += a_inv[i][j] * context_x[j];
                }
                variance += context_x[i] * temp;
            }

            let sigma = variance.max(0.0).sqrt();
            let z_a = if deterministic {
                0.0
            } else {
                sample_standard_normal().clamp(-2.0, 2.0)
            };

            let score = dot_product + (alpha_ucb + alpha_ts * z_a) * sigma;

            if score > best_score {
                best_score = score;
                best_arm = arm;
            }
        }

        best_arm
    }

    /// update_arm fn
    pub fn update_arm(&mut self, arm: ModelTier, context_x: [f64; 12], reward: f64) {
        if let Some((a, b)) = self.arms.get_mut(arm.as_str()) {
            for i in 0..12 {
                for j in 0..12 {
                    a[i][j] += context_x[i] * context_x[j];
                }
                b[i] += reward * context_x[i];
            }
        }
    }
}
