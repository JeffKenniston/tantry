use crate::error::CognitiveError;
use data::task_ledger::TaskLedgerStore;
use iam::svid::{JwtSvidClaims, WorkloadSvid, mint_hybrid_jwt_svid};
use serde::Serialize;
use std::sync::Arc;

/// Payload for the budget webhook.
#[derive(Serialize)]
pub struct BudgetWebhookPayload {
    /// Task identifier.
    pub task_id: String,
    /// Thread identifier.
    pub thread_id: String,
    /// Tenant identifier.
    pub tenant_id: String,
    /// Spiffe identifier.
    pub spiffe_id: String,
    /// Spent budget in microseconds.
    pub spent_micros: i64,
    /// Hard budget in microseconds.
    pub hard_budget_micros: i64,
    /// Timestamp in ms.
    pub timestamp_ms: u64,
}

/// Reservation-Based Atomic Credit-Lease Enforcer & 90% Signed Webhook Gate.
pub struct BillingEnforcer {
    /// Task ledger instance.
    pub ledger: Arc<TaskLedgerStore>,
}

/// RAII Guard that manages a budget lease for the duration of a speculative task.
pub struct BudgetLeaseGuard {
    /// Ledger reference.
    ledger: Arc<TaskLedgerStore>,
    /// Task identifier.
    task_id: String,
    pub lease_micros: i64,
    settled: bool,
}

impl BillingEnforcer {
    /// Initializes a new BillingEnforcer.
    pub fn new(ledger: Arc<TaskLedgerStore>) -> Self {
        Self { ledger }
    }

    /// Pre-Flight Lease (`acquire_lease`): Computes worst-case estimated cost,
    /// reserves it in the ledger, and returns a RAII BudgetLeaseGuard.
    pub fn acquire_lease_fixed(
        &self,
        task_id: &str,
        lease_micros: i64,
    ) -> Result<BudgetLeaseGuard, CognitiveError> {
        self.ledger
            .try_reserve_budget(task_id, lease_micros)
            .map_err(|e| {
                if e.to_string().contains("Budget exhausted") {
                    CognitiveError::BudgetExhausted(e.to_string())
                } else {
                    CognitiveError::DatabaseError(e.to_string())
                }
            })?;

        Ok(BudgetLeaseGuard {
            ledger: self.ledger.clone(),
            task_id: task_id.to_string(),
            lease_micros,
            settled: false,
        })
    }

    /// acquire lease
    pub fn acquire_lease(
        &self,
        task_id: &str,
        n_in_est: i64,
        n_max_out: i64,
        p_in: i64,
        p_out: i64,
    ) -> Result<BudgetLeaseGuard, CognitiveError> {
        let lease_micros = ((n_in_est * p_in) + (n_max_out * p_out) + 999_999) / 1_000_000;

        self.ledger
            .try_reserve_budget(task_id, lease_micros)
            .map_err(|e| {
                if e.to_string().contains("Budget exhausted") {
                    CognitiveError::BudgetExhausted(e.to_string())
                } else {
                    CognitiveError::DatabaseError(e.to_string())
                }
            })?;

        Ok(BudgetLeaseGuard {
            ledger: self.ledger.clone(),
            task_id: task_id.to_string(),
            lease_micros,
            settled: false,
        })
    }
}

impl BudgetLeaseGuard {
    /// Mid-Flight Lease Upgrade (`upgrade_lease`): Atomically reserves the delta.
    pub fn upgrade_lease(&mut self, target_lease: i64) -> Result<(), CognitiveError> {
        if target_lease > self.lease_micros {
            let delta = target_lease - self.lease_micros;
            self.ledger
                .upgrade_reserved_budget(&self.task_id, delta)
                .map_err(|e| {
                    if e.to_string().contains("Budget exhausted") {
                        CognitiveError::BudgetExhausted(e.to_string())
                    } else {
                        CognitiveError::DatabaseError(e.to_string())
                    }
                })?;
            self.lease_micros = target_lease;
        }
        Ok(())
    }

    /// Post-Call Settlement & Signed 90% Webhook (`settle`):
    #[allow(clippy::too_many_arguments)]
    pub fn settle(
        mut self,
        n_in: i64,
        n_cached: i64,
        n_out: i64,
        p_in: i64,
        p_cached: i64,
        p_out: i64,
        webhook_url: Option<&str>,
        webhook_timeout_ms: u64,
        svid: Option<&WorkloadSvid>,
    ) -> Result<bool, CognitiveError> {
        let actual_cost_micros =
            (((n_in - n_cached) * p_in) + (n_cached * p_cached) + (n_out * p_out) + 999_999)
                / 1_000_000;

        self.settled = true;

        let should_fire_webhook = self
            .ledger
            .settle_budget(&self.task_id, self.lease_micros, actual_cost_micros, 0.9)
            .map_err(|e| CognitiveError::DatabaseError(e.to_string()))?;

        #[allow(clippy::collapsible_if)]
        if should_fire_webhook {
            if let (Some(url), Some(svid)) = (webhook_url, svid) {
                let task_opt = self.ledger.get_task(&self.task_id).unwrap_or(None);
                if let Some(task) = task_opt {
                    let timestamp_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let payload = BudgetWebhookPayload {
                        task_id: task.task_id.clone(),
                        thread_id: "thread".to_string(),
                        tenant_id: "tenant".to_string(),
                        spiffe_id: svid.spiffe_id.uri().to_string(),
                        spent_micros: task.spent_budget_micros,
                        hard_budget_micros: task.hard_budget_micros,
                        timestamp_ms,
                    };

                    use base64::Engine;
                    let pq_pk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(&svid.mldsa65_verifying_key_bytes);
                    let jti = uuid::Uuid::now_v7().to_string();

                    let claims = JwtSvidClaims {
                        iss: svid.spiffe_id.uri().to_string(),
                        sub: "budget_alert".to_string(),
                        aud: vec![url.to_string()],
                        exp: (timestamp_ms / 1000) as i64 + 300,
                        iat: (timestamp_ms / 1000) as i64,
                        jti: jti.clone(),
                        pq_pk_b64: pq_pk_b64.clone(),
                        htm: None,
                        htu: None,
                    };

                    if let Ok(jwt) = mint_hybrid_jwt_svid(svid, &claims) {
                        // Create DPoP proof matching RFC 9449 format. It must be a JWT itself.
                        // For simplicity in this implementation, we re-use the minting logic for DPoP with a different audience/subject or specific claims
                        // Since DPoP proof is a JWT, we will mint a second JWT for the DPoP header
                        // Use iam's DPoP proof minting
                        if let Ok(dpop_proof) = iam::dpop::mint_dpop_proof(svid, "POST", url, None)
                        {
                            if let Ok(client) = reqwest::blocking::Client::builder()
                                .timeout(std::time::Duration::from_millis(webhook_timeout_ms))
                                .build()
                            {
                                let _ = client
                                    .post(url)
                                    .header("Authorization", format!("DPoP {}", jwt))
                                    .header("DPoP", dpop_proof)
                                    .json(&payload)
                                    .send();
                            }
                        }

                        let _ = self.ledger.mark_webhook_90_fired(&self.task_id);

                        let conn = self.ledger.db.lock().unwrap();
                        let _ = conn.execute(
                            "CREATE TABLE IF NOT EXISTS audit_log (
                                seq_no INTEGER PRIMARY KEY,
                                timestamp_ms INTEGER NOT NULL,
                                spiffe_id TEXT NOT NULL,
                                thread_id TEXT NOT NULL,
                                event_kind TEXT NOT NULL,
                                payload_json TEXT NOT NULL,
                                entry_hash BLOB NOT NULL,
                                mmr_size INTEGER NOT NULL,
                                mmr_peaks BLOB NOT NULL,
                                signed_tree_head BLOB NOT NULL
                            )",
                            [],
                        );

                        let _ = conn.execute(
                            "INSERT INTO audit_log (seq_no, timestamp_ms, spiffe_id, thread_id, event_kind, payload_json, entry_hash, mmr_size, mmr_peaks, signed_tree_head)
                             VALUES ((SELECT IFNULL(MAX(seq_no), 0) + 1 FROM audit_log), ?1, ?2, ?3, ?4, ?5, zeroblob(32), 1, zeroblob(32), zeroblob(64))",
                            rusqlite::params![timestamp_ms as i64, svid.spiffe_id.uri().to_string(), "thread", "BUDGET_90_WEBHOOK_FIRED", serde_json::to_string(&payload).unwrap()]
                        );
                    }
                }
            }
        }

        Ok(should_fire_webhook)
    }
}

impl Drop for BudgetLeaseGuard {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self
                .ledger
                .settle_budget(&self.task_id, self.lease_micros, 0, 0.9);
        }
    }
}
