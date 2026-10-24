use crate::error::CognitiveError;
use data::task_ledger::TaskLedgerStore;
use std::sync::Arc;

/// Reservation-Based Atomic Credit-Lease Enforcer & 90% Signed Webhook Gate.
pub struct BillingEnforcer {
    /// Persists budget allocations.
    pub ledger: Arc<TaskLedgerStore>,
}

/// RAII Guard that manages a budget lease for the duration of a speculative task.
pub struct BudgetLeaseGuard {
    ledger: Arc<TaskLedgerStore>,
    task_id: String,
    lease_micros: i64,
    settled: bool,
}

impl BillingEnforcer {
    /// Initializes a new BillingEnforcer.
    pub fn new(ledger: Arc<TaskLedgerStore>) -> Self {
        Self { ledger }
    }

    /// Pre-Flight Lease (`acquire_lease`): Computes worst-case estimated cost,
    /// reserves it in the ledger, and returns a RAII BudgetLeaseGuard.
    pub fn acquire_lease(
        &self,
        task_id: &str,
        n_in_est: i64,
        n_max_out: i64,
        p_in: i64,
        p_out: i64,
    ) -> Result<BudgetLeaseGuard, CognitiveError> {
        let lease_micros = ((n_in_est * p_in) + (n_max_out * p_out) + 999_999) / 1_000_000;

        self.ledger.try_reserve_budget(task_id, lease_micros).map_err(|e| {
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
            self.ledger.upgrade_reserved_budget(&self.task_id, delta).map_err(|e| {
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
    pub fn settle(
        mut self,
        n_in: i64,
        n_cached: i64,
        n_out: i64,
        p_in: i64,
        p_cached: i64,
        p_out: i64,
    ) -> Result<bool, CognitiveError> {
        let actual_cost_micros =
            (((n_in - n_cached) * p_in) + (n_cached * p_cached) + (n_out * p_out) + 999_999) / 1_000_000;

        self.settled = true;

        self.ledger.settle_budget(&self.task_id, self.lease_micros, actual_cost_micros, 0.9).map_err(|e| {
            CognitiveError::DatabaseError(e.to_string())
        })
    }
}

impl Drop for BudgetLeaseGuard {
    fn drop(&mut self) {
        if !self.settled {
            // Rolls back reserved_budget_micros -= lease_micros
            // TaskLedgerStore doesn't seem to have a dedicated rollback fn,
            // wait, settle_budget drops reserve, what about a failed drop?
            // "If Drop runs before settle() (e.g., task cancellation or network error), rolls back reserved_budget_micros -= lease_micros."
            let _ = self.ledger.settle_budget(&self.task_id, self.lease_micros, 0, 0.9);
        }
    }
}
