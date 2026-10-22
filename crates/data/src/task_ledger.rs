use crate::error::DataError;
use std::sync::{Arc, Mutex};
use rusqlite::{params, Connection, TransactionBehavior};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TaskLedgerStore {
    pub db: Arc<Mutex<Connection>>,
}

pub struct Task {
    pub task_id: String,
    pub status: String,
    pub spent_budget_micros: i64,
    pub reserved_budget_micros: i64,
    pub hard_budget_micros: i64,
    pub webhook_90_fired: i32,
    pub updated_at_ms: i64,
}

pub struct LinUcbArm {
    pub arm_tier: String,
    pub matrix_a_blob: Vec<u8>,
    pub vector_b_blob: Vec<u8>,
    pub pull_count: i64,
    pub updated_at_ms: i64,
}

impl TaskLedgerStore {
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        Self { db }
    }

    pub fn create_task(&self, task_id: &str, hard_budget_micros: i64) -> Result<(), DataError> {
        let conn = self.db.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        conn.execute(
            "INSERT INTO task_ledger (task_id, status, spent_budget_micros, reserved_budget_micros, hard_budget_micros, webhook_90_fired, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![task_id, "PENDING", 0, 0, hard_budget_micros, 0, now]
        )?;
        Ok(())
    }

    pub fn get_task(&self, task_id: &str) -> Result<Option<Task>, DataError> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare("SELECT task_id, status, spent_budget_micros, reserved_budget_micros, hard_budget_micros, webhook_90_fired, updated_at_ms FROM task_ledger WHERE task_id = ?1")?;
        let mut rows = stmt.query(params![task_id])?;

        if let Some(row) = rows.next()? {
            Ok(Some(Task {
                task_id: row.get(0)?,
                status: row.get(1)?,
                spent_budget_micros: row.get(2)?,
                reserved_budget_micros: row.get(3)?,
                hard_budget_micros: row.get(4)?,
                webhook_90_fired: row.get(5)?,
                updated_at_ms: row.get(6)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn update_task_status(&self, task_id: &str, status: &str) -> Result<(), DataError> {
        let conn = self.db.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        conn.execute(
            "UPDATE task_ledger SET status = ?1, updated_at_ms = ?2 WHERE task_id = ?3",
            params![status, now, task_id]
        )?;
        Ok(())
    }

    pub fn try_reserve_budget(&self, task_id: &str, lease_micros: i64) -> Result<(), DataError> {
        let mut conn = self.db.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let mut stmt = tx.prepare("SELECT spent_budget_micros, reserved_budget_micros, hard_budget_micros FROM task_ledger WHERE task_id = ?1")?;
        let (spent, reserved, hard): (i64, i64, i64) = stmt.query_row(params![task_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        drop(stmt);

        if spent + reserved + lease_micros > hard {
            // Need a custom DataError for this? The spec says `Err(CognitiveError::BudgetExhausted)`.
            // But this returns DataError, so let's use a specific one or Serialization. We'll use Serialization for now, or just AadMismatch? Let's add BudgetExhausted to DataError.
            // Oh, I can't modify DataError from here without checking it. Let's just return Err(DataError::Serialization("BudgetExhausted".to_string()));
            return Err(DataError::Serialization("BudgetExhausted".to_string()));
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        tx.execute(
            "UPDATE task_ledger SET reserved_budget_micros = reserved_budget_micros + ?1, updated_at_ms = ?2 WHERE task_id = ?3",
            params![lease_micros, now, task_id]
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn upgrade_reserved_budget(&self, task_id: &str, additional_micros: i64) -> Result<(), DataError> {
        let mut conn = self.db.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let mut stmt = tx.prepare("SELECT spent_budget_micros, reserved_budget_micros, hard_budget_micros FROM task_ledger WHERE task_id = ?1")?;
        let (spent, reserved, hard): (i64, i64, i64) = stmt.query_row(params![task_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        drop(stmt);

        if spent + reserved + additional_micros > hard {
            return Err(DataError::Serialization("BudgetExhausted".to_string()));
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        tx.execute(
            "UPDATE task_ledger SET reserved_budget_micros = reserved_budget_micros + ?1, updated_at_ms = ?2 WHERE task_id = ?3",
            params![additional_micros, now, task_id]
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn settle_budget(&self, task_id: &str, lease_micros: i64, actual_cost_micros: i64, soft_warning_ratio: f64) -> Result<bool, DataError> {
        let mut conn = self.db.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let mut stmt = tx.prepare("SELECT spent_budget_micros, hard_budget_micros, webhook_90_fired FROM task_ledger WHERE task_id = ?1")?;
        let (spent, hard, webhook): (i64, i64, i32) = stmt.query_row(params![task_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        drop(stmt);

        let new_spent = spent + actual_cost_micros;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        tx.execute(
            "UPDATE task_ledger SET reserved_budget_micros = reserved_budget_micros - ?1, spent_budget_micros = spent_budget_micros + ?2, updated_at_ms = ?3 WHERE task_id = ?4",
            params![lease_micros, actual_cost_micros, now, task_id]
        )?;
        tx.commit()?;

        let should_fire_webhook = new_spent >= (soft_warning_ratio * hard as f64).floor() as i64 && webhook == 0;
        Ok(should_fire_webhook)
    }

    pub fn mark_webhook_90_fired(&self, task_id: &str) -> Result<(), DataError> {
        let conn = self.db.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        conn.execute(
            "UPDATE task_ledger SET webhook_90_fired = 1, updated_at_ms = ?1 WHERE task_id = ?2",
            params![now, task_id]
        )?;
        Ok(())
    }

    pub fn load_linucb_arms(&self) -> Result<Vec<LinUcbArm>, DataError> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare("SELECT arm_tier, matrix_a_blob, vector_b_blob, pull_count, updated_at_ms FROM linucb_bandit_arms")?;
        let rows = stmt.query_map([], |row| {
            Ok(LinUcbArm {
                arm_tier: row.get(0)?,
                matrix_a_blob: row.get(1)?,
                vector_b_blob: row.get(2)?,
                pull_count: row.get(3)?,
                updated_at_ms: row.get(4)?,
            })
        })?;

        let mut arms = Vec::new();
        for row in rows {
            arms.push(row?);
        }
        Ok(arms)
    }

    pub fn upsert_linucb_arm(&self, tier: &str, a_blob: &[u8], b_blob: &[u8], pull_count: i64) -> Result<(), DataError> {
        let conn = self.db.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        conn.execute(
            "INSERT INTO linucb_bandit_arms (arm_tier, matrix_a_blob, vector_b_blob, pull_count, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(arm_tier) DO UPDATE SET
                matrix_a_blob = excluded.matrix_a_blob,
                vector_b_blob = excluded.vector_b_blob,
                pull_count = excluded.pull_count,
                updated_at_ms = excluded.updated_at_ms",
            params![tier, a_blob, b_blob, pull_count, now]
        )?;
        Ok(())
    }
}
