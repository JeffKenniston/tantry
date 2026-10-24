use base::execution::ModelTier;
use cognitive::router::{Router, generate_context_vector};

#[test]
fn tdd_cognitive_linucb_and_credit_leases() {
    let mut router = Router::new();

    let ctx_override =
        generate_context_vector(1000, 0.1, false, 0, 10, 0, false, 0.9, 5, true, false);
    let arm_override = router.select_arm(
        ctx_override,
        Some(ModelTier::ReasoningPro),
        false,
        false,
        0.1,
        0,
        false,
        1000,
        0,
        true,
    );
    assert_eq!(
        arm_override,
        ModelTier::ReasoningPro,
        "Safety Guardrail 1 Failed"
    );

    let ctx_utility = generate_context_vector(100, 0.0, false, 0, 5, 0, false, 0.9, 1, false, true);
    let arm_utility =
        router.select_arm(ctx_utility, None, true, false, 0.0, 0, false, 100, 0, true);
    assert_eq!(
        arm_utility,
        ModelTier::CompactLite,
        "Safety Guardrail 2 Failed"
    );

    let ctx_conflict =
        generate_context_vector(1000, 0.1, true, 0, 10, 0, false, 0.9, 5, true, false);
    let arm_conflict = router.select_arm(
        ctx_conflict,
        None,
        false,
        true,
        0.1,
        0,
        false,
        1000,
        0,
        true,
    );
    assert_eq!(
        arm_conflict,
        ModelTier::FrontierDeep,
        "Safety Guardrail 3 Failed (conflict)"
    );

    let ctx_readonly =
        generate_context_vector(5000, 0.1, false, 0, 10, 3, true, 0.9, 5, true, false);
    let arm_readonly = router.select_arm(
        ctx_readonly,
        None,
        false,
        false,
        0.1,
        0,
        true,
        5000,
        3,
        true,
    );

    // Check if arm_readonly is in the valid set {FastExecution, ReasoningPro}
    let valid_readonly = [ModelTier::FastExecution, ModelTier::ReasoningPro];
    assert!(
        valid_readonly.contains(&arm_readonly),
        "Safety Guardrail 4 Failed"
    );

    // Test update_arm convergence towards an optimal ModelTier selection
    let ctx_learn = generate_context_vector(500, 0.0, false, 0, 0, 0, false, 1.0, 0, false, false);

    // Reward CompactLite heavily for this context to make it the preferred choice
    for _ in 0..10 {
        router.update_arm(ModelTier::CompactLite, ctx_learn, 1.0);
    }

    // Now, without safety guardrails overriding it, the router should select CompactLite
    let learned_arm = router.select_arm(
        ctx_learn,
        None,
        false,
        false,
        0.0,
        0,
        false,
        500,
        0,
        true, // deterministic
    );

    assert_eq!(
        learned_arm,
        ModelTier::CompactLite,
        "LinUCB Convergence Failed: Model did not select the highly rewarded arm"
    );
}

#[test]
fn test_billing_concurrent() {
    use cognitive::billing::BillingEnforcer;
    use data::task_ledger::TaskLedgerStore;
    use std::sync::{Arc, Mutex};
    use rusqlite::Connection;
    use std::thread;

    let db = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
    db.lock().unwrap().execute(
        "CREATE TABLE task_ledger (
            task_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            spent_budget_micros INTEGER NOT NULL,
            reserved_budget_micros INTEGER NOT NULL,
            hard_budget_micros INTEGER NOT NULL,
            webhook_90_fired INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        )",
        [],
    ).unwrap();

    let ledger = Arc::new(TaskLedgerStore::new(db));
    let task_id = "test_task";
    ledger.create_task(task_id, 15).unwrap();

    let mut handles = vec![];
    for _ in 0..16 {
        let l = ledger.clone();
        handles.push(thread::spawn(move || {
            let enforcer = BillingEnforcer::new(l);
            if let Ok(guard) = enforcer.acquire_lease(task_id, 1000, 0, 1000, 0) {
                let _ = guard.settle(1000, 0, 0, 1000, 0, 0, None, 0, None);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let task = ledger.get_task(task_id).unwrap().unwrap();
    assert!(task.spent_budget_micros <= 15);
}
