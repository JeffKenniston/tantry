use runtime::middleware::{AgentMiddleware, NextModelCall, TurnExecutionContext};
use std::sync::Arc;

pub fn build_middleware_onion<'a>(
    middlewares: &'a [Arc<dyn AgentMiddleware>],
    base_call: NextModelCall<'a>,
    ctx: &'a TurnExecutionContext,
) -> NextModelCall<'a> {
    let mut inner = base_call;
    for mw in middlewares.iter().rev() {
        let next = inner;
        inner = Box::new(move |st, r| {
            Box::pin(async move { mw.wrap_model_call(st, r, ctx, next).await })
        });
    }
    inner
}
