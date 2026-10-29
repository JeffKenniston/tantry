use crate::error::ProfileError;
use serde::{Deserialize, Serialize};

pub const BLOCK3_REPOMAP_HARD_CAP_TOKENS: usize = 2_500;
pub const BLOCK4_MEMORY_HARD_CAP_TOKENS: usize = 4_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptBlockBudgets {
    pub context_window_tokens: usize,
    pub max_total_prompt_tokens: usize,
    pub block1_system_max_tokens: usize,
    pub block2_tools_max_tokens: usize,
    pub block3_repomap_max_tokens: usize,
    pub block4_memory_max_tokens: usize,
    pub block5_dynamic_state_max_tokens: usize,
}

impl PromptBlockBudgets {
    pub fn total_allocated(&self) -> usize {
        self.block1_system_max_tokens
            + self.block2_tools_max_tokens
            + self.block3_repomap_max_tokens
            + self.block4_memory_max_tokens
            + self.block5_dynamic_state_max_tokens
    }
}

pub struct PromptTokenBudgetAllocator;

impl PromptTokenBudgetAllocator {
    pub fn allocate(context_window_tokens: usize) -> Result<PromptBlockBudgets, ProfileError> {
        if context_window_tokens < 64 {
            return Err(ProfileError::InvalidBudgetWindow(context_window_tokens));
        }

        let max_total = context_window_tokens / 4;

        let (block1, block2, block3, block4, block5) = if max_total >= 13_000 {
            let block3 = BLOCK3_REPOMAP_HARD_CAP_TOKENS;
            let block4 = BLOCK4_MEMORY_HARD_CAP_TOKENS;
            let remaining = max_total - (block3 + block4);
            let block1 = (remaining * 25) / 100;
            let block2 = (remaining * 55) / 100;
            let block5 = remaining - (block1 + block2);
            (block1, block2, block3, block4, block5)
        } else {
            let block1 = (max_total * 15) / 100;
            let block2 = (max_total * 35) / 100;
            let block3 = ((max_total * 20) / 100).min(BLOCK3_REPOMAP_HARD_CAP_TOKENS);
            let block4 = ((max_total * 20) / 100).min(BLOCK4_MEMORY_HARD_CAP_TOKENS);
            let block5 = max_total - (block1 + block2 + block3 + block4);
            (block1, block2, block3, block4, block5)
        };

        Ok(PromptBlockBudgets {
            context_window_tokens,
            max_total_prompt_tokens: max_total,
            block1_system_max_tokens: block1,
            block2_tools_max_tokens: block2,
            block3_repomap_max_tokens: block3,
            block4_memory_max_tokens: block4,
            block5_dynamic_state_max_tokens: block5,
        })
    }
}

pub fn estimate_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
}

pub fn truncate_to_token_budget(text: &str, max_tokens: usize) -> String {
    let max_bytes = max_tokens.saturating_mul(4);
    if text.len() <= max_bytes {
        return text.to_string();
    }
    if max_bytes == 0 {
        return String::new();
    }
    let mut idx = max_bytes;
    while !text.is_char_boundary(idx) {
        idx -= 1;
    }
    text[..idx].to_string()
}
