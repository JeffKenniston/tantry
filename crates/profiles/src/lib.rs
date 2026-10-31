pub mod budget_allocator;
pub mod error;
pub mod registry;
pub mod schema;
pub mod sigstore;

pub use budget_allocator::{
    BLOCK3_REPOMAP_HARD_CAP_TOKENS, BLOCK4_MEMORY_HARD_CAP_TOKENS, PromptBlockBudgets,
    PromptTokenBudgetAllocator, estimate_tokens, truncate_to_token_budget,
};
pub use error::ProfileError;
pub use registry::ProfileRegistry;
pub use schema::{
    HarnessProfile, HarnessProfileOverride, merge_middleware_in_place, parse_profile_key,
};
pub use sigstore::{
    FulcioCertificateDescriptor, RekorInclusionProof, RekorTransparencyLogEntry, SigstoreBundle,
    SigstoreVerificationReport, SigstoreVerifier, verify_rfc6962_inclusion_proof,
};
