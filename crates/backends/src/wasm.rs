use crate::error::BackendError;
use wasmparser::{Parser, Payload};

/// Validates a WebAssembly component or module to ensure it does not contain
/// a start section, neutralizing RUSTSEC-2026-0358.
pub fn validate_component_no_start_yield(wasm_bytes: &[u8]) -> Result<(), BackendError> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm_bytes) {
        match payload {
            Ok(Payload::StartSection { .. }) | Ok(Payload::ComponentStartSection { .. }) => {
                return Err(BackendError::UnsafeWasmStartSection);
            }
            Err(e) => return Err(BackendError::Execution(format!("Invalid WASM: {}", e))),
            _ => continue,
        }
    }
    Ok(())
}
