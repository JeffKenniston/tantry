use crate::error::PathValidationError;

/// PosixPath type
pub type PosixPath = String;

/// validate_and_normalize_path fn
pub fn validate_and_normalize_path(raw: &str) -> Result<PosixPath, PathValidationError> {
    if raw.is_empty() {
        return Err(PathValidationError::EmptyPath);
    }

    if raw.bytes().any(|b| b <= 0x1F || b == 0x7F) {
        return Err(PathValidationError::NullByteOrControlChar);
    }

    if raw.contains('\\') {
        return Err(PathValidationError::BackslashForbidden);
    }

    let mut segments = Vec::new();
    for segment in raw.split('/') {
        if segment == "." || segment == ".." {
            return Err(PathValidationError::TraversalAttempt);
        }
        if !segment.is_empty() {
            segments.push(segment);
        }
    }

    if segments.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", segments.join("/")))
    }
}
