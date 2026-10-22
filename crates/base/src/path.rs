use crate::error::PathValidationError;

pub type PosixPath = String;

pub fn validate_and_normalize_path(raw: &str) -> Result<PosixPath, PathValidationError> {
    if raw.is_empty() {
        return Err(PathValidationError::EmptyPath);
    }

    if raw
        .chars()
        .any(|c| c == '\0' || (c as u32 <= 0x1F) || c == '\x7F')
    {
        return Err(PathValidationError::NullByteOrControlChar);
    }

    if raw.contains('\\') {
        return Err(PathValidationError::BackslashForbidden);
    }

    let mut parts = Vec::new();

    for segment in raw.split('/') {
        if segment == "." || segment == ".." {
            return Err(PathValidationError::TraversalAttempt);
        }
        if !segment.is_empty() {
            parts.push(segment);
        }
    }

    let mut result = parts.join("/");
    if !result.starts_with('/') {
        result.insert(0, '/');
    }

    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }

    Ok(result)
}
