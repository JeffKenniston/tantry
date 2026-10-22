use crate::error::PathValidationError;

pub type PosixPath = String;

pub fn validate_and_normalize_path(raw: &str) -> Result<PosixPath, PathValidationError> {
    if raw.is_empty() {
        return Err(PathValidationError::EmptyPath);
    }

    if raw.chars().any(|c| {
        let code = c as u32;
        code <= 0x1F || code == 0x7F
    }) {
        return Err(PathValidationError::NullByteOrControlChar);
    }

    if raw.contains('\\') {
        return Err(PathValidationError::BackslashForbidden);
    }

    for segment in raw.split('/') {
        if segment == "." || segment == ".." {
            return Err(PathValidationError::TraversalAttempt);
        }
    }

    let mut normalized = String::new();
    let mut prev_was_slash = false;

    // ensure starts with slash
    if !raw.starts_with('/') {
        normalized.push('/');
        prev_was_slash = true;
    }

    for c in raw.chars() {
        if c == '/' {
            if !prev_was_slash {
                normalized.push(c);
                prev_was_slash = true;
            }
        } else {
            normalized.push(c);
            prev_was_slash = false;
        }
    }

    // strip trailing slash unless root
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }

    Ok(normalized)
}
