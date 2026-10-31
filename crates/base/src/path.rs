use crate::error::PathValidationError;

pub type PosixPath = String;

pub fn validate_and_normalize_path(raw: &str) -> Result<PosixPath, PathValidationError> {
    if raw.is_empty() {
        return Err(PathValidationError::EmptyPath);
    }

    if raw.chars().any(|c| c == '\0' || (c as u32) <= 0x1F || c == '\x7F') {
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

    let mut result = String::new();
    if !raw.starts_with('/') {
        result.push('/');
    }

    let mut prev_slash = false;
    for c in raw.chars() {
        if c == '/' {
            if !prev_slash {
                result.push(c);
                prev_slash = true;
            }
        } else {
            result.push(c);
            prev_slash = false;
        }
    }

    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }

    Ok(result)
}
