use crate::error::PathValidationError;

pub type PosixPath = String;

pub fn validate_and_normalize_path(raw: &str) -> Result<PosixPath, PathValidationError> {
    if raw.is_empty() {
        return Err(PathValidationError::EmptyPath);
    }

    if raw.chars().any(|c| c == '\0' || c.is_ascii_control()) {
        return Err(PathValidationError::NullByteOrControlChar);
    }

    if raw.contains('\\') {
        return Err(PathValidationError::BackslashForbidden);
    }

    let mut normalized = String::with_capacity(raw.len() + 1);

    // We'll process by splitting on '/'
    let segments: Vec<&str> = raw.split('/').collect();

    for segment in &segments {
        if *segment == "." || *segment == ".." {
            return Err(PathValidationError::TraversalAttempt);
        }
    }

    if !raw.starts_with('/') {
        normalized.push('/');
    }

    let mut prev_slash = false;
    for c in raw.chars() {
        if c == '/' {
            if !prev_slash {
                normalized.push(c);
                prev_slash = true;
            }
        } else {
            normalized.push(c);
            prev_slash = false;
        }
    }

    // Strip trailing slash except if the entire path is just "/"
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }

    // Also need to handle case where original string didn't start with / but we prepended it
    // then if the original string was "a/", it becomes "/a/", we pop to get "/a".

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PathValidationError;

    #[test]
    fn test_normalize() {
        assert_eq!(validate_and_normalize_path("foo/bar").unwrap(), "/foo/bar");
        assert_eq!(validate_and_normalize_path("/foo/bar").unwrap(), "/foo/bar");
        assert_eq!(validate_and_normalize_path("//foo///bar//").unwrap(), "/foo/bar");
        assert_eq!(validate_and_normalize_path("/").unwrap(), "/");

        assert!(matches!(validate_and_normalize_path(""), Err(PathValidationError::EmptyPath)));
        assert!(matches!(validate_and_normalize_path("foo/./bar"), Err(PathValidationError::TraversalAttempt)));
        assert!(matches!(validate_and_normalize_path("foo/../bar"), Err(PathValidationError::TraversalAttempt)));
        assert!(matches!(validate_and_normalize_path("foo\\bar"), Err(PathValidationError::BackslashForbidden)));
        assert!(matches!(validate_and_normalize_path("foo/\0/bar"), Err(PathValidationError::NullByteOrControlChar)));
    }
}
