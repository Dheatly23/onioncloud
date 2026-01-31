//! Reference/generic variant.
//!
//! Implements non-SIMD variant. Defines reference for all other implementations.
#![allow(dead_code)]

pub(crate) fn check_line(s: &str) -> Result<usize, usize> {
    for (i, c) in s.as_bytes().iter().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => (),
            b'-' if i != 0 => (),
            b' ' | b'\t' => return Ok(i),
            _ => return Err(i),
        }
    }

    Ok(s.len())
}

pub(crate) fn check_argument(s: &str) -> Option<usize> {
    enum State {
        NonSpace,
        Space,
    }

    let mut t = State::Space;
    for (i, c) in s.as_bytes().iter().enumerate() {
        t = match (t, c) {
            (_, b'\0' | b'\n') => return Some(i),
            (State::NonSpace, b' ' | b'\t') => State::Space,
            (State::NonSpace, _) => State::NonSpace,
            (State::Space, b' ' | b'\t') => return Some(i),
            (State::Space, _) => State::NonSpace,
        };
    }

    if matches!(t, State::Space) {
        return Some(s.len());
    }

    None
}

pub(crate) fn check_object_keyword(s: &str) -> Option<usize> {
    enum State {
        NonSpace,
        Space,
    }

    let mut t = State::Space;
    for (i, c) in s.as_bytes().iter().enumerate() {
        t = match (t, c) {
            (_, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9') | (State::NonSpace, b'-') => {
                State::NonSpace
            }
            (State::NonSpace, b' ') => State::Space,
            _ => return Some(i),
        };
    }

    if matches!(t, State::Space) {
        return Some(s.len());
    }

    None
}

pub(crate) fn check_object_content(s: &str) -> Option<usize> {
    s.as_bytes()
        .iter()
        .position(|c| !matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'='))
}
