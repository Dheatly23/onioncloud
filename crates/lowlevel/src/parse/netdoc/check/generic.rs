//! Reference/generic variant.
//!
//! Implements non-SIMD variant. Defines reference for all other implementations.
#![allow(dead_code)]

use std::mem::replace;

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

pub(crate) fn proto_keyword(s: &str) -> Result<usize, usize> {
    for (i, c) in s.as_bytes().iter().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => (),
            b'-' if i != 0 => (),
            b'=' if i != 0 => return Ok(i),
            _ => return Err(i),
        }
    }

    Err(s.len())
}

pub(crate) fn next_non_ws(s: &str) -> usize {
    s.as_bytes()
        .iter()
        .position(|c| !matches!(c, b' ' | b'\t'))
        .unwrap_or(s.len())
}

pub(crate) fn check_argument(s: &str) -> Option<usize> {
    if s.starts_with(" ") || s.starts_with("\t") {
        Some(0)
    } else if let r @ Some(_) = s.find(['\0', '\n']) {
        r
    } else if s.ends_with(" ") || s.ends_with("\t") {
        Some(s.len() - 1)
    } else {
        None
    }
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct ArgIterInner<'a>(&'a str);

impl<'a> From<&'a str> for ArgIterInner<'a> {
    fn from(s: &'a str) -> Self {
        Self(s)
    }
}

impl<'a> Iterator for ArgIterInner<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let Some((v, r)) = self.0.split_once([' ', '\t']) else {
            return if self.0.is_empty() {
                None
            } else {
                Some(replace(&mut self.0, ""))
            };
        };

        let i = r
            .find(|c| !matches!(c, ' ' | '\t'))
            .expect("string must be valid argument string");
        self.0 = &r[i..];
        Some(v)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.0.is_empty() {
            (0, Some(0))
        } else {
            (1, None)
        }
    }
}

impl<'a> DoubleEndedIterator for ArgIterInner<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let Some((r, v)) = self.0.rsplit_once([' ', '\t']) else {
            return if self.0.is_empty() {
                None
            } else {
                Some(replace(&mut self.0, ""))
            };
        };

        let mut i = r.len();
        while i > 0 {
            i -= 1;
            if !matches!(r.as_bytes()[i], b' ' | b'\t') {
                break;
            }
        }
        self.0 = &r[..=i];
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_iter_not_infinite(s in "[^\0\n \t]+([ \t]+[^\0\n \t]+){0,128}") {
            for (i, v) in ArgIterInner::from(&*s).enumerate() {
                assert!(i < 256, "index overflow! (value {v:?})");
            }

            for (i, v) in ArgIterInner::from(&*s).rev().enumerate() {
                assert!(i < 256, "index overflow! (value {v:?})");
            }
        }
    }
}
