use std::mem::replace;

use crate::errors::{NetdocParseError, NetdocParseErrorType as ErrType};

/// Netdoc parser.
///
/// Parse netdoc format into [`Item`]s.
/// Items are returned incrementally, allowing for zero-copy parsing.
pub struct NetdocParser<'a> {
    s: &'a str,
    off: usize,
    line: usize,
}

/// Single netdoc item.
///
/// Returned by iteration of [`NetdocParser`].
pub struct Item<'a> {
    s: &'a str,
    byte_off: usize,
    kw_len: usize,
    line_len: usize,
    object_len: usize,
}

const BEGIN: &str = "-----BEGIN ";
const END: &str = "-----END ";
const ENDL: &str = "-----";

impl<'a> NetdocParser<'a> {
    /// Create new [`NetdocParser`] to parse string.
    pub fn new(s: &'a str) -> Self {
        Self { s, off: 0, line: 1 }
    }

    /// Returns original string.
    pub const fn original_string(&self) -> &'a str {
        self.s
    }
}

impl<'a> Iterator for NetdocParser<'a> {
    type Item = Result<Item<'a>, NetdocParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.s.len() != self.off {
            // SAFETY: Offset will always be less than string length
            let s = unsafe { self.s.get_unchecked(self.off..) };

            if matches!(s.as_bytes(), b"opt " | b"opt\t") {
                return Some(Err(NetdocParseError {
                    line: self.line,
                    pos: 0,
                    reason: ErrType::OptKeyword,
                }));
            }

            let mut ki = s.len();
            let mut li = ki;
            for (i, c) in s.bytes().enumerate() {
                match c {
                    b' ' | b'\t' if i != 0 => {
                        ki = i;
                        li = i + 1;
                        break;
                    }
                    b'\n' if i != 0 => {
                        ki = i;
                        li = i;
                        break;
                    }
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => (),
                    b'-' if i != 0 => (),
                    _ => {
                        self.off = self.s.len();
                        return Some(Err(NetdocParseError {
                            line: self.line,
                            pos: i,
                            reason: ErrType::InvalidKeywordChar,
                        }));
                    }
                }
            }

            // SAFETY: Index is within or at the end of string
            let s = unsafe { s.get_unchecked(li..) };
            let Some(bi) = s.find('\n') else {
                self.off = self.s.len();
                return Some(Err(NetdocParseError {
                    line: self.line,
                    pos: 0,
                    reason: ErrType::NoNewline,
                }));
            };

            // SAFETY: Index is at newline within string
            let (a, s) = unsafe { (s.get_unchecked(..bi), s.get_unchecked(bi + 1..)) };

            enum AState {
                NonSpace,
                Space,
            }

            let mut t = AState::Space;
            for (i, c) in a.bytes().enumerate() {
                t = match (t, c) {
                    (_, b'\0') => {
                        self.off = self.s.len();
                        return Some(Err(NetdocParseError {
                            line: self.line,
                            pos: li + i,
                            reason: ErrType::Null,
                        }));
                    }
                    (AState::NonSpace, b' ' | b'\t') => AState::Space,
                    (AState::NonSpace, _) => AState::NonSpace,
                    (AState::Space, b' ' | b'\t') => {
                        self.off = self.s.len();
                        return Some(Err(NetdocParseError {
                            line: self.line,
                            pos: li + i,
                            reason: ErrType::InvalidArgumentChar,
                        }));
                    }
                    (AState::Space, _) => AState::NonSpace,
                };
            }

            if s.starts_with(BEGIN) {
                // Parse object
                self.line += 1;

                // SAFETY: String starts with BEGIN
                let s = unsafe { s.get_unchecked(BEGIN.len()..) };
                let Some(mut n) = s.find('\n') else {
                    self.off = self.s.len();
                    return Some(Err(NetdocParseError {
                        line: self.line,
                        pos: 0,
                        reason: ErrType::NoNewline,
                    }));
                };

                // SAFETY: Index is at newline within string
                let (s, mut r) = unsafe { (s.get_unchecked(..n), s.get_unchecked(n + 1..)) };
                n += BEGIN.len() + 1;

                if !s.ends_with(ENDL) {
                    self.off = self.s.len();
                    return Some(Err(NetdocParseError {
                        line: self.line,
                        pos: BEGIN.len() + s.len(),
                        reason: ErrType::InvalidObjectFormat,
                    }));
                }

                enum State {
                    Start,
                    WordBegin,
                    Word,
                    Space,
                }

                // SAFETY: String ends with ENDL
                let obj_s = unsafe { s.get_unchecked(..s.len() - ENDL.len()) };
                let mut w = State::Start;
                for (i, c) in obj_s.bytes().enumerate() {
                    w = match (w, c) {
                        (
                            State::Start | State::WordBegin | State::Word,
                            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9',
                        ) => State::Word,
                        (State::Space, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9') => State::WordBegin,
                        (State::Word, b'-') => State::Word,
                        (State::WordBegin | State::Word, b' ') => State::Space,
                        (State::Space, b' ') => {
                            self.off = self.s.len();
                            return Some(Err(NetdocParseError {
                                line: self.line,
                                pos: BEGIN.len() + i,
                                reason: ErrType::InvalidObjectFormat,
                            }));
                        }
                        _ => {
                            self.off = self.s.len();
                            return Some(Err(NetdocParseError {
                                line: self.line,
                                pos: BEGIN.len() + i,
                                reason: ErrType::InvalidKeywordChar,
                            }));
                        }
                    };
                }
                if !matches!(w, State::Word | State::WordBegin) {
                    self.off = self.s.len();
                    return Some(Err(NetdocParseError {
                        line: self.line,
                        pos: BEGIN.len() + s.len(),
                        reason: ErrType::InvalidKeywordChar,
                    }));
                }

                'outer: while !r.starts_with(END) {
                    self.line += 1;

                    for (i, c) in r.bytes().enumerate() {
                        match c {
                            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'=' => (),
                            b'\n' => {
                                // SAFETY: Index is at newline within string
                                r = unsafe { r.get_unchecked(i + 1..) };
                                n += i + 1;
                                continue 'outer;
                            }
                            _ => {
                                self.off = self.s.len();
                                return Some(Err(NetdocParseError {
                                    line: self.line,
                                    pos: i,
                                    reason: ErrType::InvalidObjectContent,
                                }));
                            }
                        }
                    }

                    self.off = self.s.len();
                    return Some(Err(NetdocParseError {
                        line: self.line,
                        pos: 0,
                        reason: ErrType::NoNewline,
                    }));
                }

                // SAFETY: String starts with END
                let s = unsafe { r.get_unchecked(END.len()..) };
                let Some(i) = s.find('\n') else {
                    self.off = self.s.len();
                    return Some(Err(NetdocParseError {
                        line: self.line,
                        pos: 0,
                        reason: ErrType::NoNewline,
                    }));
                };

                // SAFETY: Index is at newline within string
                let (s, r) = unsafe { (s.get_unchecked(..i), s.get_unchecked(i + 1..)) };
                n += END.len() + i;

                if !s.ends_with(ENDL) {
                    self.off = self.s.len();
                    return Some(Err(NetdocParseError {
                        line: self.line,
                        pos: BEGIN.len() + s.len(),
                        reason: ErrType::InvalidObjectFormat,
                    }));
                }

                // SAFETY: String is suffixed with ENDL
                let obj2_s = unsafe { s.get_unchecked(..s.len() - ENDL.len()) };
                if obj_s != obj2_s {
                    // End keyword did not match begin keyword
                    self.off = self.s.len();
                    return Some(Err(NetdocParseError {
                        line: self.line,
                        pos: END.len(),
                        reason: ErrType::InvalidObjectFormat,
                    }));
                }

                self.line += 1;
                let old_len = self.s.len() - self.off;
                let new_len = r.len();
                debug_assert_eq!(
                    new_len + n + li + bi + 2,
                    old_len,
                    "{new_len} + {n} + {li} + {bi} + 2 != {old_len}"
                );

                let l = n + li + bi + 1;
                // SAFETY: Index is within string
                let s = unsafe { self.s.get_unchecked(self.off..self.off + l) };
                let byte_off = self.off;
                self.off += l + 1;

                return Some(Ok(Item {
                    s,
                    byte_off,
                    kw_len: ki,
                    line_len: li + bi,
                    object_len: obj_s.len(),
                }));
            } else {
                self.line += 1;
                let old_len = self.s.len() - self.off;
                let new_len = s.len();
                debug_assert_eq!(
                    new_len + li + bi + 1,
                    old_len,
                    "{new_len} + {li} + {bi} + 1 != {old_len}"
                );

                let l = li + bi;
                // SAFETY: Index is within string
                let s = unsafe { self.s.get_unchecked(self.off..self.off + l) };
                let byte_off = self.off;
                self.off += l + 1;

                return Some(Ok(Item {
                    s,
                    byte_off,
                    kw_len: ki,
                    line_len: li + bi,
                    object_len: 0,
                }));
            }
        }

        None
    }
}

impl<'a> Item<'a> {
    /// Keyword of item.
    pub fn keyword(&self) -> &'a str {
        // SAFETY: kw_len is within string
        unsafe { self.s.get_unchecked(..self.kw_len) }
    }

    /// Raw arguments.
    ///
    /// It is recommended to use [`Self::arguments()`] instead.
    pub fn arguments_raw(&self) -> &'a str {
        if self.kw_len == self.line_len {
            return "";
        }
        // SAFETY: kw_len and line_len is within string
        unsafe { self.s.get_unchecked(self.kw_len + 1..self.line_len) }
    }

    /// Iterates over arguments.
    ///
    /// Unless specified otherwise, user must accept excess argument.
    pub fn arguments(&self) -> Arguments<'a> {
        Arguments {
            s: self.arguments_raw(),
        }
    }

    /// Optional object of item.
    ///
    /// If exist, returns tuple of object keyword and content.
    pub fn object(&self) -> Option<(&'a str, &'a str)> {
        if self.line_len == self.s.len() {
            return None;
        }
        let start_kw = self.line_len + 1 + BEGIN.len();
        let end_kw = start_kw + self.object_len;
        let begin_line_len = end_kw + ENDL.len() + 1;
        let end_line_len = END.len() + self.object_len + ENDL.len();
        // SAFETY: Indices is within string
        unsafe {
            Some((
                self.s.get_unchecked(start_kw..end_kw),
                self.s
                    .get_unchecked(begin_line_len..self.s.len() - end_line_len),
            ))
        }
    }

    /// Returns byte offset of item.
    pub fn byte_offset(&self) -> usize {
        self.byte_off
    }
}

/// Iterator of netdoc item arguments.
pub struct Arguments<'a> {
    s: &'a str,
}

impl<'a> Iterator for Arguments<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        while self.s != "" {
            let Some(i) = self.s.find([' ', '\t']) else {
                return Some(replace(&mut self.s, ""));
            };

            // SAFETY: Index is space or tab within string
            let (a, b) = unsafe { (self.s.get_unchecked(..i), self.s.get_unchecked(i + 1..)) };
            self.s = b;
            return Some(a);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::option::of;
    use proptest::prelude::*;

    fn doc_strat() -> impl Strategy<Value = Vec<(String, Vec<String>, Option<(String, String)>)>> {
        vec(
            (
                "[a-zA-Z0-9][a-zA-Z0-9-]{1,16}".prop_filter("keyword is opt", |s| s != "opt"),
                vec("[ \t][^ \t\n\0]{1,8}", 0..8),
                of((
                    vec("[a-zA-Z0-9]{1,8}", 1..8).prop_map(|v| v.join(" ")),
                    "[a-zA-Z0-9+\\\n]{0,32}\n",
                )),
            ),
            0..32,
        )
    }

    fn ignore_parse(s: &str) {
        for i in NetdocParser::new(s) {
            i.unwrap();
        }
    }

    #[test]
    fn test_netdoc_empty() {
        assert!(NetdocParser::new("").next().is_none());
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line 1 byte 0: no newline found")]
    fn test_netdoc_no_newline() {
        ignore_parse("abc 123\t de-f");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line 1 byte 2: invalid keyword character")]
    fn test_netdoc_invalid_keyword() {
        ignore_parse("ab#3 211\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line 1 byte 8: invalid argument character")]
    fn test_netdoc_invalid_argument() {
        ignore_parse("ab3 1\t2  3\n");
    }

    proptest! {
        #[test]
        fn test_netdoc(doc in doc_strat()) {
            let mut s = String::new();
            for (k, a, o) in &doc {
                s += k;
                s.extend(a.iter().map(|s| &**s));
                s += "\n";
                if let Some((k, a)) = o {
                    s += BEGIN;
                    s += k;
                    s += ENDL;
                    s += "\n";
                    s += a;
                    s += END;
                    s += k;
                    s += ENDL;
                    s += "\n";
                }
            }

            let mut it = doc.into_iter();
            for i in NetdocParser::new(&s) {
                let i = i.unwrap();
                let (k, a, o) = it.next().unwrap();
                assert_eq!(i.keyword(), k);

                let a_ = a.iter().map(|s| &**s).collect::<String>();
                assert_eq!(i.arguments_raw(), if a_ == "" { "" } else { &a_[1..] });

                assert_eq!(i.arguments().take(a.len() + 1).collect::<Vec<_>>(), a.iter().map(|s| &s[1..]).collect::<Vec<_>>());

                let o_ = i.object();
                assert_eq!(o_.as_ref().map(|(a, b)| (&**a, &**b)), o.as_ref().map(|(a, b)| (&**a, &**b)));
            }
            assert_eq!(it.next(), None);
        }
    }
}
