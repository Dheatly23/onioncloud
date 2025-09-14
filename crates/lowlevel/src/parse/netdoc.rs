use std::iter::FusedIterator;
use std::mem::take;

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
    is_opt: bool,
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
        if self.s.len() == self.off {
            return None;
        }

        // SAFETY: Offset will always be less than string length
        let mut s = unsafe { self.s.get_unchecked(self.off..) };
        let is_opt = matches!(s.as_bytes(), [b'o', b'p', b't', b' ' | b'\t', ..]);

        let mut n = if is_opt {
            // SAFETY: String is prefixed with opt
            s = unsafe { s.get_unchecked(4..) };
            4
        } else {
            0
        };

        let mut t: Option<(usize, bool)> = None;
        for (i, c) in s.bytes().enumerate() {
            match c {
                b' ' | b'\t' if i != 0 => {
                    t = Some((i, false));
                    break;
                }
                b'\n' if i != 0 => {
                    t = Some((i, true));
                    break;
                }
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => (),
                b'-' if i != 0 => (),
                _ => {
                    self.off = self.s.len();
                    return Some(Err(NetdocParseError {
                        line: self.line,
                        pos: n + i,
                        reason: ErrType::InvalidKeywordChar,
                    }));
                }
            }
        }

        let Some((ki, is_endl)) = t else {
            self.off = self.s.len();
            return Some(Err(NetdocParseError {
                line: self.line,
                pos: 0,
                reason: ErrType::NoNewline,
            }));
        };

        let a;
        let li = n + if is_endl {
            a = "";
            // SAFETY: Index is at newline within string
            s = unsafe { s.get_unchecked(ki + 1..) };
            n += ki + 1;
            ki
        } else {
            // SAFETY: Index is within or at the end of string
            s = unsafe { s.get_unchecked(ki + 1..) };
            let Some(i) = s.find('\n') else {
                self.off = self.s.len();
                return Some(Err(NetdocParseError {
                    line: self.line,
                    pos: 0,
                    reason: ErrType::NoNewline,
                }));
            };

            // SAFETY: Index is at newline within string
            (a, s) = unsafe { (s.get_unchecked(..i), s.get_unchecked(i + 1..)) };
            n += ki + i + 2;
            ki + i + 1
        };

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
                        pos: ki + 1 + i,
                        reason: ErrType::Null,
                    }));
                }
                (AState::NonSpace, b' ' | b'\t') => AState::Space,
                (AState::NonSpace, _) => AState::NonSpace,
                (AState::Space, b' ' | b'\t') => {
                    self.off = self.s.len();
                    return Some(Err(NetdocParseError {
                        line: self.line,
                        pos: ki + 1 + i,
                        reason: ErrType::InvalidArgumentChar,
                    }));
                }
                (AState::Space, _) => AState::NonSpace,
            };
        }

        self.line += 1;
        if !s.starts_with(BEGIN) {
            // No oject
            let old_len = self.s.len() - self.off;
            let new_len = s.len();
            debug_assert_eq!(new_len + n, old_len, "{new_len} + {n} != {old_len}");

            // SAFETY: Index is within string
            let s = unsafe { self.s.get_unchecked(self.off..self.off + li) };
            let byte_off = self.off;
            self.off += n;

            return Some(Ok(Item {
                s,
                byte_off,
                is_opt,
                kw_len: ki,
                line_len: li,
                object_len: 0,
            }));
        }

        // Parse object
        // SAFETY: String starts with BEGIN
        s = unsafe { s.get_unchecked(BEGIN.len()..) };
        let Some(i) = s.find('\n') else {
            self.off = self.s.len();
            return Some(Err(NetdocParseError {
                line: self.line,
                pos: 0,
                reason: ErrType::NoNewline,
            }));
        };

        let mut r;
        // SAFETY: Index is at newline within string
        unsafe {
            r = s.get_unchecked(i + 1..);
            s = s.get_unchecked(..i);
        }
        n += BEGIN.len() + i + 1;

        if !s.ends_with(ENDL) {
            self.off = self.s.len();
            return Some(Err(NetdocParseError {
                line: self.line,
                pos: BEGIN.len() + s.len(),
                reason: ErrType::InvalidObjectFormat,
            }));
        }

        enum KState {
            Start,
            WordBegin,
            Word,
            Space,
        }

        // SAFETY: String ends with ENDL
        let obj_s = unsafe { s.get_unchecked(..s.len() - ENDL.len()) };
        let mut t = KState::Start;
        for (i, c) in obj_s.bytes().enumerate() {
            t = match (t, c) {
                (
                    KState::Start | KState::WordBegin | KState::Word,
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9',
                ) => KState::Word,
                (KState::Space, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9') => KState::WordBegin,
                (KState::Word, b'-') => KState::Word,
                (KState::WordBegin | KState::Word, b' ') => KState::Space,
                (KState::Space, b' ') => {
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
        if !matches!(t, KState::Word | KState::WordBegin) {
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
        self.line += 1;

        // SAFETY: String starts with END
        s = unsafe { r.get_unchecked(END.len()..) };
        let Some(i) = s.find('\n') else {
            self.off = self.s.len();
            return Some(Err(NetdocParseError {
                line: self.line,
                pos: 0,
                reason: ErrType::NoNewline,
            }));
        };

        // SAFETY: Index is at newline within string
        unsafe {
            r = s.get_unchecked(i + 1..);
            s = s.get_unchecked(..i);
        }
        n += END.len() + i + 1;

        if !s.ends_with(ENDL) {
            self.off = self.s.len();
            return Some(Err(NetdocParseError {
                line: self.line,
                pos: END.len() + s.len(),
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
        debug_assert_eq!(new_len + n, old_len, "{new_len} + {n} != {old_len}");

        // SAFETY: Index is within string
        s = unsafe { self.s.get_unchecked(self.off..self.off + n - 1) };
        let byte_off = self.off;
        self.off += n;

        Some(Ok(Item {
            s,
            byte_off,
            is_opt,
            kw_len: ki,
            line_len: li,
            object_len: obj_s.len(),
        }))
    }
}

impl<'a> Item<'a> {
    /// Keyword of item.
    pub fn keyword(&self) -> &'a str {
        let o = if self.is_opt { 4 } else { 0 };
        // SAFETY: kw_len is within string
        unsafe { self.s.get_unchecked(o..o + self.kw_len) }
    }

    /// Raw arguments.
    ///
    /// It is recommended to use [`Self::arguments()`] instead.
    pub fn arguments_raw(&self) -> &'a str {
        let o = if self.is_opt { 4 } else { 0 };
        if self.kw_len + o == self.line_len {
            return "";
        }
        // SAFETY: kw_len and line_len is within string
        unsafe { self.s.get_unchecked(o + self.kw_len + 1..self.line_len) }
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

    /// Returns length of item line (excluding object and trailing newline).
    pub fn line_len(&self) -> usize {
        self.line_len
    }
}

/// Iterator of netdoc item arguments.
pub struct Arguments<'a> {
    s: &'a str,
}

impl<'a> Iterator for Arguments<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.s.is_empty() {
            return None;
        }
        let Some(i) = self.s.find([' ', '\t']) else {
            return Some(take(&mut self.s));
        };

        // SAFETY: Index is space or tab within string
        let (a, b) = unsafe { (self.s.get_unchecked(..i), self.s.get_unchecked(i + 1..)) };
        self.s = b;
        Some(a)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.s {
            "" => (0, Some(0)),
            _ => (1, None),
        }
    }
}

impl DoubleEndedIterator for Arguments<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.s.is_empty() {
            return None;
        }
        let Some(i) = self.s.rfind([' ', '\t']) else {
            return Some(take(&mut self.s));
        };

        // SAFETY: Index is space or tab within string
        let (a, b) = unsafe { (self.s.get_unchecked(..i), self.s.get_unchecked(i + 1..)) };
        self.s = a;
        Some(b)
    }
}

impl FusedIterator for Arguments<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::option::of;
    use proptest::prelude::*;

    fn doc_strat() -> impl Strategy<
        Value = Vec<(
            &'static str,
            String,
            Vec<(char, String)>,
            Option<(String, String)>,
        )>,
    > {
        vec(
            (
                prop_oneof![Just(""), Just("opt "), Just("opt\t")],
                "[a-zA-Z0-9][a-zA-Z0-9-]{1,16}".prop_filter("keyword is opt", |s| s != "opt"),
                vec(
                    (prop_oneof![Just(' '), Just('\t')], "[^ \t\n\0]{1,8}"),
                    0..8,
                ),
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
            for (opt, k, a, o) in &doc {
                s += opt;
                s += k;

                for (c, v) in a {
                    s.push(*c);
                    s += v;
                }

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
                let (_, k, a, o) = it.next().unwrap();
                assert_eq!(i.keyword(), k);

                {
                    let mut a_ = String::new();
                    for (i, (c, v)) in a.iter().enumerate() {
                        if i != 0 {
                            a_.push(*c);
                        }
                        a_ += v;
                    }
                    assert_eq!(i.arguments_raw(), a_);
                }

                {
                    let mut a = a.into_iter().map(|(_, i)| i).collect::<Vec<_>>();
                    assert_eq!(i.arguments().take(a.len() + 1).collect::<Vec<_>>(), a);
                    a.reverse();
                    assert_eq!(i.arguments().rev().take(a.len() + 1).collect::<Vec<_>>(), a);
                }

                assert_eq!(i.object(), o.as_ref().map(|(a, b)| (&**a, &**b)));
            }
            assert_eq!(it.next(), None);
        }
    }
}
