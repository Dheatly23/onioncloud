mod check;

use std::cell::Cell;
use std::iter::{FusedIterator, from_fn};
use std::mem::{replace, take};

use memchr::{memchr_iter, memchr2, memrchr2};

use crate::errors::{NetdocParseError, NetdocParseErrorType as ErrType};

/// Netdoc parser.
///
/// Parse netdoc format into [`Item`]s.
/// Items are returned incrementally, allowing for zero-copy parsing.
///
/// # Stability (Non)-guarantee
///
/// If the document is **valid**, it's guaranteed it will produce the exact same items in order.
/// Reverse iteration will produce the exact order (in reverse) as forward iteration.
///
/// In case of **invalid** document, it's guaranteed it will produce error value eventually and then stops.
/// There is **no guarantee** when will error value be produced and/or it's content.
/// Reverse order is not guaranteed to produce the exact reverse of forward iteration.
pub struct NetdocParser<'a> {
    s: &'a str,
    off: Cell<usize>,
    end: Cell<usize>,
    line: Cell<isize>,
    endl: Cell<isize>,
}

// SAFETY: All the cells are written only with mutable borrow to the entire struct
// (similiar to wrapping it in nightly Exclusive type)
unsafe impl Sync for NetdocParser<'_> {}

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
        Self {
            s,
            off: Cell::new(0),
            end: Cell::new(s.len()),
            line: Cell::new(0),
            endl: Cell::new(0),
        }
    }

    /// Returns original string.
    pub const fn original_string(&self) -> &'a str {
        self.s
    }
}

impl<'a> Iterator for NetdocParser<'a> {
    type Item = Result<Item<'a>, NetdocParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.end.get() <= self.off.get() {
            return None;
        }

        let start = self.off.get();
        debug_assert!(
            self.s.is_char_boundary(start),
            "{start} is not in character boundary"
        );
        debug_assert!(
            self.s.is_char_boundary(self.end.get()),
            "{} is not in character boundary",
            self.end.get()
        );
        // SAFETY: Offset will always be less than end.
        // Both will always be less than or equal to string length
        let ori_s = unsafe { self.s.get_unchecked(start..self.end.get()) };

        let last = Cell::new(0usize);
        let mut it = memchr_iter(b'\n', ori_s.as_bytes()).map(|i| {
            let s = last.get();
            debug_assert!(s <= i);
            last.set(i + 1);
            // SAFETY: Indices is within string
            let s = unsafe { ori_s.get_unchecked(s..i) };

            let i = self.off.get();
            debug_assert_eq!(&self.s[i..i + s.len()], s);
            self.line.update(|l| l + 1);
            self.off.update(|o| o + s.len() + 1);
            s
        });

        let Some(s) = it.next() else {
            self.end.set(0);
            return Some(Err(NetdocParseError::with_line_pos(
                self.line.get() + 1,
                0,
                ErrType::NoNewline,
            )));
        };

        let line_len = s.len();
        let (is_opt, kw_len) = match check_item_line(s, self.line.get()) {
            Ok(v) => v,
            Err(e) => {
                self.end.set(0);
                return Some(Err(e));
            }
        };

        // SAFETY: Index is within string
        let s = unsafe { ori_s.get_unchecked(last.get()..) };
        if !s.starts_with(BEGIN) {
            // No oject
            let end = self.off.get();
            debug_assert!(end <= self.end.get(), "{} > {}", end, self.end.get());
            debug_assert_eq!(end - start, line_len + 1);
            debug_assert!(self.s[..end].ends_with("\n"));
            // SAFETY: Index is within string
            let s = unsafe { self.s.get_unchecked(start..end - 1) };

            return Some(Ok(Item {
                s,
                byte_off: start,
                is_opt,
                kw_len,
                line_len,
                object_len: 0,
            }));
        }

        // Parse object
        let Some(s) = it.next() else {
            self.end.set(0);
            return Some(Err(NetdocParseError::with_line_pos(
                self.line.get() + 1,
                0,
                ErrType::NoNewline,
            )));
        };

        if !s.ends_with(ENDL) {
            self.end.set(0);
            return Some(Err(NetdocParseError::with_line_pos(
                self.line.get(),
                0,
                ErrType::InvalidObjectFormat,
            )));
        }
        // SAFETY: String is prefixed with BEGIN and suffixed with ENDL
        let obj_s = unsafe { s.get_unchecked(BEGIN.len()..s.len() - ENDL.len()) };
        if let Some(e) = check_object_keyword(obj_s, self.line.get(), BEGIN.len()) {
            self.end.set(0);
            return Some(Err(e));
        }

        let s = loop {
            let Some(s) = it.next() else {
                self.end.set(0);
                return Some(Err(NetdocParseError::with_line_pos(
                    self.line.get() + 1,
                    0,
                    ErrType::NoNewline,
                )));
            };

            if s.starts_with(END) {
                break s;
            }

            if let Some(e) = check_object_content(s, self.line.get()) {
                self.end.set(0);
                return Some(Err(e));
            }
        };

        if !s.ends_with(ENDL) {
            self.end.set(0);
            return Some(Err(NetdocParseError::with_line_pos(
                self.line.get(),
                0,
                ErrType::InvalidObjectFormat,
            )));
        }

        // SAFETY: String is prefixed with END and suffixed with ENDL
        let obj2_s = unsafe { s.get_unchecked(END.len()..s.len() - ENDL.len()) };
        if obj_s != obj2_s {
            // End keyword did not match begin keyword
            self.end.set(0);
            return Some(Err(NetdocParseError::with_line_pos(
                self.line.get(),
                END.len(),
                ErrType::InvalidObjectFormat,
            )));
        }

        let end = self.off.get();
        debug_assert!(end <= self.end.get(), "{} > {}", end, self.end.get());
        debug_assert!(self.s[..end].ends_with("\n"));
        // SAFETY: Index is within string
        let s = unsafe { self.s.get_unchecked(start..end - 1) };

        Some(Ok(Item {
            s,
            byte_off: start,
            is_opt,
            kw_len,
            line_len,
            object_len: obj_s.len(),
        }))
    }
}

impl DoubleEndedIterator for NetdocParser<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.end.get() <= self.off.get() {
            return None;
        }

        let end = self.end.get();
        debug_assert!(
            self.s.is_char_boundary(end),
            "{end} is not in character boundary"
        );
        debug_assert!(
            self.s.is_char_boundary(self.off.get()),
            "{} is not in character boundary",
            self.off.get()
        );
        // SAFETY: Offset will always be less than end.
        // Both will always be less than or equal to string length
        let s = unsafe { self.s.get_unchecked(self.off.get()..end) };

        if !s.ends_with("\n") {
            self.end.set(0);
            return Some(Err(NetdocParseError::with_line_pos(
                self.endl.get() - 1,
                0,
                ErrType::NoNewline,
            )));
        }
        // SAFETY: String is suffixed with newline character
        let s = unsafe { s.get_unchecked(..s.len() - 1) };

        let mut last = s.len();
        let mut it = memchr_iter(b'\n', s.as_bytes());
        let mut it = from_fn(|| {
            let (i, e) = match it.next_back() {
                Some(i) => (i + 1, replace(&mut last, i)),
                None if last != usize::MAX => (0, replace(&mut last, usize::MAX)),
                None => return None,
            };
            debug_assert!(e >= i);
            // SAFETY: Indices is within string
            let s = unsafe { s.get_unchecked(i..e) };

            let i = self.end.get();
            debug_assert_eq!(&self.s[i - s.len() - 1..i - 1], s);
            self.endl.update(|l| l - 1);
            self.end.update(|o| o - s.len() - 1);
            Some(s)
        });

        let Some(s) = it.next() else {
            self.end.set(0);
            return Some(Err(NetdocParseError::with_line_pos(
                self.endl.get() - 1,
                0,
                ErrType::NoNewline,
            )));
        };

        let (object_len, line_s);
        if s.starts_with(END) {
            // Parse object
            if !s.ends_with(ENDL) {
                self.end.set(0);
                return Some(Err(NetdocParseError::with_line_pos(
                    self.endl.get(),
                    0,
                    ErrType::NoNewline,
                )));
            }

            // SAFETY: String is prefixed with END and suffixed with ENDL
            let obj_s = unsafe { s.get_unchecked(END.len()..s.len() - ENDL.len()) };
            if let Some(e) = check_object_keyword(obj_s, self.endl.get(), END.len()) {
                self.end.set(0);
                return Some(Err(e));
            }
            object_len = obj_s.len();

            let s = loop {
                let Some(s) = it.next() else {
                    self.end.set(0);
                    return Some(Err(NetdocParseError::with_line_pos(
                        self.endl.get() - 1,
                        0,
                        ErrType::NoNewline,
                    )));
                };

                if s.starts_with(BEGIN) {
                    break s;
                }

                if let Some(e) = check_object_content(s, self.endl.get()) {
                    self.end.set(0);
                    return Some(Err(e));
                }
            };

            if !s.ends_with(ENDL) {
                self.end.set(0);
                return Some(Err(NetdocParseError::with_line_pos(
                    self.endl.get(),
                    0,
                    ErrType::InvalidObjectFormat,
                )));
            }

            // SAFETY: String is prefixed with BEGIN and suffixed with ENDL
            let obj2_s = unsafe { s.get_unchecked(BEGIN.len()..s.len() - ENDL.len()) };
            if obj_s != obj2_s {
                // End keyword did not match begin keyword
                self.end.set(0);
                return Some(Err(NetdocParseError::with_line_pos(
                    self.endl.get(),
                    BEGIN.len(),
                    ErrType::InvalidObjectFormat,
                )));
            }

            let Some(s) = it.next() else {
                self.end.set(0);
                return Some(Err(NetdocParseError::with_line_pos(
                    self.endl.get() - 1,
                    0,
                    ErrType::NoNewline,
                )));
            };
            line_s = s;
        } else {
            // No object
            object_len = 0;
            line_s = s;
        }

        let line_len = line_s.len();
        let (is_opt, kw_len) = match check_item_line(line_s, self.endl.get()) {
            Ok(v) => v,
            Err(e) => {
                self.end.set(0);
                return Some(Err(e));
            }
        };

        let start = self.end.get();
        debug_assert!(self.off.get() <= start, "{} > {}", self.off.get(), start);
        debug_assert!(self.s[..start].is_empty() || self.s[..start].ends_with("\n"));
        // SAFETY: Index is within string
        let s = unsafe { self.s.get_unchecked(start..end - 1) };

        Some(Ok(Item {
            s,
            byte_off: start,
            is_opt,
            kw_len,
            line_len,
            object_len,
        }))
    }
}

impl FusedIterator for NetdocParser<'_> {}

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
        let Some(i) = memchr2(b' ', b'\t', self.s.as_bytes()) else {
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
        let Some(i) = memrchr2(b' ', b'\t', self.s.as_bytes()) else {
            return Some(take(&mut self.s));
        };

        // SAFETY: Index is space or tab within string
        let (a, b) = unsafe { (self.s.get_unchecked(..i), self.s.get_unchecked(i + 1..)) };
        self.s = a;
        Some(b)
    }
}

impl FusedIterator for Arguments<'_> {}

/// Return value of [`get_signature`].
#[non_exhaustive]
pub struct SignatureResult<'a> {
    /// Signature item.
    pub item: Item<'a>,
    /// Rest of the document.
    pub document: &'a str,
}

/// Get signature from document.
///
/// Signature is defined as last item in document with object.
/// If succeed, returns [`SignatureResult`]. Otherwise it returns error.
pub fn get_signature(document: &str) -> Result<SignatureResult<'_>, NetdocParseError> {
    if document.is_empty() {
        return Err(NetdocParseError::with_unknown_pos(ErrType::Empty));
    } else if !document.ends_with('\n') {
        return Err(NetdocParseError::with_byte_off(
            document.len() - 1,
            ErrType::NoNewline,
        ));
    }

    // SAFETY: Document is suffixed with newline
    let s = unsafe { document.get_unchecked(..document.len() - 1) };

    let l = Cell::new(0isize);
    let n = Cell::new(document.len());
    let mut it = s.split('\n').rev().inspect(|s| {
        l.update(|l| l - 1);
        n.update(|n| n - s.len() - 1);

        let i = n.get();
        debug_assert_eq!(&document[i..i + s.len()], *s);
    });

    let Some(s) = it.next() else {
        return Err(NetdocParseError::with_line_pos(-1, 0, ErrType::NoNewline));
    };

    if !s.ends_with(ENDL) || !s.starts_with(END) {
        return Err(NetdocParseError::with_line_pos(
            l.get(),
            0,
            ErrType::InvalidObjectFormat,
        ));
    }

    // SAFETY: String is prefixed with END and suffixed with ENDL
    let obj_s = unsafe { s.get_unchecked(END.len()..s.len() - ENDL.len()) };
    check_object_keyword(obj_s, l.get(), END.len()).map_or(Ok(()), Err)?;

    let s = loop {
        let Some(s) = it.next() else {
            return Err(NetdocParseError::with_line_pos(
                l.get(),
                0,
                ErrType::NoNewline,
            ));
        };

        if s.starts_with(BEGIN) {
            break s;
        }

        check_object_content(s, l.get()).map_or(Ok(()), Err)?;
    };

    if !s.ends_with(ENDL) {
        return Err(NetdocParseError::with_line_pos(
            l.get(),
            s.len() - 1,
            ErrType::InvalidObjectFormat,
        ));
    }

    // SAFETY: String is prefixed with BEGIN and suffixed with ENDL
    let obj2_s = unsafe { s.get_unchecked(BEGIN.len()..s.len() - ENDL.len()) };
    if obj_s != obj2_s {
        return Err(NetdocParseError::with_line_pos(
            l.get(),
            BEGIN.len(),
            ErrType::InvalidObjectFormat,
        ));
    }

    let Some(s) = it.next() else {
        return Err(NetdocParseError::with_line_pos(
            l.get(),
            0,
            ErrType::NoNewline,
        ));
    };

    let line_len = s.len();
    let (is_opt, kw_len) = check_item_line(s, l.get())?;

    let i = n.get();
    // SAFETY: Index points to character right after newline within string
    let (s, r) = unsafe {
        (
            document.get_unchecked(i..document.len() - 1),
            document.get_unchecked(..i),
        )
    };
    Ok(SignatureResult {
        document: r,
        item: Item {
            s,
            byte_off: i,
            is_opt,
            kw_len,
            line_len,
            object_len: obj_s.len(),
        },
    })
}

fn is_opt(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }

    // SAFETY: String is at least 4 bytes long
    let v = u32::from_le_bytes(unsafe { *s.as_ptr().cast::<[u8; 4]>() });

    const C: u32 = b'o' as u32 | (b'p' as u32) << 8 | (b't' as u32) << 16;
    const C1: u32 = C | (b' ' as u32) << 24;
    const C2: u32 = C | (b'\t' as u32) << 24;
    v == C1 || v == C2
}

fn check_item_line(s: &str, line: isize) -> Result<(bool, usize), NetdocParseError> {
    let is_opt = is_opt(s);
    let s = if is_opt {
        // SAFETY: String is prefixed with opt
        unsafe { s.get_unchecked(4..) }
    } else {
        s
    };

    let ki = match check::check_line(s) {
        Ok(i) => i,
        Err(i) => {
            return Err(NetdocParseError::with_line_pos(
                line,
                if is_opt { 4 } else { 0 } + i,
                ErrType::InvalidKeywordChar,
            ));
        }
    };

    if ki != s.len() {
        // SAFETY: Index points to space or tab character after keyword or end of string
        let a = unsafe { s.get_unchecked(ki + 1..) };
        if let Some(i) = check::check_argument(a) {
            return Err(NetdocParseError::with_line_pos(
                line,
                if is_opt { 4 } else { 0 } + ki + 1 + i,
                if let Some(0) = a.as_bytes().get(i) {
                    ErrType::Null
                } else {
                    ErrType::InvalidArgumentChar
                },
            ));
        }
    }

    Ok((is_opt, ki))
}

fn check_object_keyword(s: &str, line: isize, off: usize) -> Option<NetdocParseError> {
    check::check_object_keyword(s)
        .map(|i| NetdocParseError::with_line_pos(line, off + i, ErrType::InvalidKeywordChar))
}

fn check_object_content(s: &str, line: isize) -> Option<NetdocParseError> {
    check::check_object_content(s)
        .map(|i| NetdocParseError::with_line_pos(line, i, ErrType::InvalidObjectContent))
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::option::of;
    use proptest::prelude::*;

    fn item_strat() -> impl Strategy<Value = (&'static str, String, Vec<(char, String)>)> {
        (
            prop_oneof![Just(""), Just("opt "), Just("opt\t")],
            "[a-zA-Z0-9][a-zA-Z0-9-]{0,16}".prop_filter("keyword is opt", |s| s != "opt"),
            vec(
                (prop_oneof![Just(' '), Just('\t')], "[^ \t\n\0]{1,8}"),
                0..8,
            ),
        )
    }

    fn sig_strat() -> impl Strategy<Value = (String, String)> {
        (
            "([a-zA-Z0-9][a-zA-Z0-9-]{0,8} ){0,8}[a-zA-Z0-9][a-zA-Z0-9-]{0,16}",
            "([a-zA-Z0-9+\\\n]{1,32}\n)?",
        )
    }

    fn doc_strat() -> impl Strategy<
        Value = Vec<(
            &'static str,
            String,
            Vec<(char, String)>,
            Option<(String, String)>,
        )>,
    > {
        vec(
            (item_strat(), of(sig_strat())).prop_map(|((a, b, c), d)| (a, b, c, d)),
            0..32,
        )
    }

    fn to_argument_raw(a: &[(char, String)]) -> String {
        let mut a_ = String::new();
        for (i, (c, v)) in a.iter().enumerate() {
            if i != 0 {
                a_.push(*c);
            }
            a_ += v;
        }
        a_
    }

    fn ignore_parse(s: &str) {
        for i in NetdocParser::new(s) {
            i.unwrap();
        }
    }

    fn rev_ignore_parse(s: &str) {
        for i in NetdocParser::new(s).rev() {
            i.unwrap();
        }
    }

    #[test]
    fn test_netdoc_empty() {
        assert!(NetdocParser::new("").next().is_none());
        assert!(NetdocParser::new("").next_back().is_none());
    }

    #[test]
    fn test_netdoc_some_doc() {
        const DOC: &str = r#"ABC
DEF
"#;

        for (i, item) in NetdocParser::new(DOC).enumerate() {
            let item = item.unwrap();
            match i {
                0 => assert_eq!(item.keyword(), "ABC"),
                1 => assert_eq!(item.keyword(), "DEF"),
                _ => unreachable!("should only be 2 items max"),
            }
        }

        for (i, item) in NetdocParser::new(DOC).rev().enumerate() {
            let item = item.unwrap();
            match i {
                0 => assert_eq!(item.keyword(), "DEF"),
                1 => assert_eq!(item.keyword(), "ABC"),
                _ => unreachable!("should only be 2 items max"),
            }
        }
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line 1 byte 0: no newline found")]
    fn test_netdoc_no_newline() {
        ignore_parse("abc 123\tde-f");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line -1 byte 0: no newline found")]
    fn test_netdoc_rev_no_newline() {
        rev_ignore_parse("abc 123\tde-f");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line 1 byte 2: invalid keyword character")]
    fn test_netdoc_invalid_keyword() {
        ignore_parse("ab#3 211\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line -1 byte 2: invalid keyword character")]
    fn test_netdoc_rev_invalid_keyword() {
        rev_ignore_parse("ab#3 211\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line 1 byte 8: invalid argument character")]
    fn test_netdoc_invalid_argument() {
        ignore_parse("ab3 1\t2  3\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line -1 byte 8: invalid argument character")]
    fn test_netdoc_rev_invalid_argument() {
        rev_ignore_parse("ab3 1\t2  3\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line 2 byte 0: invalid object format")]
    fn test_netdoc_object_invalid_format() {
        ignore_parse("abc 123\n-----BEGIN TEST_____\n-----END TEST-----\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line -2 byte 0: invalid object format")]
    fn test_netdoc_rev_object_invalid_format() {
        rev_ignore_parse("abc 123\n-----BEGIN TEST_____\n-----END TEST-----\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line 2 byte 14: invalid keyword character")]
    fn test_netdoc_object_invalid_keyword() {
        ignore_parse("abc 123\n-----BEGIN ABC_DEF-----\n-----END ABC_DEF-----\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line -1 byte 12: invalid keyword character")]
    fn test_netdoc_rev_object_invalid_keyword() {
        rev_ignore_parse("abc 123\n-----BEGIN ABC_DEF-----\n-----END ABC_DEF-----\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line 3 byte 9: invalid object format")]
    fn test_netdoc_object_unequal_keyword() {
        ignore_parse("abc 123\n-----BEGIN ABCDEF-----\n-----END ABCFED-----\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line -2 byte 11: invalid object format")]
    fn test_netdoc_rev_object_unequal_keyword() {
        rev_ignore_parse("abc 123\n-----BEGIN ABCDEF-----\n-----END ABCFED-----\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line 3 byte 2: invalid object content")]
    fn test_netdoc_object_invalid_content() {
        ignore_parse("abc 123\n-----BEGIN ABCDEF-----\nab?123\n-----END ABCDEF-----\n");
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at line -2 byte 2: invalid object content")]
    fn test_netdoc_rev_object_invalid_content() {
        rev_ignore_parse("abc 123\n-----BEGIN ABCDEF-----\nab?123\n-----END ABCDEF-----\n");
    }

    proptest! {
        #[test]
        fn test_netdoc_forward_proptest(doc in doc_strat()) {
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

                assert_eq!(i.arguments_raw(), to_argument_raw(&a));
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

        #[test]
        fn test_netdoc_reverse_proptest(doc in doc_strat()) {
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

            let mut it = doc.into_iter().rev();
            for i in NetdocParser::new(&s).rev() {
                let i = i.unwrap();
                let (_, k, a, o) = it.next().unwrap();
                assert_eq!(i.keyword(), k);

                assert_eq!(i.arguments_raw(), to_argument_raw(&a));
                assert_eq!(i.arguments().take(a.len() + 1).collect::<Vec<_>>(), a.into_iter().map(|(_, i)| i).collect::<Vec<_>>());

                assert_eq!(i.object(), o.as_ref().map(|(a, b)| (&**a, &**b)));
            }
            assert_eq!(it.next(), None);
        }

        #[test]
        fn test_netdoc_get_signature_proptest(doc in doc_strat(), (opt, k, a) in item_strat(), sig in sig_strat()) {
            let mut s = String::new();
            for (opt, k, a, o) in doc.iter().map(|(a, b, c, d)| (a, b, c, d.as_ref())).chain([(&opt, &k, &a, Some(&sig))]) {
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

            let SignatureResult{document: rest, item} = get_signature(&s).unwrap();
            assert_eq!(item.keyword(), k);
            assert_eq!(item.arguments_raw(), to_argument_raw(&a));
            assert_eq!(item.object(), Some((&*sig.0, &*sig.1)));

            let mut it = doc.into_iter();
            for i in NetdocParser::new(&rest) {
                let i = i.unwrap();
                let (_, k, a, o) = it.next().unwrap();
                assert_eq!(i.keyword(), k);

                assert_eq!(i.arguments_raw(), to_argument_raw(&a));
                assert_eq!(i.arguments().take(a.len() + 1).collect::<Vec<_>>(), a.into_iter().map(|(_, i)| i).collect::<Vec<_>>());

                assert_eq!(i.object(), o.as_ref().map(|(a, b)| (&**a, &**b)));
            }
            assert_eq!(it.next(), None);
        }
    }
}
