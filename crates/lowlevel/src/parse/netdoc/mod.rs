mod check;

use std::cell::Cell;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::iter::{FusedIterator, from_fn};
use std::mem::replace;

use memchr::{Memchr2, memchr_iter};

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
#[derive(Clone)]
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
#[derive(Clone)]
pub struct Item<'a> {
    s: &'a str,
    byte_off: usize,
    is_opt: bool,
    kw_len: usize,
    line_len: usize,
    object_len: usize,
}

impl Debug for Item<'_> {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> FmtResult {
        fmt.debug_struct("Item")
            .field("s", &self.s)
            .field("byte_off", &self.byte_off)
            .finish_non_exhaustive()
    }
}

const BEGIN: &str = "-----BEGIN ";
const END: &str = "-----END ";
const ENDL: &str = "-----";

impl<'a> NetdocParser<'a> {
    /// Create new [`NetdocParser`] to parse string.
    pub const fn new(s: &'a str) -> Self {
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

    /// Force terminate parser.
    ///
    /// Afterwards it's guaranteed to stop iterating.
    pub fn terminate(&mut self) {
        self.end.set(0);
    }
}

impl<'a> Iterator for NetdocParser<'a> {
    type Item = Result<Item<'a>, NetdocParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.end.get() <= self.off.get() {
                return None;
            }

            let start = self.off.get();
            // SAFETY: Indices is within string.
            let b = unsafe { self.s.as_bytes().get_unchecked(start) };
            // Skip empty lines
            if *b != b'\n' {
                break;
            }
            self.off.set(start + 1);
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
        loop {
            if self.end.get() <= self.off.get() {
                return None;
            }

            let end = self.end.get();
            // SAFETY: Indices is within string
            let s = unsafe { self.s.get_unchecked(..end) };
            // Skip empty lines
            if !s.ends_with("\n\n") {
                break;
            }
            self.end.set(end - 1);
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
    /// Parses a line item **without trailing newline** into [`Item`].
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::parse::netdoc::Item;
    ///
    /// // Parse line item
    /// let item = Item::try_parse_str("keyword arg1 arg2", 0).unwrap();
    /// assert_eq!(item.keyword(), "keyword");
    /// assert_eq!(item.arguments().iter().collect::<Vec<_>>(), ["arg1", "arg2"]);
    ///
    /// // With byte offset
    /// let item = Item::try_parse_str("keyword", 123).unwrap();
    /// assert_eq!(item.byte_offset(), 123);
    ///
    /// // Object is also supported
    /// let s = r"with-object
    /// -----BEGIN KEYWORD-----
    /// abcdef
    /// -----END KEYWORD-----";
    /// let item = Item::try_parse_str(s, 0).unwrap();
    /// assert_eq!(item.keyword(), "with-object");
    /// assert_eq!(item.object(), Some(("KEYWORD", "abcdef\n")));
    ///
    /// // Trailing newline
    /// Item::try_parse_str("trailing\n", 0).unwrap_err();
    ///
    /// // Empty string
    /// Item::try_parse_str("", 0).unwrap_err();
    ///
    /// // Leading newline
    /// Item::try_parse_str("\nleading", 0).unwrap_err();
    /// ```
    pub fn try_parse_str(s: &'a str, byte_offset: usize) -> Result<Self, NetdocParseError> {
        if s.ends_with("\n") {
            return Err(NetdocParseError::with_byte_off(
                byte_offset + (s.len() - 1),
                ErrType::HasTrailing,
            ));
        }
        let ori_s = s;

        // Setup iterator.
        // Iterator should iterates through all lines,
        // including last line without trailing newline.
        let last = Cell::new(0usize);
        let mut it = memchr_iter(b'\n', s.as_bytes());
        let mut f = || {
            let t = last.get();
            let i = if let Some(i) = it.next() {
                last.set(i + 1);
                i
            } else if t < s.len() {
                last.set(s.len());
                s.len()
            } else {
                return None;
            };
            debug_assert!(t <= i);
            // SAFETY: Indices is within string
            unsafe { Some((s.get_unchecked(t..i), byte_offset + t)) }
        };

        // Parse first line
        let Some((s, off)) = f() else {
            debug_assert_eq!(s, "");
            return Err(NetdocParseError::with_byte_off(byte_offset, ErrType::Empty));
        };

        let line_len = s.len();
        // Parse opt
        let is_opt = s.starts_with("opt ") | s.starts_with("opt\t");
        let s = if is_opt {
            // SAFETY: String is prefixed with opt
            unsafe { s.get_unchecked(4..) }
        } else {
            s
        };

        // Parse keyword
        let kw_len = match check::check_line(s) {
            Ok(0) => {
                return Err(NetdocParseError::with_byte_off(
                    off + if is_opt { 4 } else { 0 },
                    ErrType::InvalidKeywordChar,
                ));
            }
            Ok(i) => i,
            Err(i) => {
                return Err(NetdocParseError::with_byte_off(
                    off + if is_opt { 4 } else { 0 } + i,
                    ErrType::InvalidKeywordChar,
                ));
            }
        };

        // Parse arguments
        if kw_len != s.len() {
            // SAFETY: Index points to space or tab character after keyword or end of string
            let a = unsafe { s.get_unchecked(kw_len + 1..) };
            if let Some(i) = check::check_argument(a) {
                return Err(NetdocParseError::with_byte_off(
                    off + if is_opt { 4 } else { 0 } + kw_len + 1 + i,
                    if let Some(0) = a.as_bytes().get(i) {
                        ErrType::Null
                    } else {
                        ErrType::InvalidArgumentChar
                    },
                ));
            }
        }

        let Some((s, off)) = f() else {
            debug_assert_eq!(line_len, ori_s.len());
            debug_assert_eq!(off, byte_offset);
            return Ok(Self {
                s: ori_s,
                byte_off: byte_offset,
                is_opt,
                kw_len,
                line_len,
                object_len: 0,
            });
        };

        // Parse object
        if !s.starts_with(BEGIN) || !s.ends_with(ENDL) {
            return Err(NetdocParseError::with_byte_off(
                off,
                ErrType::InvalidObjectFormat,
            ));
        }
        // SAFETY: String is prefixed with BEGIN and suffixed with ENDL
        let obj_s = unsafe { s.get_unchecked(BEGIN.len()..s.len() - ENDL.len()) };
        if let Some(i) = check::check_object_keyword(obj_s) {
            return Err(NetdocParseError::with_byte_off(
                off + BEGIN.len() + i,
                ErrType::InvalidKeywordChar,
            ));
        }

        let (s, off) = loop {
            let Some((s, off)) = f() else {
                return Err(NetdocParseError::with_byte_off(
                    off,
                    ErrType::InvalidObjectFormat,
                ));
            };

            if s.starts_with(END) {
                break (s, off);
            }

            if let Some(i) = check::check_object_content(s) {
                return Err(NetdocParseError::with_byte_off(
                    off + i,
                    ErrType::InvalidObjectContent,
                ));
            }
        };

        if !s.ends_with(ENDL) {
            return Err(NetdocParseError::with_byte_off(
                off,
                ErrType::InvalidObjectFormat,
            ));
        }

        // SAFETY: String is prefixed with END and suffixed with ENDL
        let obj2_s = unsafe { s.get_unchecked(END.len()..s.len() - ENDL.len()) };
        if obj_s != obj2_s {
            // End keyword did not match begin keyword
            return Err(NetdocParseError::with_byte_off(
                off + END.len(),
                ErrType::InvalidObjectFormat,
            ));
        }

        if let Some((_, off)) = f() {
            return Err(NetdocParseError::with_byte_off(off, ErrType::HasTrailing));
        }

        Ok(Item {
            s: ori_s,
            byte_off: byte_offset,
            is_opt,
            kw_len,
            line_len,
            object_len: obj_s.len(),
        })
    }

    /// Gets raw item string.
    ///
    /// It excludes trailing newline.
    #[inline(always)]
    pub fn raw_string(&self) -> &'a str {
        self.s
    }

    /// Keyword of item.
    pub fn keyword(&self) -> &'a str {
        let o = if self.is_opt { 4 } else { 0 };
        // SAFETY: kw_len is within string
        unsafe { self.s.get_unchecked(o..o + self.kw_len) }
    }

    /// Iterates over arguments.
    ///
    /// Unless specified otherwise, user must accept excess argument.
    pub fn arguments(&self) -> Arguments<'a> {
        let o = if self.is_opt { 4 } else { 0 };
        Arguments {
            s: if self.kw_len + o == self.line_len {
                ""
            } else {
                // SAFETY: kw_len and line_len is within string
                unsafe { self.s.get_unchecked(o + self.kw_len + 1..self.line_len) }
            },
        }
    }

    /// Raw object string.
    ///
    /// Returns the entire object string, including trailing newline.
    pub fn object_raw(&self) -> Option<&'a str> {
        if !self.has_object() {
            return None;
        }
        // SAFETY: Indices is within string
        unsafe { Some(self.s.get_unchecked(self.line_len + 1..)) }
    }

    /// Optional object of item.
    ///
    /// If exist, returns tuple of object keyword and content.
    pub fn object(&self) -> Option<(&'a str, &'a str)> {
        if !self.has_object() {
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

    /// Return `true` if item has object.
    pub fn has_object(&self) -> bool {
        self.line_len != self.s.len()
    }

    /// Returns byte offset of item.
    pub fn byte_offset(&self) -> usize {
        self.byte_off
    }

    /// Returns length of item line (excluding object and trailing newline).
    pub fn line_len(&self) -> usize {
        self.line_len
    }

    /// Returns total length of item (including object but excluding trailing newline).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.s.len()
    }
}

/// Parses a line item **without trailing newline**.
///
/// Byte offset will be set to 0.
///
/// It does not implemeent [`FromStr`] because it takes the lifetime of the string.
///
/// See: [`Self::try_parse_str`].
impl<'a> TryFrom<&'a str> for Item<'a> {
    type Error = NetdocParseError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::try_parse_str(s, 0)
    }
}

/// Netdoc item arguments.
#[derive(Debug, Clone)]
pub struct Arguments<'a> {
    s: &'a str,
}

/// Parses an argument string.
///
/// Valid argument string is in the form of `([^ \t]+([ \t][^ \t]+)*)?`.
/// Also it **should not** contain NUL character.
///
/// It does not implemeent [`FromStr`] because it takes the lifetime of the string.
///
/// # Example
///
/// ```
/// use onioncloud_lowlevel::parse::netdoc::Arguments;
///
/// // Parsing argument string
/// assert_eq!(Arguments::try_from("ab cd\tef").unwrap().iter().collect::<Vec<_>>(), ["ab", "cd", "ef"]);
///
/// // Empty string is valid
/// assert_eq!(Arguments::try_from("").unwrap().iter().collect::<Vec<_>>().len(), 0);
///
/// // Consequentive whitespace
/// let _ = Arguments::try_from("ab cd \tef").unwrap_err();
///
/// // Trailing whitespace
/// let _ = Arguments::try_from("ab cd ").unwrap_err();
///
/// // Leading whitespace
/// let _ = Arguments::try_from(" ab\tcd").unwrap_err();
/// ```
impl<'a> TryFrom<&'a str> for Arguments<'a> {
    type Error = NetdocParseError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Ok(Self { s });
        }

        match check::check_argument(s) {
            Some(i) => Err(NetdocParseError::with_byte_off(
                i,
                if let Some(0) = s.as_bytes().get(i) {
                    ErrType::Null
                } else {
                    ErrType::InvalidArgumentChar
                },
            )),
            None => Ok(Self { s }),
        }
    }
}

impl<'a> IntoIterator for Arguments<'a> {
    type Item = <ArgumentsIter<'a> as Iterator>::Item;
    type IntoIter = ArgumentsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &Arguments<'a> {
    type Item = <ArgumentsIter<'a> as Iterator>::Item;
    type IntoIter = ArgumentsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> Arguments<'a> {
    /// Directly converts argument string into [`Arguments`].
    ///
    /// # Safety
    ///
    /// String must be a valid argument string. See it's [`TryFrom`] impl.
    /// String returned from [`Self::raw_string`] are always safe.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::parse::netdoc::Arguments;
    ///
    /// let args = Arguments::try_from("a b c").unwrap();
    /// // SAFETY: String is a valid argument string.
    /// let args = unsafe { Arguments::from_string_unchecked(args.raw_string()) };
    /// ```
    #[inline(always)]
    pub const unsafe fn from_string_unchecked(s: &'a str) -> Self {
        Self { s }
    }

    /// Gets raw string.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::parse::netdoc::Arguments;
    ///
    /// let args = Arguments::try_from("a b c").unwrap();
    /// assert_eq!(args.raw_string(), "a b c");
    /// ```
    #[inline(always)]
    pub const fn raw_string(&self) -> &'a str {
        self.s
    }

    /// Iterates through arguments.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::parse::netdoc::Arguments;
    ///
    /// let args = Arguments::try_from("a b c").unwrap();
    /// for i in args.iter() {
    ///     // Argument items
    ///     println!("{i}");
    /// }
    /// ```
    pub fn iter(&self) -> ArgumentsIter<'a> {
        ArgumentsIter {
            s: self.s,
            off: 0,
            it: Memchr2::new(b' ', b'\t', self.s.as_bytes()),
        }
    }

    /// Checks if argument is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::parse::netdoc::Arguments;
    ///
    /// assert!(Arguments::try_from("").unwrap().is_empty());
    /// assert!(!Arguments::try_from("a").unwrap().is_empty());
    /// ```
    pub const fn is_empty(&self) -> bool {
        self.s.is_empty()
    }
}

/// Iterator of netdoc item arguments.
#[derive(Debug, Clone)]
pub struct ArgumentsIter<'a> {
    s: &'a str,
    off: usize,
    it: Memchr2<'a>,
}

impl<'a> Iterator for ArgumentsIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.s.is_empty() {
            return None;
        }
        let Some(mut i) = self.it.next() else {
            return Some(replace(&mut self.s, ""));
        };
        i -= self.off;
        self.off += i + 1;

        if cfg!(debug_assertions) {
            let s = &self.s[i..=i];
            debug_assert!(
                s == " " || s == "\t",
                "spacer string {s:#?} is not space or tab"
            );
        }

        // SAFETY: Index is space or tab within string
        let (a, b) = unsafe { (self.s.get_unchecked(..i), self.s.get_unchecked(i + 1..)) };
        self.s = b;
        Some(a)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.s.is_empty() {
            return (0, Some(0));
        }
        let (a, b) = self.it.size_hint();
        // Add 1 because we return one more item when iteration stops
        (a + 1, b.map(|v| v + 1))
    }
}

impl DoubleEndedIterator for ArgumentsIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.s.is_empty() {
            return None;
        }
        let Some(mut i) = self.it.next_back() else {
            return Some(replace(&mut self.s, ""));
        };
        i -= self.off;

        if cfg!(debug_assertions) {
            let s = &self.s[i..=i];
            debug_assert!(
                s == " " || s == "\t",
                "spacer string {s:#?} is not space or tab"
            );
        }

        // SAFETY: Index is space or tab within string
        let (a, b) = unsafe { (self.s.get_unchecked(..i), self.s.get_unchecked(i + 1..)) };
        self.s = a;
        Some(b)
    }
}

impl FusedIterator for ArgumentsIter<'_> {}

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

fn check_item_line(s: &str, line: isize) -> Result<(bool, usize), NetdocParseError> {
    let is_opt = s.starts_with("opt ") | s.starts_with("opt\t");
    let s = if is_opt {
        // SAFETY: String is prefixed with opt
        unsafe { s.get_unchecked(4..) }
    } else {
        s
    };

    let ki = match check::check_line(s) {
        Ok(0) => {
            return Err(NetdocParseError::with_line_pos(
                line,
                if is_opt { 4 } else { 0 },
                ErrType::InvalidKeywordChar,
            ));
        }
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

    fn doc_to_str(
        doc: &Vec<(
            &'static str,
            String,
            Vec<(char, String)>,
            Option<(String, String)>,
        )>,
    ) -> String {
        doc_to_str_it(doc.iter().map(|(a, b, c, d)| (*a, b, c, d.as_ref())))
    }

    fn doc_to_str_it<'a>(
        doc: impl IntoIterator<
            Item = (
                &'a str,
                &'a String,
                &'a Vec<(char, String)>,
                Option<&'a (String, String)>,
            ),
        >,
    ) -> String {
        let mut s = String::new();
        for (opt, k, a, o) in doc {
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
        s
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

    #[test]
    fn test_netdoc_item_parse_keyword() {
        let item = Item::try_from("abcdef").unwrap();
        assert_eq!(item.keyword(), "abcdef");
        assert_eq!(item.arguments().raw_string(), "");
        assert_eq!(item.object(), None);
    }

    #[test]
    fn test_netdoc_item_parse_argument() {
        let item = Item::try_from("abcdef 1 2 3").unwrap();
        assert_eq!(item.keyword(), "abcdef");
        assert_eq!(item.arguments().iter().collect::<Vec<_>>(), ["1", "2", "3"]);
        assert_eq!(item.object(), None);
    }

    #[test]
    fn test_netdoc_item_parse_object() {
        let item =
            Item::try_from("abcdef\n-----BEGIN ABCDEF-----\nabc123\n-----END ABCDEF-----").unwrap();
        assert_eq!(item.keyword(), "abcdef");
        assert_eq!(item.arguments().raw_string(), "");
        assert_eq!(item.object(), Some(("ABCDEF", "abc123\n")));
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at byte offset 0: document is empty")]
    fn test_netdoc_item_parse_empty() {
        Item::try_from("").unwrap();
    }

    #[test]
    #[should_panic(
        expected = "error parsing netdoc at byte offset 3: input string have trailing characters"
    )]
    fn test_netdoc_item_parse_trailing_nl() {
        Item::try_from("abc\n").unwrap();
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at byte offset 0: invalid keyword character")]
    fn test_netdoc_item_parse_leading_nl() {
        Item::try_from("\nabc").unwrap();
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at byte offset 4: invalid object format")]
    fn test_netdoc_item_parse_multi() {
        Item::try_from("abc\ndef").unwrap();
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at byte offset 0: invalid keyword character")]
    fn test_netdoc_item_parse_leading_nl2() {
        Item::try_from("\n-----BEGIN ABC DEF-----\n-----END ABC DEF-----").unwrap();
    }

    #[test]
    fn test_netdoc_argument_parse_simple() {
        assert_eq!(
            Arguments::try_from("a b c\td\te\tf")
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            ["a", "b", "c", "d", "e", "f"]
        );
    }

    #[test]
    fn test_netdoc_argument_parse_empty() {
        assert_eq!(Arguments::try_from("").unwrap().iter().count(), 0);
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at byte offset 6: invalid argument character")]
    fn test_netdoc_argument_parse_trailing() {
        Arguments::try_from("a b c ").unwrap();
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at byte offset 0: invalid argument character")]
    fn test_netdoc_argument_parse_leading() {
        Arguments::try_from("\ta b c").unwrap();
    }

    #[test]
    #[should_panic(expected = "error parsing netdoc at byte offset 2: invalid argument character")]
    fn test_netdoc_argument_parse_spacing() {
        Arguments::try_from("a  b c").unwrap();
    }

    proptest! {
        #[test]
        fn test_netdoc_forward_proptest(doc in doc_strat()) {
            let s = doc_to_str(&doc);

            let mut it = doc.into_iter();
            for i in NetdocParser::new(&s) {
                let i = i.unwrap();
                let (_, k, a, o) = it.next().unwrap();
                assert_eq!(i.keyword(), k);

                assert_eq!(i.arguments().raw_string(), to_argument_raw(&a));
                {
                    let mut a = a.into_iter().map(|(_, i)| i).collect::<Vec<_>>();
                    assert_eq!(i.arguments().iter().take(a.len() + 1).collect::<Vec<_>>(), a);
                    a.reverse();
                    assert_eq!(i.arguments().iter().rev().take(a.len() + 1).collect::<Vec<_>>(), a);
                }

                assert_eq!(i.object(), o.as_ref().map(|(a, b)| (&**a, &**b)));
            }
            assert_eq!(it.next(), None);
        }

        #[test]
        fn test_netdoc_reverse_proptest(doc in doc_strat()) {
            let s = doc_to_str(&doc);

            let mut it = doc.into_iter().rev();
            for i in NetdocParser::new(&s).rev() {
                let i = i.unwrap();
                let (_, k, a, o) = it.next().unwrap();
                assert_eq!(i.keyword(), k);

                assert_eq!(i.arguments().raw_string(), to_argument_raw(&a));
                assert_eq!(i.arguments().iter().take(a.len() + 1).collect::<Vec<_>>(), a.into_iter().map(|(_, i)| i).collect::<Vec<_>>());

                assert_eq!(i.object(), o.as_ref().map(|(a, b)| (&**a, &**b)));
            }
            assert_eq!(it.next(), None);
        }

        #[test]
        fn test_netdoc_item_reparse(doc in doc_strat()) {
            let s = doc_to_str(&doc);
            drop(doc);

            for i in NetdocParser::new(&s) {
                let i = i.unwrap();
                let j = Item::try_parse_str(i.s, i.byte_off).unwrap();
                assert_eq!(j.s, i.s);
                assert_eq!(j.byte_off, i.byte_off);
                assert_eq!(j.is_opt, i.is_opt);
                assert_eq!(j.kw_len, i.kw_len);
                assert_eq!(j.line_len, i.line_len);
                assert_eq!(j.object_len, i.object_len);

                let i = i.arguments();
                let j = Arguments::try_from(i.s).unwrap();
                assert_eq!(j.s, i.s);
            }
        }

        #[test]
        fn test_netdoc_get_signature_proptest(doc in doc_strat(), (opt, k, a) in item_strat(), sig in sig_strat()) {
            let s = doc_to_str_it(doc.iter().map(|(a, b, c, d)| (*a, b, c, d.as_ref())).chain([(opt, &k, &a, Some(&sig))]));

            let SignatureResult{document: rest, item} = get_signature(&s).unwrap();
            assert_eq!(item.keyword(), k);
            assert_eq!(item.arguments().raw_string(), to_argument_raw(&a));
            assert_eq!(item.object(), Some((&*sig.0, &*sig.1)));

            let mut it = doc.into_iter();
            for i in NetdocParser::new(&rest) {
                let i = i.unwrap();
                let (_, k, a, o) = it.next().unwrap();
                assert_eq!(i.keyword(), k);

                assert_eq!(i.arguments().raw_string(), to_argument_raw(&a));
                assert_eq!(i.arguments().iter().take(a.len() + 1).collect::<Vec<_>>(), a.into_iter().map(|(_, i)| i).collect::<Vec<_>>());

                assert_eq!(i.object(), o.as_ref().map(|(a, b)| (&**a, &**b)));
            }
            assert_eq!(it.next(), None);
        }
    }
}
