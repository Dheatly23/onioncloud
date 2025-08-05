use std::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::mem::take;

use crate::cache::{Cachable, CellCache, CellCacheExt};
use crate::errors;

/// Helper for read buffers.
///
/// Useful for sans-io reader.
///
/// # [`Read`] Behavior
///
/// [`Buffer`] acts like a non-blocking reader.
/// When trying to read past it's end and it's not EOF, it will return [`ErrorKind::WouldBlock`] error.
pub struct Buffer<'a> {
    buf: &'a [u8],
    consumed: usize,
    eof: bool,
}

impl<'a> Buffer<'a> {
    /// Create new `Buffer`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            consumed: 0,
            eof: false,
        }
    }

    /// Mark buffer as EOF.
    pub fn set_eof(mut self) -> Self {
        self.eof = true;
        self
    }

    /// Finalize buffer and returns how many bytes have been consumed.
    pub fn finalize(self) -> usize {
        self.consumed
    }

    fn consume_all(&mut self) -> usize {
        let n = self.buf.len();
        self.buf = &[];
        self.consumed += n;
        n
    }
}

impl Read for Buffer<'_> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let n = buf.len().min(self.buf.len());
        match n {
            0 if !self.eof => return Err(ErrorKind::WouldBlock.into()),
            0 => (),
            1 => {
                buf[0] = self.buf[0];
                self.buf = &self.buf[1..];
            }
            n => {
                let src;
                (src, self.buf) = self.buf.split_at(n);
                buf[..n].copy_from_slice(src);
            }
        }

        self.consumed += n;
        Ok(n)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        let mut is_empty = true;
        let mut r = 0;
        for buf in bufs {
            if buf.is_empty() {
                continue;
            }
            is_empty = false;

            let n = buf.len().min(self.buf.len());
            match n {
                0 => break,
                1 => {
                    buf[0] = self.buf[0];
                    self.buf = &self.buf[1..];
                }
                n => {
                    let src;
                    (src, self.buf) = self.buf.split_at(n);
                    buf[..n].copy_from_slice(src);
                }
            }

            self.consumed += n;
            r += n;
        }

        if !is_empty && r == 0 && !self.eof {
            return Err(ErrorKind::WouldBlock.into());
        }
        Ok(r)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> IoResult<usize> {
        buf.extend_from_slice(self.buf);
        let n = self.consume_all();
        if !self.eof {
            return Err(ErrorKind::WouldBlock.into());
        }
        Ok(n)
    }

    fn read_to_string(&mut self, buf: &mut String) -> IoResult<usize> {
        let Ok(s) = std::str::from_utf8(self.buf) else {
            self.consume_all();
            return Err(IoError::new(
                ErrorKind::InvalidData,
                errors::StreamUtf8Error,
            ));
        };
        buf.push_str(s);
        let n = self.consume_all();
        if !self.eof {
            return Err(ErrorKind::WouldBlock.into());
        }
        Ok(n)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> IoResult<()> {
        if buf.is_empty() {
            return Ok(());
        } else if self.buf.len() < buf.len() {
            return Err(if self.buf.is_empty() && !self.eof {
                ErrorKind::WouldBlock
            } else {
                self.consume_all();
                ErrorKind::UnexpectedEof
            }
            .into());
        } else if buf.len() == 1 {
            buf[0] = self.buf[0];
            self.consumed += 1;
            return Ok(());
        }

        let b;
        (b, self.buf) = self.buf.split_at(buf.len());
        buf.copy_from_slice(b);
        self.consumed += buf.len();
        Ok(())
    }
}

/// Helper for write buffers.
///
/// Useful for sans-io writer.
///
/// # [`Write`] Behavior
///
/// [`Buffer`] acts like a non-blocking writer.
/// When trying to write past it's end and it's not EOF, it will return [`ErrorKind::WouldBlock`] error.
pub struct BufferWrite<'a> {
    buf: &'a mut Vec<u8>,
    consumed: usize,
    cap: usize,
    eof: bool,
}

impl<'a> BufferWrite<'a> {
    /// Create new `BufferWrite`.
    pub fn new(buf: &'a mut Vec<u8>, cap: usize) -> Self {
        Self {
            buf,
            cap,
            consumed: 0,
            eof: false,
        }
    }

    /// Mark buffer as EOF.
    pub fn set_eof(mut self) -> Self {
        self.eof = true;
        self
    }

    /// Finalize buffer and returns how many bytes have been consumed.
    pub fn finalize(self) -> usize {
        self.consumed
    }
}

impl Write for BufferWrite<'_> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let l = self.cap - self.consumed;
        Ok(if l == 0 {
            if !self.eof {
                return Err(ErrorKind::WouldBlock.into());
            }
            0
        } else if buf.len() > l {
            self.buf.extend_from_slice(&buf[..l]);
            self.consumed = self.cap;
            l
        } else {
            self.buf.extend_from_slice(buf);
            self.consumed += buf.len();
            buf.len()
        })
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        let mut is_empty = true;
        let mut r = 0;
        for b in bufs {
            if b.is_empty() {
                continue;
            }
            is_empty = false;

            let l = self.cap - self.consumed;
            r += if l == 0 {
                0
            } else if b.len() > l {
                self.buf.extend_from_slice(&b[..l]);
                self.consumed = self.cap;
                l
            } else {
                self.buf.extend_from_slice(b);
                self.consumed += b.len();
                b.len()
            };
        }

        if !is_empty && r == 0 && !self.eof {
            return Err(ErrorKind::WouldBlock.into());
        }
        Ok(r)
    }

    fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let l = self.cap - self.consumed;
        if buf.len() > l {
            self.buf.extend_from_slice(&buf[..l]);
            self.consumed = self.cap;
            return Err(if !self.eof {
                ErrorKind::WouldBlock
            } else {
                ErrorKind::UnexpectedEof
            }
            .into());
        }

        self.buf.extend_from_slice(buf);
        self.consumed += buf.len();
        Ok(())
    }
}

/// FIFO buffer with scan pop capability.
///
/// Useful for input cell buffer, where cells are send in-order
/// with the ability to "skip" blocking channels.
///
/// Values are stored in no-alloc linked-list.
/// This limits the maximum number of elements to 64.
pub struct InBuffer<T> {
    buffer: [Option<T>; 64],
    index: [(u8, u8); 64],
    head: u8,
    tail: u8,
    free: u8,
}

impl<T> Default for InBuffer<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> InBuffer<T> {
    /// Create new empty [`InBuffer`].
    pub const fn new() -> Self {
        // Keep it compact
        #[rustfmt::skip]
        const INDEX: [(u8, u8); 64] = [
            (1, 64), (2, 64), (3, 64), (4, 64), (5, 64), (6, 64), (7, 64), (8, 64),
            (9, 64), (10, 64), (11, 64), (12, 64), (13, 64), (14, 64), (15, 64), (16, 64),
            (17, 64), (18, 64), (19, 64), (20, 64), (21, 64), (22, 64), (23, 64), (24, 64),
            (25, 64), (26, 64), (27, 64), (28, 64), (29, 64), (30, 64), (31, 64), (32, 64),
            (33, 64), (34, 64), (35, 64), (36, 64), (37, 64), (38, 64), (39, 64), (40, 64),
            (41, 64), (42, 64), (43, 64), (44, 64), (45, 64), (46, 64), (47, 64), (48, 64),
            (49, 64), (50, 64), (51, 64), (52, 64), (53, 64), (54, 64), (55, 64), (56, 64),
            (57, 64), (58, 64), (59, 64), (60, 64), (61, 64), (62, 64), (63, 64), (64, 64),
        ];

        Self {
            head: 64,
            tail: 64,
            free: 0,
            index: INDEX,
            buffer: [const { None }; 64],
        }
    }

    /// Check if buffer is full.
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.free == 64
    }

    /// Check if buffer is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.head == 64
    }

    /// Push value into buffer.
    ///
    /// # Panics
    ///
    /// Panics if buffer is full.
    pub fn push(&mut self, value: T) {
        debug_assert!(self.head <= 64);
        debug_assert!(self.tail <= 64);
        if self.free >= 64 {
            panic!("buffer is full");
        }

        let i = self.free;
        let ix = usize::from(i);
        debug_assert!(self.buffer[ix].is_none());
        self.buffer[ix] = Some(value);

        let t = self.tail;
        (self.free, self.tail, self.index[ix]) = (self.index[ix].0, i, (64, t));
        if t != 64 {
            debug_assert_ne!(self.head, 64);
            let tx = usize::from(t);
            debug_assert_eq!(self.index[tx].0, 64);
            self.index[tx].0 = i;
        } else {
            debug_assert_eq!(self.head, 64);
            self.head = i;
        }

        debug_assert!(self.head < 64);
        debug_assert!(self.tail < 64);
        debug_assert!(self.free <= 64);
    }

    /// Pop value from buffer.
    pub fn pop(&mut self) -> Option<T> {
        debug_assert!(self.head <= 64);
        debug_assert!(self.tail <= 64);
        debug_assert!(self.free <= 64);

        let i = self.head;
        let ix = usize::from(i);
        if i == 64 {
            return None;
        }
        debug_assert!(self.buffer[ix].is_some());
        let r = self.buffer[ix].take();

        (self.free, self.head, self.index[ix]) = (i, self.index[ix].0, (self.free, 64));
        debug_assert_ne!(self.tail, 64);
        *if self.head != 64 {
            &mut self.index[usize::from(self.head)].1
        } else {
            &mut self.tail
        } = 64;

        debug_assert!(self.head <= 64);
        debug_assert!(self.tail <= 64);
        debug_assert!(self.free < 64);

        r
    }

    /// Scans and optionally pop values.
    ///
    /// Closure can inspect and take value. When value is taken from reference, it will be treated as removed.
    ///
    /// Returns the number of elements removed.
    pub fn scan_pop<E>(
        &mut self,
        mut f: impl FnMut(&mut Option<T>) -> Result<(), E>,
    ) -> Result<usize, E> {
        debug_assert!(self.head <= 64);
        debug_assert!(self.tail <= 64);
        debug_assert!(self.free <= 64);

        let mut n = 0;
        let mut i = self.head;
        loop {
            if i == 64 {
                return Ok(n);
            }

            let ix = usize::from(i);
            let data = &mut self.buffer[ix];

            debug_assert!(data.is_some());
            let ret = f(data);

            if data.is_some() {
                ret?;
                break;
            }
            n += 1;
            (self.head, self.free, self.index[ix]) = (self.index[ix].0, i, (self.free, 64));
            debug_assert!(self.head <= 64);
            debug_assert!(self.free < 64);
            i = self.head;
            if i != 64 {
                self.index[usize::from(i)].1 = 64;
            } else {
                self.tail = 64;
            }

            ret?;
        }

        let mut j = self.index[usize::from(i)].0;
        debug_assert!(j <= 64);
        while j != 64 {
            let ix = usize::from(j);
            let data = &mut self.buffer[ix];

            debug_assert!(data.is_some());
            let ret = f(data);

            let k = self.index[ix].0;
            debug_assert!(k <= 64);
            if data.is_some() {
                (i, j) = (j, k);
            } else {
                n += 1;
                self.index[usize::from(i)].0 = k;
                (self.free, j, self.index[ix]) = (j, k, (self.free, 64));
                if j != 64 {
                    self.index[usize::from(j)].1 = i;
                } else {
                    self.tail = i;
                }
            }

            ret?;
        }

        Ok(n)
    }
}

impl<T: Cachable> InBuffer<T> {
    /// Clears and discards all cells.
    pub fn discard_all(&mut self, cache: &impl CellCache) {
        let Self { buffer, .. } = take(self);
        for v in buffer.into_iter().flatten() {
            cache.discard(v);
        }
    }
}

/// FIFO and LIFO buffer.
///
/// Data is stored as fixed-size deque with maximum size of 64.
pub struct OutBuffer<T> {
    buffer: [Option<T>; 64],
    head: u8,
    len: u8,
}

impl<T> Default for OutBuffer<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> OutBuffer<T> {
    /// Create new empty [`OutBuffer`].
    pub const fn new() -> Self {
        Self {
            buffer: [const { None }; 64],
            head: 0,
            len: 0,
        }
    }

    /// Check if buffer is full.
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.len == 64
    }

    /// Check if buffer is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Push an item into back of buffer.
    ///
    /// # Panics
    ///
    /// Panics if buffer is full.
    pub fn push_back(&mut self, value: T) {
        debug_assert!(self.head < 64);
        if self.len >= 64 {
            panic!("buffer is full");
        }

        self.head = (self.head + 1) % 64;
        self.len += 1;
        let ix = usize::from(self.head);
        debug_assert!(self.buffer[ix].is_none());
        self.buffer[ix] = Some(value);

        debug_assert!(self.head < 64);
        debug_assert!(self.len <= 64);
    }

    /// Push an item into front of buffer.
    ///
    /// # Panics
    ///
    /// Panics if buffer is full.
    pub fn push_front(&mut self, value: T) {
        debug_assert!(self.head < 64);
        assert!(self.len < 64);

        let ix = usize::from((self.head as i8 - self.len as i8).rem_euclid(64) as u8);
        debug_assert!(self.buffer[ix].is_none());
        self.buffer[ix] = Some(value);
        self.len += 1;

        debug_assert!(self.head < 64);
        debug_assert!(self.len <= 64);
    }

    /// Pop an item from front of buffer.
    pub fn pop_front(&mut self) -> Option<T> {
        assert!(self.head < 64);
        assert!(self.len <= 64);

        if self.len == 0 {
            return None;
        }
        let ix = usize::from((self.head as i8 - (self.len - 1) as i8).rem_euclid(64) as u8);
        let ret = self.buffer[ix].take();
        debug_assert!(ret.is_some());
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }

        debug_assert!(self.head < 64);
        debug_assert!(self.len < 64);

        ret
    }
}

impl<T: Cachable> OutBuffer<T> {
    /// Clears and discards all cells.
    pub fn discard_all(&mut self, cache: &impl CellCache) {
        let Self { buffer, .. } = take(self);
        for v in buffer.into_iter().flatten() {
            cache.discard(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::vec_deque::VecDeque;
    use std::sync::Arc;

    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::strategy::LazyJust;
    use proptest_state_machine::*;

    static EXAMPLE_DATA: &[u8] = b"Never gonna give you up";

    #[test]
    fn test_buffer_empty() {
        let mut buf = Buffer::new(&[]);

        assert_eq!(buf.read(&mut []).unwrap(), 0);
        assert_eq!(
            buf.read(&mut [0]).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );

        assert_eq!(buf.finalize(), 0);
    }

    #[test]
    fn test_buffer_empty_eof() {
        let mut buf = Buffer::new(&[]).set_eof();

        assert_eq!(buf.read(&mut []).unwrap(), 0);
        assert_eq!(buf.read(&mut [0]).unwrap(), 0);

        assert_eq!(buf.finalize(), 0);
    }

    #[test]
    fn test_buffer_read() {
        for i in 0..=EXAMPLE_DATA.len() * 2 {
            println!("Trying: {i}");
            let mut buf = Buffer::new(EXAMPLE_DATA);

            let n = i.min(EXAMPLE_DATA.len());
            let mut v = vec![0; i];
            assert_eq!(buf.read(&mut v).unwrap(), n);
            assert_eq!(&v[..n], &EXAMPLE_DATA[..n]);

            assert_eq!(buf.finalize(), n);
        }
    }

    #[test]
    fn test_buffer_read_exact() {
        for i in 0..=EXAMPLE_DATA.len() {
            println!("Trying: {i}");
            let mut buf = Buffer::new(EXAMPLE_DATA);

            let mut v = vec![0; i];
            buf.read_exact(&mut v).unwrap();
            assert_eq!(v, &EXAMPLE_DATA[..i]);

            assert_eq!(buf.finalize(), i);
        }
    }

    #[test]
    fn test_buffer_read_exact_fail() {
        for i in EXAMPLE_DATA.len() + 1..=EXAMPLE_DATA.len() * 2 {
            println!("Trying: {i}");
            let mut buf = Buffer::new(EXAMPLE_DATA);

            let mut v = vec![0; i];
            assert_eq!(
                buf.read_exact(&mut v).unwrap_err().kind(),
                ErrorKind::UnexpectedEof
            );

            assert_eq!(buf.finalize(), EXAMPLE_DATA.len());
        }
    }

    #[test]
    fn test_buffer_read_vec() {
        let mut buf = Buffer::new(EXAMPLE_DATA).set_eof();

        let mut v = Vec::new();
        assert_eq!(buf.read_to_end(&mut v).unwrap(), EXAMPLE_DATA.len());
        assert_eq!(v, EXAMPLE_DATA);

        assert_eq!(buf.finalize(), EXAMPLE_DATA.len());
    }

    #[test]
    fn test_buffer_read_string() {
        let mut buf = Buffer::new(EXAMPLE_DATA).set_eof();

        let mut s = String::new();
        assert_eq!(buf.read_to_string(&mut s).unwrap(), EXAMPLE_DATA.len());
        assert_eq!(s.as_bytes(), EXAMPLE_DATA);

        assert_eq!(buf.finalize(), EXAMPLE_DATA.len());
    }

    #[test]
    fn test_buffer_read_end_nonblock() {
        let mut buf = Buffer::new(EXAMPLE_DATA);

        assert_eq!(
            buf.read_to_end(&mut Vec::new()).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );

        assert_eq!(buf.finalize(), EXAMPLE_DATA.len());
    }

    #[derive(Debug, Clone)]
    enum SliceLikeOp {
        Nothing,
        Read(usize),
        ReadExact(usize),
        ReadVectored(Vec<usize>),
        ReadToEnd,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum LastResult {
        Nothing,
        Err(ErrorKind),
        Data(Vec<u8>),
        DataVector(Box<[Box<[u8]>]>),
    }

    #[derive(Debug, Clone)]
    struct SliceLike {
        data: Arc<[u8]>,
        index: usize,
        last_res: LastResult,
    }

    impl SliceLike {
        fn apply(&mut self, trans: &SliceLikeOp) {
            let mut s = &self.data[self.index..];

            self.last_res = match trans {
                SliceLikeOp::Nothing => LastResult::Nothing,
                SliceLikeOp::Read(n) => {
                    let mut v = vec![0; *n];
                    match s.read(&mut v) {
                        Err(e) => LastResult::Err(e.kind()),
                        Ok(n) => {
                            v.truncate(n);
                            LastResult::Data(v)
                        }
                    }
                }
                SliceLikeOp::ReadExact(n) => {
                    let mut v = vec![0; *n];
                    match s.read_exact(&mut v) {
                        Err(e) => LastResult::Err(e.kind()),
                        Ok(()) => LastResult::Data(v),
                    }
                }
                SliceLikeOp::ReadVectored(n) => {
                    let mut vecs = n
                        .iter()
                        .map(|n| vec![0; *n].into_boxed_slice())
                        .collect::<Vec<_>>()
                        .into_boxed_slice();
                    let r = {
                        let mut p = vecs
                            .iter_mut()
                            .map(|v| IoSliceMut::new(v))
                            .collect::<Vec<_>>();
                        s.read_vectored(&mut p)
                    };
                    match r {
                        Err(e) => LastResult::Err(e.kind()),
                        Ok(n) => {
                            let mut t = 0;
                            for v in &mut vecs {
                                let e = t + v.len();
                                if e > n {
                                    v[n.saturating_sub(t)..].fill(0);
                                }
                                t = e;
                            }
                            LastResult::DataVector(vecs)
                        }
                    }
                }
                SliceLikeOp::ReadToEnd => {
                    let mut v = Vec::new();
                    match s.read_to_end(&mut v) {
                        Err(e) => LastResult::Err(e.kind()),
                        Ok(n) => {
                            v.truncate(n);
                            LastResult::Data(v)
                        }
                    }
                }
            };

            self.index = self.data.len() - s.len();
        }
    }

    struct SliceLikeRef;

    impl ReferenceStateMachine for SliceLikeRef {
        type State = SliceLike;
        type Transition = SliceLikeOp;

        fn init_state() -> BoxedStrategy<Self::State> {
            vec(any::<u8>(), 0..=1024)
                .prop_map(|v| SliceLike {
                    data: v.into(),
                    index: 0,
                    last_res: LastResult::Nothing,
                })
                .boxed()
        }

        fn transitions(_: &Self::State) -> BoxedStrategy<Self::Transition> {
            prop_oneof![
                (0..256usize).prop_map(SliceLikeOp::Read),
                (0..256usize).prop_map(SliceLikeOp::ReadExact),
                vec(0..256usize, 0..=16).prop_map(SliceLikeOp::ReadVectored),
                Just(SliceLikeOp::ReadToEnd),
            ]
            .boxed()
        }

        fn apply(mut state: Self::State, trans: &Self::Transition) -> Self::State {
            state.apply(trans);
            state
        }
    }

    struct BufferSliceLike {
        data: Arc<[u8]>,
        index: usize,
        last_res: LastResult,
        eof: bool,
    }

    impl BufferSliceLike {
        fn apply(&mut self, trans: SliceLikeOp) {
            let mut buf = Buffer {
                buf: &self.data[self.index..],
                consumed: self.index,
                eof: self.eof,
            };

            self.last_res = match trans {
                SliceLikeOp::Nothing => LastResult::Nothing,
                SliceLikeOp::Read(n) => {
                    let mut v = vec![0; n];
                    match buf.read(&mut v) {
                        Err(e) => LastResult::Err(e.kind()),
                        Ok(n) => {
                            v.truncate(n);
                            LastResult::Data(v)
                        }
                    }
                }
                SliceLikeOp::ReadExact(n) => {
                    let mut v = vec![0; n];
                    match buf.read_exact(&mut v) {
                        Err(e) => LastResult::Err(e.kind()),
                        Ok(()) => LastResult::Data(v),
                    }
                }
                SliceLikeOp::ReadVectored(n) => {
                    let mut vecs = n
                        .into_iter()
                        .map(|n| vec![0; n].into_boxed_slice())
                        .collect::<Vec<_>>()
                        .into_boxed_slice();
                    let r = {
                        let mut p = vecs
                            .iter_mut()
                            .map(|v| IoSliceMut::new(v))
                            .collect::<Vec<_>>();
                        buf.read_vectored(&mut p)
                    };
                    match r {
                        Err(e) => LastResult::Err(e.kind()),
                        Ok(n) => {
                            let mut t = 0;
                            for v in &mut vecs {
                                let e = t + v.len();
                                if e > n {
                                    v[n.saturating_sub(t)..].fill(0);
                                }
                                t = e;
                            }
                            LastResult::DataVector(vecs)
                        }
                    }
                }
                SliceLikeOp::ReadToEnd => {
                    let mut v = Vec::new();
                    match buf.read_to_end(&mut v) {
                        Err(e) => LastResult::Err(e.kind()),
                        Ok(n) => {
                            v.truncate(n);
                            LastResult::Data(v)
                        }
                    }
                }
            };

            self.index = buf.finalize();
        }
    }

    struct BufferSliceLikeTest;

    impl StateMachineTest for BufferSliceLikeTest {
        type SystemUnderTest = BufferSliceLike;
        type Reference = SliceLikeRef;

        fn init_test(
            ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) -> Self::SystemUnderTest {
            BufferSliceLike {
                data: ref_state.data.clone(),
                index: 0,
                last_res: LastResult::Nothing,
                eof: true,
            }
        }

        fn apply(
            mut state: Self::SystemUnderTest,
            _: &<Self::Reference as ReferenceStateMachine>::State,
            trans: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            state.apply(trans);
            state
        }

        fn check_invariants(
            state: &Self::SystemUnderTest,
            ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) {
            assert_eq!(state.last_res, ref_state.last_res);
            assert_eq!(state.index, ref_state.index);
        }
    }

    struct SliceLikeNBRef(SliceLikeRef);

    impl ReferenceStateMachine for SliceLikeNBRef {
        type State = SliceLike;
        type Transition = SliceLikeOp;

        fn init_state() -> BoxedStrategy<Self::State> {
            SliceLikeRef::init_state()
        }

        fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
            let l = state.data.len() - state.index;
            match l {
                0 => prop_oneof![
                    Just(SliceLikeOp::Nothing),
                    Just(SliceLikeOp::Read(0)),
                    Just(SliceLikeOp::ReadExact(0)),
                    vec(Just(0), 0..=16).prop_map(SliceLikeOp::ReadVectored),
                ]
                .boxed(),
                1..=4 => prop_oneof![
                    (0..=l).prop_map(SliceLikeOp::Read),
                    (0..=l).prop_map(SliceLikeOp::ReadExact),
                    Just(SliceLikeOp::ReadVectored(Vec::new())),
                    (0..=l).prop_map(|a| SliceLikeOp::ReadVectored(vec![a])),
                ]
                .boxed(),
                _ => prop_oneof![
                    (0..=l).prop_map(SliceLikeOp::Read),
                    (0..=l).prop_map(SliceLikeOp::ReadExact),
                    Just(SliceLikeOp::ReadVectored(Vec::new())),
                    (0..=l).prop_map(|a| SliceLikeOp::ReadVectored(vec![a])),
                    std::array::from_fn::<_, 2, _>(|_| 0..=l / 2)
                        .prop_map(|v| SliceLikeOp::ReadVectored(Vec::from(v))),
                    std::array::from_fn::<_, 3, _>(|_| 0..=l / 3)
                        .prop_map(|v| SliceLikeOp::ReadVectored(Vec::from(v))),
                    std::array::from_fn::<_, 4, _>(|_| 0..=l / 4)
                        .prop_map(|v| SliceLikeOp::ReadVectored(Vec::from(v))),
                ]
                .boxed(),
            }
        }

        fn apply(state: Self::State, trans: &Self::Transition) -> Self::State {
            SliceLikeRef::apply(state, trans)
        }
    }

    struct BufferSliceLikeNBTest;

    impl StateMachineTest for BufferSliceLikeNBTest {
        type SystemUnderTest = BufferSliceLike;
        type Reference = SliceLikeNBRef;

        fn init_test(
            ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) -> Self::SystemUnderTest {
            BufferSliceLike {
                data: ref_state.data.clone(),
                index: 0,
                last_res: LastResult::Nothing,
                eof: false,
            }
        }

        fn apply(
            mut state: Self::SystemUnderTest,
            _: &<Self::Reference as ReferenceStateMachine>::State,
            trans: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            state.apply(trans);
            state
        }

        fn check_invariants(
            state: &Self::SystemUnderTest,
            ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) {
            assert_eq!(state.last_res, ref_state.last_res);
            assert_eq!(state.index, ref_state.index);
        }
    }

    #[derive(Debug, Clone)]
    struct RefBuffer {
        buf: VecDeque<u64>,
        i: u64,

        popped: Vec<u64>,
    }

    impl RefBuffer {
        fn new() -> Self {
            Self {
                i: 0,
                buf: VecDeque::with_capacity(64),

                popped: Vec::new(),
            }
        }

        fn is_full(&self) -> bool {
            self.buf.len() == 64
        }

        fn len(&self) -> usize {
            self.buf.len()
        }

        fn push(&mut self, n: u8) {
            self.popped.clear();

            for _ in 0..n {
                if self.is_full() {
                    break;
                }

                self.buf.push_back(self.i);
                self.i = self.i.wrapping_add(1);
            }
        }

        fn push_front(&mut self, n: u8) {
            self.popped.clear();

            for _ in 0..n {
                if self.is_full() {
                    break;
                }

                self.buf.push_front(self.i);
                self.i = self.i.wrapping_add(1);
            }
        }

        fn scan_pop(&mut self, v: &[bool; 64]) {
            self.popped.clear();

            let mut it = v.iter().copied();
            self.buf.retain(|&v| {
                if it.next().unwrap() {
                    self.popped.push(v);
                    false
                } else {
                    true
                }
            });
        }

        fn pop(&mut self, n: u8) {
            self.popped.clear();

            for _ in 0..n {
                let Some(v) = self.buf.pop_front() else { break };
                self.popped.push(v);
            }
        }
    }

    #[derive(Debug, Clone)]
    enum InBufferTrans {
        Push(u8),
        Pop(u8),
        ScanPop([bool; 64]),
    }

    struct RefInBuffer;

    impl ReferenceStateMachine for RefInBuffer {
        type State = RefBuffer;
        type Transition = InBufferTrans;

        fn init_state() -> BoxedStrategy<Self::State> {
            LazyJust::new(RefBuffer::new).boxed()
        }

        fn transitions(_: &Self::State) -> BoxedStrategy<Self::Transition> {
            prop_oneof![
                (1u8..=64).prop_map(InBufferTrans::Push),
                (1u8..=64).prop_map(InBufferTrans::Pop),
                any::<[bool; 64]>().prop_map(InBufferTrans::ScanPop),
            ]
            .boxed()
        }

        fn apply(mut state: Self::State, trans: &Self::Transition) -> Self::State {
            match *trans {
                InBufferTrans::Push(n) => state.push(n),
                InBufferTrans::Pop(n) => state.pop(n),
                InBufferTrans::ScanPop(ref v) => state.scan_pop(v),
            }

            state
        }
    }

    struct InBufferTest {
        buf: InBuffer<u64>,
        i: u64,
        popped: Vec<u64>,
    }

    impl StateMachineTest for InBufferTest {
        type SystemUnderTest = Self;
        type Reference = RefInBuffer;

        fn init_test(
            _: &<Self::Reference as ReferenceStateMachine>::State,
        ) -> Self::SystemUnderTest {
            InBufferTest {
                buf: InBuffer::new(),
                i: 0,
                popped: Vec::new(),
            }
        }

        fn apply(
            mut state: Self::SystemUnderTest,
            _: &<Self::Reference as ReferenceStateMachine>::State,
            trans: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            state.popped.clear();
            match trans {
                InBufferTrans::Push(n) => {
                    for _ in 0..n {
                        if state.buf.is_full() {
                            break;
                        }

                        state.buf.push(state.i);
                        state.i = state.i.wrapping_add(1);
                    }
                }
                InBufferTrans::Pop(n) => {
                    for _ in 0..n {
                        let Some(v) = state.buf.pop() else {
                            break;
                        };
                        state.popped.push(v);
                    }
                }
                InBufferTrans::ScanPop(v) => {
                    let mut it = v.into_iter();
                    state
                        .buf
                        .scan_pop(|v| {
                            if it.next().unwrap() {
                                state.popped.push(v.take().unwrap());
                            }
                            Ok::<(), ()>(())
                        })
                        .unwrap();
                }
            }

            state
        }

        fn check_invariants(
            state: &Self::SystemUnderTest,
            ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) {
            assert_eq!(state.popped, ref_state.popped);
            assert_eq!(state.i, ref_state.i);

            let mut flags = [false; 64];
            let mut i = state.buf.head;
            let mut p = 64;
            let mut n = 0;

            while i != 64 {
                let ix = usize::from(i);
                assert!(
                    !flags[ix],
                    "loopback at reference index {n} and bufer index {i}"
                );
                flags[ix] = true;

                assert_eq!(
                    state.buf.buffer[ix],
                    Some(ref_state.buf[n]),
                    "value mismatch at reference index {n} and bufer index {i}"
                );
                assert_eq!(
                    state.buf.index[ix].1, p,
                    "previous index mismatch at reference index {n} and bufer index {i}"
                );

                (p, i) = (i, state.buf.index[ix].0);
                n += 1;
            }

            assert_eq!(
                state.buf.tail, p,
                "tail mismatch at reference index {n} and bufer index {i}"
            );
        }
    }

    #[derive(Debug, Clone)]
    enum OutBufferTrans {
        PushBack(u8),
        PushFront(u8),
        Pop(u8),
    }

    struct RefOutBuffer;

    impl ReferenceStateMachine for RefOutBuffer {
        type State = RefBuffer;
        type Transition = OutBufferTrans;

        fn init_state() -> BoxedStrategy<Self::State> {
            LazyJust::new(RefBuffer::new).boxed()
        }

        fn transitions(_: &Self::State) -> BoxedStrategy<Self::Transition> {
            prop_oneof![
                (1u8..=64).prop_map(OutBufferTrans::PushBack),
                (1u8..=64).prop_map(OutBufferTrans::PushFront),
                (1u8..=64).prop_map(OutBufferTrans::Pop),
            ]
            .boxed()
        }

        fn apply(mut state: Self::State, trans: &Self::Transition) -> Self::State {
            match *trans {
                OutBufferTrans::PushBack(n) => state.push(n),
                OutBufferTrans::PushFront(n) => state.push_front(n),
                OutBufferTrans::Pop(n) => state.pop(n),
            }

            state
        }
    }

    struct OutBufferTest {
        buf: OutBuffer<u64>,
        i: u64,
        popped: Vec<u64>,
    }

    impl StateMachineTest for OutBufferTest {
        type SystemUnderTest = Self;
        type Reference = RefOutBuffer;

        fn init_test(
            _: &<Self::Reference as ReferenceStateMachine>::State,
        ) -> Self::SystemUnderTest {
            OutBufferTest {
                buf: OutBuffer::new(),
                i: 0,
                popped: Vec::new(),
            }
        }

        fn apply(
            mut state: Self::SystemUnderTest,
            _: &<Self::Reference as ReferenceStateMachine>::State,
            trans: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            state.popped.clear();
            match trans {
                OutBufferTrans::PushBack(n) => {
                    for _ in 0..n {
                        if state.buf.is_full() {
                            break;
                        }

                        state.buf.push_back(state.i);
                        state.i = state.i.wrapping_add(1);
                    }
                }
                OutBufferTrans::PushFront(n) => {
                    for _ in 0..n {
                        if state.buf.is_full() {
                            break;
                        }

                        state.buf.push_front(state.i);
                        state.i = state.i.wrapping_add(1);
                    }
                }
                OutBufferTrans::Pop(n) => {
                    for _ in 0..n {
                        let Some(v) = state.buf.pop_front() else {
                            break;
                        };
                        state.popped.push(v);
                    }
                }
            }

            state
        }

        fn check_invariants(
            state: &Self::SystemUnderTest,
            ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        ) {
            assert_eq!(state.popped, ref_state.popped);
            assert_eq!(state.i, ref_state.i);

            assert_eq!(state.buf.len as usize, ref_state.len());
            for i in 0..state.buf.len {
                let ix = usize::from((state.buf.head as i8 - i as i8).rem_euclid(64) as u8);
                assert_eq!(
                    state.buf.buffer[ix],
                    Some(ref_state.buf[ref_state.len() - 1 - i as usize]),
                    "value mismatch at index {i}"
                );
            }
        }
    }

    prop_state_machine! {
        #[test]
        fn test_buffer_sm_slicelike(sequential 1..32 => BufferSliceLikeTest);
        #[test]
        fn test_buffer_sm_slicelike_nb(sequential 1..32 => BufferSliceLikeNBTest);
        #[test]
        fn test_in_buffer(sequential 1..64 => InBufferTest);
        #[test]
        fn test_out_buffer(sequential 1..64 => OutBufferTest);
    }
}
