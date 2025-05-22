mod channel;
pub mod sans_io;

use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::future::{Future, poll_fn};
use std::io::{Error as IoError, ErrorKind, IoSliceMut, Read, Result as IoResult, Write};
use std::mem::size_of;
use std::pin::Pin;
use std::task::Poll::*;
use std::task::{Context, Poll};

use base64ct::{Base64Url, Encoding};
use futures_core::future::FusedFuture;
use futures_core::ready;
use futures_io::{AsyncRead, AsyncWrite};
use pin_project::pin_project;
use scopeguard::guard_on_unwind;

use crate::crypto::EdPublicKey;
use crate::errors;
pub use channel::*;

pub(crate) fn wrap_eof(v: IoResult<usize>) -> IoResult<usize> {
    match v {
        Ok(0) => Err(ErrorKind::UnexpectedEof.into()),
        v => v,
    }
}

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

/// Wrapper for [`AsyncRead`] into ordinary non-blocking [`Read`].
///
/// # How it works
///
/// If the reader returns [`Pending`], it will set it's pending flag to [`true`] and returns [`ErrorKind::WouldBlock`].
/// Then the outer [`async_reader`] can detect when the inner reader is pending and yields.
pub(crate) struct AsyncReadWrapper<'a, 'b> {
    cx: &'a mut Context<'b>,
    reader: Pin<&'a mut dyn AsyncRead>,
    pending: bool,
}

impl<'a, 'b> AsyncReadWrapper<'a, 'b> {
    pub(crate) fn new(cx: &'a mut Context<'b>, reader: Pin<&'a mut dyn AsyncRead>) -> Self {
        Self {
            cx,
            reader,
            pending: false,
        }
    }

    pub(crate) fn finish(self) -> bool {
        self.pending
    }
}

impl Read for AsyncReadWrapper<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if self.pending {
            // Immediately returns WouldBlock
            return Err(ErrorKind::WouldBlock.into());
        }

        match self.reader.as_mut().poll_read(self.cx, buf) {
            Ready(v) => v,
            Pending => {
                self.pending = true;
                Err(ErrorKind::WouldBlock.into())
            }
        }
    }
}

/// Wrapper for [`AsyncWrite`] into ordinary non-blocking [`Write`].
///
/// # How it works
///
/// If the writer returns [`Pending`], it will set it's pending flag to [`true`] and returns [`ErrorKind::WouldBlock`].
/// Then the outer [`async_writer`] can detect when the inner writer is pending and yields.
pub(crate) struct AsyncWriteWrapper<'a, 'b> {
    cx: &'a mut Context<'b>,
    writer: Pin<&'a mut dyn AsyncWrite>,
    pending: bool,
}

impl<'a, 'b> AsyncWriteWrapper<'a, 'b> {
    pub(crate) fn new(cx: &'a mut Context<'b>, writer: Pin<&'a mut dyn AsyncWrite>) -> Self {
        Self {
            cx,
            writer,
            pending: false,
        }
    }

    pub(crate) fn finish(self) -> bool {
        self.pending
    }
}

impl Write for AsyncWriteWrapper<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if self.pending {
            // Immediately returns WouldBlock
            return Err(ErrorKind::WouldBlock.into());
        }

        match self.writer.as_mut().poll_write(self.cx, buf) {
            Ready(v) => v,
            Pending => {
                self.pending = true;
                Err(ErrorKind::WouldBlock.into())
            }
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        if self.pending {
            // Immediately returns WouldBlock
            return Err(ErrorKind::WouldBlock.into());
        }

        match self.writer.as_mut().poll_flush(self.cx) {
            Ready(v) => v,
            Pending => {
                self.pending = true;
                Err(ErrorKind::WouldBlock.into())
            }
        }
    }
}

pub(crate) fn err_is_would_block(e: &(dyn Error + 'static)) -> bool {
    let mut p = Some(e);
    while let Some(e) = p {
        if let Some(e) = e.downcast_ref::<IoError>() {
            if e.kind() == ErrorKind::WouldBlock {
                return true;
            }
            break;
        }
        p = e.source();
    }

    false
}

/// Wraps an ordinary [`Read`] handling data into [`AsyncRead`].
pub async fn async_reader<R, E, H>(
    mut reader: Pin<&mut dyn AsyncRead>,
    mut handle: H,
) -> Result<R, E>
where
    for<'a> H: sans_io::Handle<&'a mut dyn Read, Return = Result<R, E>>,
    E: Error + 'static,
{
    poll_fn(|cx| {
        let mut s = AsyncReadWrapper {
            cx,
            reader: reader.as_mut(),
            pending: false,
        };

        match handle.handle(&mut s) {
            // Check if pending is true to ensure there isn't spurious WouldBlock.
            Err(e) if s.finish() && err_is_would_block(&e) => Pending,
            v => Ready(v),
        }
    })
    .await
}

/// Wraps an ordinary [`Write`] handling data into [`AsyncWrite`].
pub async fn async_writer<R, E, H>(
    mut writer: Pin<&mut dyn AsyncWrite>,
    mut handle: H,
) -> Result<R, E>
where
    for<'a> H: sans_io::Handle<&'a mut dyn Write, Return = Result<R, E>>,
    E: Error + 'static,
{
    poll_fn(|cx| {
        let mut s = AsyncWriteWrapper {
            cx,
            writer: writer.as_mut(),
            pending: false,
        };

        match handle.handle(&mut s) {
            // Check if pending is true to ensure there isn't spurious WouldBlock.
            Err(e) if s.finish() && err_is_would_block(&e) => Pending,
            v => Ready(v),
        }
    })
    .await
}

#[pin_project(project = FutureRepollableProj)]
pub(crate) enum FutureRepollable<F: Future> {
    Fut(#[pin] F),
    Res(F::Output),
    Panic,
}

impl<F: Future> From<F> for FutureRepollable<F> {
    fn from(fut: F) -> Self {
        Self::new(fut)
    }
}

impl<F: Future> FutureRepollable<F> {
    pub(crate) const fn new(fut: F) -> Self {
        Self::Fut(fut)
    }

    pub(crate) const fn is_finished(&self) -> bool {
        matches!(self, Self::Res(_) | Self::Panic)
    }
}

impl<F> Future for FutureRepollable<F>
where
    F: Future,
    F::Output: Copy,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = guard_on_unwind(self, |mut this| this.set(Self::Panic));

        match this.as_mut().project() {
            FutureRepollableProj::Fut(f) => {
                let r = ready!(f.poll(cx));
                this.set(Self::Res(r));
                Ready(r)
            }
            FutureRepollableProj::Res(r) => Ready(*r),
            FutureRepollableProj::Panic => panic!("future has panicked before"),
        }
    }
}

impl<F> FusedFuture for FutureRepollable<F>
where
    F: Future,
    F::Output: Copy,
{
    fn is_terminated(&self) -> bool {
        // Always can be polled
        false
    }
}

pub(crate) fn print_hex(s: &[u8]) -> impl '_ + Debug + Display {
    struct S<'a>(&'a [u8]);

    impl Debug for S<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            Display::fmt(self, f)
        }
    }

    impl Display for S<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            for &v in self.0 {
                write!(f, "{v:02X}")?;
            }
            Ok(())
        }
    }

    S(s)
}

pub(crate) fn print_list<T: Display>(s: &[T]) -> impl '_ + Debug + Display {
    struct S<'a, T>(&'a [T]);

    impl<T: Display> Debug for S<'_, T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            Display::fmt(self, f)
        }
    }

    impl<T: Display> Display for S<'_, T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            write!(f, "[")?;
            for (i, v) in self.0.iter().enumerate() {
                write!(f, "{}{v}", if i == 0 { "" } else { ", " })?;
            }
            write!(f, "]")
        }
    }

    S(s)
}

pub(crate) fn print_ed(key: &EdPublicKey) -> impl Debug + Display {
    // Calculate length based on base64ct encoded_len_inner
    const LEN: usize = const {
        let q = size_of::<EdPublicKey>() * 4;
        ((q / 3) + 3) & !3
    };

    struct S([u8; LEN]);

    impl Debug for S {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            Display::fmt(self, f)
        }
    }

    impl Display for S {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            // SAFETY: bytes are complete string
            let s = unsafe { str::from_utf8_unchecked(&self.0) };
            write!(f, "{}", s)
        }
    }

    let mut a = [0; LEN];
    let s = Base64Url::encode(key, &mut a).unwrap();
    assert_eq!(s.len(), LEN);
    S(a)
}

#[cfg(test)]
pub(crate) use tests::*;

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest_state_machine::*;

    use crate::cache::{CellCache, TestCache};
    use crate::cell::dispatch::{CellType, WithCellConfig};
    use crate::cell::{CellHeader, FixedCell};
    use crate::errors::InvalidCellHeader;

    static EXAMPLE_DATA: &[u8] = b"Never gonna give you up";

    pub(crate) fn test_read_helper<T, E, H>(data: &[u8], steps: Vec<usize>, mut h: H) -> T
    where
        for<'a> H: sans_io::Handle<&'a mut dyn Read, Return = Result<T, E>>,
        E: Error + 'static,
    {
        let mut it = steps.into_iter();
        let mut n = 0;
        while n < data.len() {
            let t = n
                .saturating_add(it.next().unwrap_or(usize::MAX))
                .min(data.len());
            let b = &data[n..t];
            let l = b.len();
            let mut buf = Buffer::new(b);
            match h.handle(&mut buf) {
                Ok(v) => return v,
                Err(e) if err_is_would_block(&e) => (),
                Err(e) => panic!("IO error: {e}"),
            }
            assert_eq!(buf.finalize(), l);
            n += l;
        }
        panic!("buffer finished but value isn't yet produced");
    }

    pub(crate) struct TestConfig {
        circ_4bytes: bool,
        pub(crate) cache: TestCache,
    }

    impl TestConfig {
        pub(crate) fn new(circ_4bytes: bool) -> Self {
            Self {
                circ_4bytes,
                cache: TestCache::new(),
            }
        }
    }

    impl WithCellConfig for TestConfig {
        fn is_circ_id_4bytes(&self) -> bool {
            self.circ_4bytes
        }

        fn cell_type(&self, header: &CellHeader) -> Result<CellType, InvalidCellHeader> {
            match header.command {
                8 | 128..=254 => Ok(CellType::Variable),
                0..128 => Ok(CellType::Fixed),
                _ => Err(InvalidCellHeader::with_header(header)),
            }
        }
    }

    impl CellCache for TestConfig {
        fn get_cached(&self) -> FixedCell {
            self.cache.get_cached()
        }

        fn cache_cell(&self, cell: FixedCell) {
            self.cache.cache_cell(cell);
        }
    }

    pub(crate) fn steps() -> impl Strategy<Value = Vec<usize>> {
        vec(0..=256usize, 0..32)
    }

    pub(crate) fn circ_id_strat() -> impl Strategy<Value = (bool, u32)> {
        any::<bool>().prop_flat_map(|v| (Just(v), 0..=if v { u32::MAX } else { u16::MAX.into() }))
    }

    pub(crate) fn var_cell_strat() -> impl Strategy<Value = Vec<u8>> {
        vec(any::<u8>(), 0..=1024)
    }

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

    #[test]
    fn test_encode_ed() {
        let v = EdPublicKey::default();
        println!("{}", print_ed(&v));
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

    prop_state_machine! {
        #[test]
        fn test_buffer_sm_slicelike(sequential 1..32 => BufferSliceLikeTest);
        #[test]
        fn test_buffer_sm_slicelike_nb(sequential 1..32 => BufferSliceLikeNBTest);
    }
}
