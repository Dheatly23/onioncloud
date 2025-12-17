mod buffer;
pub mod cell_map;
//pub mod channel;
//pub mod circuit;
pub mod sans_io;

use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::convert::{AsMut, AsRef};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::future::{Future, poll_fn};
use std::hash::{Hash, Hasher};
use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use std::mem::size_of;
use std::pin::Pin;
use std::task::Poll::*;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use base64ct::{Base64Url, Encoding};
use futures_core::future::FusedFuture;
use futures_core::ready;
use futures_io::{AsyncRead, AsyncWrite};
use pin_project::pin_project;
use scopeguard::guard_on_unwind;

use crate::cache::{Cachable, CellCache};
use crate::crypto::EdPublicKey;
use crate::runtime::{Runtime, Timer};
pub use buffer::*;

pub(crate) fn set_option_waker(waker: &mut Option<Waker>, cx: &mut Context<'_>) {
    match waker {
        Some(w) => w.clone_from(cx.waker()),
        w @ None => *w = Some(cx.waker().clone()),
    }
}

pub(crate) fn wrap_eof(v: IoResult<usize>) -> IoResult<usize> {
    match v {
        Ok(0) => Err(ErrorKind::UnexpectedEof.into()),
        v => v,
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

/// Future wrapper that can be polled infinitely.
///
/// Requires that return value is [`Copy`].
///
/// If underlying future has finished, polling it again will return the same result.
/// If underlying future has panicked, repolling will always panic.
///
/// To reset, just reassign it.
///
/// Also implements [`FusedFuture`] because it can always be polled, thus never terminates.
#[pin_project]
pub struct FutureRepollable<F: Future>(#[pin] FutureRepollableInner<F>);

#[pin_project(project = FutureRepollableInnerProj)]
pub(crate) enum FutureRepollableInner<F: Future> {
    Fut(#[pin] F),
    Res(F::Output),
    Panic,
}

/// Wraps future into [`FutureRepollable`].
impl<F: Future> From<F> for FutureRepollable<F> {
    fn from(fut: F) -> Self {
        Self::new(fut)
    }
}

impl<F: Future> FutureRepollable<F> {
    /// Create new [`FutureRepollable`].
    pub const fn new(fut: F) -> Self {
        Self(FutureRepollableInner::Fut(fut))
    }

    /// Check if future is finished.
    ///
    /// If future panicked, it will return `true` too.
    pub const fn is_finished(&self) -> bool {
        matches!(
            self.0,
            FutureRepollableInner::Res(_) | FutureRepollableInner::Panic
        )
    }
}

impl<F> Future for FutureRepollable<F>
where
    F: Future,
    F::Output: Copy,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = guard_on_unwind(self.project().0, |mut this| {
            this.set(FutureRepollableInner::Panic)
        });

        match this.as_mut().project() {
            FutureRepollableInnerProj::Fut(f) => {
                let r = ready!(f.poll(cx));
                this.set(FutureRepollableInner::Res(r));
                Ready(r)
            }
            FutureRepollableInnerProj::Res(r) => Ready(*r),
            FutureRepollableInnerProj::Panic => panic!("future has panicked before"),
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

/// Timer manager.
#[pin_project]
pub struct TimerManager<R: Runtime> {
    #[pin]
    timer: Option<R::Timer>,
    finished: bool,
}

impl<R: Runtime> Default for TimerManager<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Runtime> TimerManager<R> {
    /// Create new [`TimerManager`].
    pub const fn new() -> Self {
        Self {
            timer: None,
            finished: false,
        }
    }

    /// Returns `true` if timer wants to be polled.
    pub fn wants_poll(&self) -> bool {
        matches!(
            self,
            Self {
                timer: Some(_),
                finished: false
            }
        )
    }

    /// Set timer to fire at time.
    pub fn set(self: Pin<&mut Self>, runtime: &R, time: Instant) {
        let mut this = self.project();
        match this.timer.as_mut().as_pin_mut() {
            Some(timer) => timer.reset(time),
            None => this.timer.set(Some(runtime.timer(time))),
        }
        *this.finished = false;
    }

    /// Set timer to never fires.
    pub fn unset(self: Pin<&mut Self>) {
        *self.project().finished = true;
    }
}

impl<R: Runtime> Future for TimerManager<R> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.project();

        if !*this.finished
            && let Some(timer) = this.timer.as_pin_mut()
        {
            ready!(timer.poll(cx));
            *this.finished = true;
            Ready(())
        } else {
            Pending
        }
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
            write!(f, "{s}")
        }
    }

    let mut a = [0; LEN];
    let s = Base64Url::encode(key, &mut a).unwrap();
    assert_eq!(s.len(), LEN);
    S(a)
}

pub(crate) fn print_bytes(s: &[u8]) -> impl '_ + Display {
    struct S<'a>(&'a [u8]);

    impl Display for S<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            for &b in self.0 {
                Display::fmt(&char::from(b).escape_default(), f)?;
            }
            Ok(())
        }
    }

    S(s)
}

pub(crate) fn option_ord_min<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (v, None) | (None, v) => v,
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

pub(crate) const fn c_max_usize(a: usize, b: usize) -> usize {
    if a >= b { a } else { b }
}

/// Data type wrapping data with  generational reference.
pub struct GenerationalData<T: ?Sized> {
    /// Generation value.
    pub generation: u64,

    /// Wrapped value.
    pub inner: T,
}

impl<T: Clone> Clone for GenerationalData<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone(), self.generation)
    }

    fn clone_from(&mut self, src: &Self) {
        self.inner.clone_from(&src.inner);
        self.generation = src.generation;
    }
}

impl<T: Copy> Copy for GenerationalData<T> {}

impl<T: ?Sized + Hash> Hash for GenerationalData<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
        self.generation.hash(state);
    }
}

impl<R: ?Sized, T: ?Sized + PartialEq<R>> PartialEq<GenerationalData<R>> for GenerationalData<T> {
    fn eq(&self, rhs: &GenerationalData<R>) -> bool {
        self.inner.eq(&rhs.inner) && self.generation == rhs.generation
    }
}

impl<T: ?Sized + Eq> Eq for GenerationalData<T> {}

impl<R: ?Sized, T: ?Sized + PartialOrd<R>> PartialOrd<GenerationalData<R>> for GenerationalData<T> {
    fn partial_cmp(&self, rhs: &GenerationalData<R>) -> Option<Ordering> {
        self.inner
            .partial_cmp(&rhs.inner)
            .map(|v| v.then_with(|| self.generation.cmp(&rhs.generation)))
    }
}

impl<T: ?Sized + Ord> Ord for GenerationalData<T> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.inner
            .cmp(&rhs.inner)
            .then_with(|| self.generation.cmp(&rhs.generation))
    }
}

impl<T: ?Sized + Debug> Debug for GenerationalData<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("GenerationalData")
            .field("generation", &self.generation)
            .field("inner", &&self.inner)
            .finish()
    }
}

impl<T: ?Sized + Display> Display for GenerationalData<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} generation {:016x}", &self.inner, self.generation)
    }
}

impl<T: ?Sized> AsRef<T> for GenerationalData<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: ?Sized> AsMut<T> for GenerationalData<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Cachable> Cachable for GenerationalData<T> {
    fn cache<C: CellCache + ?Sized>(self, cache: &C) {
        self.inner.cache(cache);
    }
}

impl<T> GenerationalData<T> {
    /// Create new [`GenerationalData`].
    #[inline]
    pub const fn new(value: T, generation: u64) -> Self {
        Self {
            generation,
            inner: value,
        }
    }

    /// Unwraps into inner value.
    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: ?Sized> GenerationalData<T> {
    /// Gets generation value.
    #[inline(always)]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Sets generation value.
    #[inline(always)]
    pub const fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    /// Gets reference to inner.
    #[inline(always)]
    pub const fn as_ref(&self) -> &T {
        &self.inner
    }

    /// Gets mutable reference to inner.
    #[inline(always)]
    pub const fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Maps inner value.
    #[inline(always)]
    pub fn map<R>(self, f: impl FnOnce(T) -> R) -> GenerationalData<R>
    where
        T: Sized,
    {
        GenerationalData {
            generation: self.generation,
            inner: f(self.inner),
        }
    }
}

#[cfg(test)]
pub(crate) use tests::*;

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::cache::{CellCache, TestCache};
    use crate::cell::dispatch::{CellType, WithCellConfig};
    use crate::cell::{CellHeader, FixedCell};
    use crate::errors::InvalidCellHeader;

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

    pub(crate) fn test_write_helper<T, E, H>(
        data: &mut Vec<u8>,
        n: usize,
        steps: Vec<usize>,
        mut h: H,
    ) -> T
    where
        for<'a> H: sans_io::Handle<&'a mut dyn Write, Return = Result<T, E>>,
        E: Error + 'static,
    {
        for i in steps {
            match h.handle(&mut BufferWrite::new(
                data,
                n.saturating_sub(data.len()).min(i),
            )) {
                Ok(v) => return v,
                Err(e) if err_is_would_block(&e) => (),
                Err(e) => panic!("IO error: {e}"),
            }
        }

        h.handle(&mut BufferWrite::new(data, n.saturating_sub(data.len())).set_eof())
            .unwrap()
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
    fn test_encode_ed() {
        let v = EdPublicKey::default();
        println!("{}", print_ed(&v));
    }
}
