//! Network Socket Emulation.
//!
//! Contains wrapper types for emulating and fuzzing network socket.

use std::io::{IoSlice, IoSliceMut, Read, Result as IoResult, Write};
use std::mem::replace;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::ptr::{null_mut, slice_from_raw_parts_mut};
use std::task::{Context, Poll};

use arbitrary::{Arbitrary, MaxRecursionReached, Result as ArbResult, Unstructured};
use futures_io::{AsyncRead, AsyncWrite};
use pin_project::pin_project;
use tracing::instrument;

use crate::utils::RevVec;

/// Trait for socket limiter entropy generation.
///
/// Returned limit must be [`usize::MAX`] if it ran out of entropy bytes.
/// This allows for read/write operation to be unlimited.
pub trait SocketLimiterEntropy {
    /// Take read limit.
    fn take_read_limit(&mut self) -> NonZeroUsize;
    /// Take write limit.
    fn take_write_limit(&mut self) -> NonZeroUsize;
}

/// Socket limiter wrapper.
///
/// Wraps a [`AsyncRead`] + [`AsyncWrite`] socket and adds fuzzing ability.
/// It emulates buffer limitation, which can discover new bugs.
///
/// It also wraps [`Read`] + [`Write`] socket for sync operation.
#[pin_project(project = SocketLimiterWrapperProj)]
#[derive(Clone, Debug)]
#[must_use]
pub struct SocketLimiterWrapper<S, R> {
    #[pin]
    socket: S,
    entropy: R,

    read_limit: Option<NonZeroUsize>,
    write_limit: Option<NonZeroUsize>,

    with_read_vectored: bool,
    with_write_vectored: bool,
}

impl<S, R> SocketLimiterWrapper<S, R> {
    /// Create new [`SocketLimiterWrapper`].
    pub fn new(socket: S, entropy: R) -> Self {
        Self {
            socket,
            entropy,

            read_limit: None,
            write_limit: None,

            with_read_vectored: false,
            with_write_vectored: false,
        }
    }

    /// Enables `read_vectored` emulation.
    ///
    /// By default, [`AsyncRead::poll_read_vectored`] and [`Read::read_vectored`] are reduced to ordinary [`AsyncRead::poll_read`] and [`Read::read`].
    /// Setting this flag allows for limiting vectored reads.
    #[inline(always)]
    pub fn with_read_vectored(mut self, value: bool) -> Self {
        self.with_read_vectored = value;
        self
    }

    /// Enables `write_vectored` emulation.
    ///
    /// By default, [`AsyncWrite::poll_write_vectored`] and [`Write::write_vectored`] are reduced to ordinary [`AsyncWrite::poll_write`] and [`Write::write`].
    /// Setting this flag allows for limiting vectored writes.
    #[inline(always)]
    pub fn with_write_vectored(mut self, value: bool) -> Self {
        self.with_write_vectored = value;
        self
    }

    /// Gets mutable reference to inner socket.
    #[inline(always)]
    pub fn socket_mut(&mut self) -> &mut S {
        &mut self.socket
    }

    /// Gets pinned mutable reference to inner socket.
    #[inline(always)]
    pub fn socket_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        self.project().socket
    }

    /// Gets reference to entropy generator.
    #[inline(always)]
    pub fn entropy_ref(&self) -> &R {
        &self.entropy
    }

    /// Gets mutable reference to entropy generator.
    #[inline(always)]
    pub fn entropy_mut_unpin(&mut self) -> &mut R {
        &mut self.entropy
    }

    /// Gets mutable reference to entropy generator.
    #[inline(always)]
    pub fn entropy_mut(self: Pin<&mut Self>) -> &mut R {
        self.project().entropy
    }
}

struct IoSliceMutGuard<'a, 'b>(&'a mut [IoSliceMut<'b>], *mut [u8]);

impl Drop for IoSliceMutGuard<'_, '_> {
    fn drop(&mut self) {
        let [.., a] = self.0 else { return };
        if self.1.is_null() {
            return;
        }
        // SAFETY: Pointer is the old value of last item in slice.
        unsafe { *a = IoSliceMut::new(&mut *self.1) }
    }
}

impl<S: AsyncRead, R: SocketLimiterEntropy> AsyncRead for SocketLimiterWrapper<S, R> {
    #[instrument(level = "debug", skip_all)]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let SocketLimiterWrapperProj {
            socket,
            entropy,
            read_limit,
            ..
        } = self.project();

        if buf.is_empty() {
            return socket.poll_read(cx, buf);
        }

        let limit = buf
            .len()
            .min((*read_limit.get_or_insert_with(|| entropy.take_read_limit())).into());

        let ret = socket.poll_read(cx, &mut buf[..limit]);
        if ret.is_ready() {
            *read_limit = None;
        }
        ret
    }

    #[instrument(level = "debug", skip_all)]
    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        if !self.with_read_vectored {
            for b in bufs.iter_mut() {
                if !b.is_empty() {
                    return self.poll_read(cx, &mut *b);
                }
            }

            return self.poll_read(cx, bufs.last_mut().map_or(&mut [], |v| &mut **v));
        }

        let SocketLimiterWrapperProj {
            socket,
            entropy,
            read_limit,
            ..
        } = self.project();

        let len = bufs.iter().map(|t| t.len()).sum::<usize>();
        if len == 0 {
            return socket.poll_read_vectored(cx, bufs);
        }

        let mut limit =
            len.min((*read_limit.get_or_insert_with(|| entropy.take_read_limit())).into());
        let mut i = 0;
        while let Some(t) = bufs.get(i)
            && let Some(l @ 1..) = limit.checked_sub(t.len())
        {
            i += 1;
            limit = l;
        }

        let ret = if i == bufs.len() {
            socket.poll_read_vectored(cx, bufs)
        } else {
            let bufs = &mut bufs[..i + 1];
            let p;
            if let Some(t) = bufs.last_mut() {
                let mut u = replace(t, IoSliceMut::new(&mut []));
                p = (&mut *u) as *mut [u8];
                // SAFETY: Pointer is the old value of item.
                // Otherwise transmute of lifetime is in order, which is blasphemy of the highest degree.
                *t = IoSliceMut::new(unsafe { &mut (&mut *p)[..limit] });
            } else {
                p = slice_from_raw_parts_mut(null_mut(), 0);
            }
            let guard = IoSliceMutGuard(bufs, p);

            socket.poll_read_vectored(cx, &mut *guard.0)
        };
        if ret.is_ready() {
            *read_limit = None;
        }
        ret
    }
}

impl<S: AsyncWrite, R: SocketLimiterEntropy> AsyncWrite for SocketLimiterWrapper<S, R> {
    #[instrument(level = "debug", skip_all)]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let SocketLimiterWrapperProj {
            socket,
            entropy,
            write_limit,
            ..
        } = self.project();

        if buf.is_empty() {
            return socket.poll_write(cx, buf);
        }

        let limit = buf
            .len()
            .min((*write_limit.get_or_insert_with(|| entropy.take_write_limit())).into());

        let ret = socket.poll_write(cx, &buf[..limit]);
        if ret.is_ready() {
            *write_limit = None;
        }
        ret
    }

    #[instrument(level = "debug", skip_all)]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().socket.poll_flush(cx)
    }

    #[instrument(level = "debug", skip_all)]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().socket.poll_close(cx)
    }

    #[instrument(level = "debug", skip_all)]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        if !self.with_write_vectored {
            for b in bufs {
                if !b.is_empty() {
                    return self.poll_write(cx, b);
                }
            }

            return self.poll_write(cx, bufs.last().map_or(&[], |v| &**v));
        }

        let SocketLimiterWrapperProj {
            socket,
            entropy,
            write_limit,
            ..
        } = self.project();

        let len = bufs.iter().map(|t| t.len()).sum::<usize>();
        if len == 0 {
            return socket.poll_write_vectored(cx, bufs);
        }

        let mut limit =
            len.min((*write_limit.get_or_insert_with(|| entropy.take_write_limit())).into());
        let mut i = 0;
        while let Some(t) = bufs.get(i)
            && let Some(l @ 1..) = limit.checked_sub(t.len())
        {
            i += 1;
            limit = l;
        }

        let ret = if i == bufs.len() {
            socket.poll_write_vectored(cx, bufs)
        } else {
            let b = &bufs[..i + 1];
            if let [.., t] = b
                && t.len() == limit
            {
                socket.poll_write_vectored(cx, b)
            } else {
                let mut v = b.to_vec();
                if let ([.., a], [.., b]) = (&mut *v, b) {
                    *a = IoSlice::new(&b[..limit]);
                }

                socket.poll_write_vectored(cx, &v)
            }
        };
        if ret.is_ready() {
            *write_limit = None;
        }
        ret
    }
}

impl<S: Read, R: SocketLimiterEntropy> Read for SocketLimiterWrapper<S, R> {
    #[instrument(level = "debug", skip_all)]
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let Self {
            socket,
            entropy,
            read_limit,
            ..
        } = self;

        if buf.is_empty() {
            return socket.read(buf);
        }

        let limit = buf.len().min(
            read_limit
                .take()
                .unwrap_or_else(|| entropy.take_read_limit())
                .into(),
        );

        socket.read(&mut buf[..limit])
    }

    #[instrument(level = "debug", skip_all)]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        if !self.with_read_vectored {
            for b in bufs.iter_mut() {
                if !b.is_empty() {
                    return self.read(&mut *b);
                }
            }

            return self.read(bufs.last_mut().map_or(&mut [], |v| &mut **v));
        }

        let Self {
            socket,
            entropy,
            read_limit,
            ..
        } = self;

        let len = bufs.iter().map(|t| t.len()).sum::<usize>();
        if len == 0 {
            return socket.read_vectored(bufs);
        }

        let mut limit = len.min(
            read_limit
                .take()
                .unwrap_or_else(|| entropy.take_read_limit())
                .into(),
        );
        let mut i = 0;
        while let Some(t) = bufs.get(i)
            && let Some(l @ 1..) = limit.checked_sub(t.len())
        {
            i += 1;
            limit = l;
        }

        if i == bufs.len() {
            socket.read_vectored(bufs)
        } else {
            let bufs = &mut bufs[..i + 1];
            let p;
            if let Some(t) = bufs.last_mut() {
                let mut u = replace(t, IoSliceMut::new(&mut []));
                p = (&mut *u) as *mut [u8];
                // SAFETY: Pointer is the old value of item.
                // Otherwise transmute of lifetime is in order, which is blasphemy of the highest degree.
                *t = IoSliceMut::new(unsafe { &mut (&mut *p)[..limit] });
            } else {
                p = slice_from_raw_parts_mut(null_mut(), 0);
            }
            let guard = IoSliceMutGuard(bufs, p);

            socket.read_vectored(&mut *guard.0)
        }
    }
}

impl<S: Write, R: SocketLimiterEntropy> Write for SocketLimiterWrapper<S, R> {
    #[instrument(level = "debug", skip_all)]
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let Self {
            socket,
            entropy,
            write_limit,
            ..
        } = self;

        if buf.is_empty() {
            return socket.write(buf);
        }

        let limit = buf.len().min(
            write_limit
                .take()
                .unwrap_or_else(|| entropy.take_write_limit())
                .into(),
        );

        socket.write(&buf[..limit])
    }

    #[instrument(level = "debug", skip_all)]
    fn flush(&mut self) -> IoResult<()> {
        self.socket.flush()
    }

    #[instrument(level = "debug", skip_all)]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        if !self.with_write_vectored {
            for b in bufs {
                if !b.is_empty() {
                    return self.write(b);
                }
            }

            return self.write(bufs.last().map_or(&[], |v| &**v));
        }

        let Self {
            socket,
            entropy,
            write_limit,
            ..
        } = self;

        let len = bufs.iter().map(|t| t.len()).sum::<usize>();
        if len == 0 {
            return socket.write_vectored(bufs);
        }

        let mut limit = len.min(
            write_limit
                .take()
                .unwrap_or_else(|| entropy.take_write_limit())
                .into(),
        );
        let mut i = 0;
        while let Some(t) = bufs.get(i)
            && let Some(l @ 1..) = limit.checked_sub(t.len())
        {
            i += 1;
            limit = l;
        }

        if i == bufs.len() {
            socket.write_vectored(bufs)
        } else {
            let b = &bufs[..i + 1];
            if let [.., t] = b
                && t.len() == limit
            {
                socket.write_vectored(b)
            } else {
                let mut v = b.to_vec();
                if let ([.., a], [.., b]) = (&mut *v, b) {
                    *a = IoSlice::new(&b[..limit]);
                }

                socket.write_vectored(&v)
            }
        }
    }
}

/// Socket limiter with [`Arbitrary`] generation (unidirectional).
///
/// Useful for fuzzing by automatically generate limiter pattern.
///
/// **NOTE: Do not use it with bidirectional socket! Use [`FuzzBidiSocketLimiter`] instead.**
#[derive(Debug, Clone)]
pub struct FuzzSocketLimiter {
    inner: Vec<usize>,
    read: usize,
    write: usize,
}

impl AsRef<Self> for FuzzSocketLimiter {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<'a> Arbitrary<'a> for FuzzSocketLimiter {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            inner: Arbitrary::arbitrary(u)?,
            read: 0,
            write: 0,
        })
    }

    fn arbitrary_take_rest(u: Unstructured<'a>) -> ArbResult<Self> {
        Ok(Self {
            inner: Arbitrary::arbitrary_take_rest(u)?,
            read: 0,
            write: 0,
        })
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        <Vec<usize> as Arbitrary<'a>>::size_hint(depth)
    }

    fn try_size_hint(depth: usize) -> Result<(usize, Option<usize>), MaxRecursionReached> {
        <Vec<usize> as Arbitrary<'a>>::try_size_hint(depth)
    }
}

impl SocketLimiterEntropy for FuzzSocketLimiter {
    fn take_read_limit(&mut self) -> NonZeroUsize {
        if let Some(&r) = self.inner.get(self.read) {
            self.read += 1;
            zero_to_one(r)
        } else {
            NonZeroUsize::MAX
        }
    }

    fn take_write_limit(&mut self) -> NonZeroUsize {
        if let Some(&r) = self.inner.get(self.write) {
            self.write += 1;
            zero_to_one(r)
        } else {
            NonZeroUsize::MAX
        }
    }
}

/// Shared wrapper of [`FuzzSocketLimiter`].
///
/// Useful for reusing the same value for multiple connections (eg. server).
#[derive(Debug, Clone)]
pub struct FuzzSocketLimiterShared<Inner> {
    read: usize,
    write: usize,
    inner: Inner,
}

impl<Inner: AsRef<FuzzSocketLimiter>> FuzzSocketLimiterShared<Inner> {
    pub fn new(inner: Inner) -> Self {
        Self {
            inner,
            read: 0,
            write: 0,
        }
    }

    pub fn inner(&self) -> &Inner {
        &self.inner
    }
}

impl<Inner: AsRef<FuzzSocketLimiter>> SocketLimiterEntropy for FuzzSocketLimiterShared<Inner> {
    fn take_read_limit(&mut self) -> NonZeroUsize {
        if let Some(&r) = self.inner.as_ref().inner.get(self.read) {
            self.read += 1;
            zero_to_one(r)
        } else {
            NonZeroUsize::MAX
        }
    }

    fn take_write_limit(&mut self) -> NonZeroUsize {
        if let Some(&r) = self.inner.as_ref().inner.get(self.write) {
            self.write += 1;
            zero_to_one(r)
        } else {
            NonZeroUsize::MAX
        }
    }
}

/// Socket limiter with [`Arbitrary`] generation (bidirectional).
///
/// Useful for fuzzing by automatically generate limiter pattern.
///
/// NOTE: Use [`FuzzSocketLimiter`] for implementation optimized for unidirectional socket.
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzBidiSocketLimiter {
    read: RevVec<usize>,
    write: RevVec<usize>,
}

impl AsRef<Self> for FuzzBidiSocketLimiter {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl SocketLimiterEntropy for FuzzBidiSocketLimiter {
    fn take_read_limit(&mut self) -> NonZeroUsize {
        self.read.pop().map_or(NonZeroUsize::MAX, zero_to_one)
    }

    fn take_write_limit(&mut self) -> NonZeroUsize {
        self.write.pop().map_or(NonZeroUsize::MAX, zero_to_one)
    }
}

/// Shared wrapper of [`FuzzBidiSocketLimiter`].
///
/// Useful for sharing the same value for multiple connections (eg. server).
///
/// NOTE: Do not modify the inner [`FuzzBidiSocketLimiter`]. It will produce incorrect state.
#[derive(Debug, Clone)]
pub struct FuzzBidiSocketLimiterShared<Inner> {
    read: usize,
    write: usize,
    inner: Inner,
}

impl<Inner: AsRef<FuzzBidiSocketLimiter>> FuzzBidiSocketLimiterShared<Inner> {
    pub fn new(inner: Inner) -> Self {
        Self {
            inner,
            read: 0,
            write: 0,
        }
    }

    pub fn inner(&self) -> &Inner {
        &self.inner
    }
}

impl<Inner: AsRef<FuzzBidiSocketLimiter>> SocketLimiterEntropy
    for FuzzBidiSocketLimiterShared<Inner>
{
    fn take_read_limit(&mut self) -> NonZeroUsize {
        let p = &self.inner.as_ref().read;
        if let i @ 1.. = p.len().saturating_sub(self.read) {
            self.read += 1;
            zero_to_one(p[i - 1])
        } else {
            NonZeroUsize::MAX
        }
    }

    fn take_write_limit(&mut self) -> NonZeroUsize {
        let p = &self.inner.as_ref().write;
        if let i @ 1.. = p.len().saturating_sub(self.write) {
            self.write += 1;
            zero_to_one(p[i - 1])
        } else {
            NonZeroUsize::MAX
        }
    }
}

fn zero_to_one(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap_or(NonZeroUsize::MIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::pin::pin;

    use futures_util::{AsyncReadExt, AsyncWriteExt};
    use test_log::test;
    use tracing::info;

    use crate::rt::Executor;
    use crate::utils::run_test;

    struct OneLimit;

    impl SocketLimiterEntropy for OneLimit {
        fn take_read_limit(&mut self) -> NonZeroUsize {
            NonZeroUsize::new(1).unwrap()
        }

        fn take_write_limit(&mut self) -> NonZeroUsize {
            NonZeroUsize::new(1).unwrap()
        }
    }

    struct OnesSocket;

    impl AsyncRead for OnesSocket {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<IoResult<usize>> {
            buf.fill(1);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_read_vectored(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
        ) -> Poll<IoResult<usize>> {
            let mut len = 0;
            for b in bufs {
                b.fill(1);
                len += b.len();
            }
            Poll::Ready(Ok(len))
        }
    }

    impl AsyncWrite for OnesSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<IoResult<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<IoResult<usize>> {
            Poll::Ready(Ok(bufs.iter().map(|t| t.len()).sum::<usize>()))
        }
    }

    #[test]
    fn test_socket_read_limit() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();
            let rt = executor.runtime();

            rt.spawn(async {
                let mut socket =
                    pin!(SocketLimiterWrapper::new(OnesSocket, OneLimit).with_read_vectored(true));
                let mut buf = [0; 2];

                assert_eq!(socket.read(&mut buf).await.unwrap(), 1);
                assert_eq!(buf, [1, 0]);

                assert_eq!(socket.read(&mut []).await.unwrap(), 0);

                let mut buf2 = [0; 2];

                assert_eq!(
                    socket
                        .read_vectored(&mut [
                            IoSliceMut::new(&mut []),
                            IoSliceMut::new(&mut buf2),
                            IoSliceMut::new(&mut buf[1..])
                        ])
                        .await
                        .unwrap(),
                    1
                );
                assert_eq!(buf, [1, 0]);
                assert_eq!(buf2, [1, 0]);

                assert_eq!(
                    socket
                        .read_vectored(&mut [
                            IoSliceMut::new(&mut []),
                            IoSliceMut::new(&mut []),
                            IoSliceMut::new(&mut []),
                        ])
                        .await
                        .unwrap(),
                    0
                );
            });

            executor.run();
        }

        run_test(test);
    }

    #[test]
    fn test_socket_write_limit() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();
            let rt = executor.runtime();

            rt.spawn(async {
                let mut socket =
                    pin!(SocketLimiterWrapper::new(OnesSocket, OneLimit).with_write_vectored(true));

                assert_eq!(socket.write(&[0; 2]).await.unwrap(), 1);
                assert_eq!(socket.write(&[]).await.unwrap(), 0);
                assert_eq!(
                    socket
                        .write_vectored(&[
                            IoSlice::new(&[]),
                            IoSlice::new(&[0; 2]),
                            IoSlice::new(&[0; 1]),
                        ])
                        .await
                        .unwrap(),
                    1
                );
                assert_eq!(
                    socket
                        .write_vectored(&[IoSlice::new(&[]), IoSlice::new(&[]), IoSlice::new(&[]),])
                        .await
                        .unwrap(),
                    0
                );
            });

            executor.run();
        }

        run_test(test);
    }
}
