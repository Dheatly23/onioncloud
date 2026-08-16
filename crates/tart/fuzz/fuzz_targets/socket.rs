#![no_main]

use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::cell::{Cell, UnsafeCell};
use std::cmp::Ordering;
use std::future::poll_fn;
use std::io::{ErrorKind, IoSlice, IoSliceMut, Result as IoResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::pin::{Pin, pin};
use std::ptr::{NonNull, drop_in_place, write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering::*, fence};
use std::task::{Context, Poll, Waker, ready};

use futures_util::{AsyncRead, AsyncWrite};
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use onioncloud_tart::rt::schedule::FuzzSchedule;
use onioncloud_tart::rt::{Executor, Runtime, Socket};
use onioncloud_tart::socket::emulation::{
    FuzzBidiSocketLimiter, FuzzBidiSocketLimiterShared, SocketLimiterWrapper,
};
use onioncloud_tart::socket::{OpenOpt, Socket as DynSocket, SocketHandler, SocketOpener};

thread_local! {
    pub(crate) static NEW_CNT: Cell<usize> = Cell::new(0);
    pub(crate) static DROP_CNT: Cell<usize> = Cell::new(0);
}

fn reset() {
    NEW_CNT.set(0);
    DROP_CNT.set(0);
}

struct PingPongHalf {
    buf: [u8; 256],
    start: u8,
    end: u8,
    closed: bool,

    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    flush_waker: Option<Waker>,
}

impl Default for PingPongHalf {
    fn default() -> Self {
        Self {
            buf: [0; 256],
            start: 0,
            end: 0,
            closed: false,

            read_waker: None,
            write_waker: None,
            flush_waker: None,
        }
    }
}

fn register_waker(waker: &mut Option<Waker>, cx: &mut Context<'_>) {
    match waker {
        Some(w) => w.clone_from(cx.waker()),
        None => *waker = Some(cx.waker().clone()),
    }
}

impl PingPongHalf {
    fn read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<usize> {
        let n = match self.start.cmp(&self.end) {
            Ordering::Equal if self.closed => return Poll::Ready(0),
            Ordering::Equal => {
                register_waker(&mut self.read_waker, cx);
                return Poll::Pending;
            }
            Ordering::Less => {
                let l = usize::from(self.end - self.start).min(buf.len());
                buf[..l].copy_from_slice(&self.buf[self.start as usize..self.start as usize + l]);
                self.start += l as u8;
                l
            }
            Ordering::Greater => {
                let l1 = self.buf.len() - self.start as usize;
                if l1 >= buf.len() {
                    buf.copy_from_slice(
                        &self.buf[self.start as usize..self.start as usize + buf.len()],
                    );
                    self.start = self.start.wrapping_add(buf.len() as u8);
                    buf.len()
                } else {
                    let (a, b) = buf.split_at_mut(l1);
                    a.copy_from_slice(&self.buf[self.start as usize..]);
                    let l2 = usize::from(self.end).min(b.len());
                    b[..l2].copy_from_slice(&self.buf[..l2]);
                    self.start = l2 as u8;
                    l1 + l2
                }
            }
        };

        if n > 0 {
            if let Some(w) = self.write_waker.take() {
                w.wake();
            }
            if self.start == self.end
                && let Some(w) = self.flush_waker.take()
            {
                w.wake();
            }
        }

        Poll::Ready(n)
    }

    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<IoResult<usize>> {
        match self.read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(v) => Poll::Ready(Ok(v)),
        }
    }

    fn poll_read_vectored(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        let mut n = 0;
        for b in bufs {
            if b.len() == 0 {
                continue;
            }
            n += ready!(self.read(cx, b));
            if self.start == self.end {
                break;
            }
        }
        Poll::Ready(Ok(n))
    }

    fn write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<usize> {
        if self.end.wrapping_add(1) == self.start {
            register_waker(&mut self.write_waker, cx);
            return Poll::Pending;
        }

        let n = match self.start.cmp(&self.end) {
            Ordering::Equal => {
                let l = buf.len().min(self.buf.len() - 1);
                self.buf[..l].copy_from_slice(&buf[..l]);
                self.start = 0;
                self.end = l as u8;
                l
            }
            Ordering::Greater => {
                let l = usize::from(self.start - self.end - 1).min(buf.len());
                self.buf[self.end as usize..self.end as usize + l].copy_from_slice(&buf[..l]);
                self.end += l as u8;
                l
            }
            Ordering::Less if self.start == 0 => {
                let l = (self.buf.len() - self.end as usize - 1).min(buf.len());
                self.buf[self.end as usize..self.end as usize + l].copy_from_slice(&buf[..l]);
                self.end += l as u8;
                l
            }
            Ordering::Less => {
                let l1 = self.buf.len() - self.end as usize;
                if l1 > buf.len() {
                    self.buf[self.end as usize..self.end as usize + buf.len()].copy_from_slice(buf);
                    self.end += buf.len() as u8;
                    buf.len()
                } else {
                    let (a, b) = buf.split_at(l1);
                    self.buf[self.end as usize..].copy_from_slice(a);
                    let l2 = usize::from(self.start - 1).min(b.len());
                    self.buf[..l2].copy_from_slice(&b[..l2]);
                    self.end = l2 as u8;
                    l1 + l2
                }
            }
        };

        if n > 0 {
            if let Some(w) = self.read_waker.take() {
                w.wake();
            }
        }

        Poll::Ready(n)
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        if self.closed {
            return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
        }
        match self.write(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(v) => Poll::Ready(Ok(v)),
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        if self.closed {
            Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
        } else if self.end == self.start {
            Poll::Ready(Ok(()))
        } else {
            register_waker(&mut self.flush_waker, cx);
            Poll::Pending
        }
    }

    fn poll_close(&mut self, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.closed = true;
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
        Poll::Ready(Ok(()))
    }

    fn poll_write_vectored(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        if self.closed {
            return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
        }
        let mut n = 0;
        for b in bufs {
            if b.len() == 0 {
                continue;
            }
            n += ready!(self.write(cx, b));
            if self.end.wrapping_add(1) == self.start {
                break;
            }
        }
        Poll::Ready(Ok(n))
    }
}

#[derive(Default)]
struct PingPongInner {
    client_server: PingPongHalf,
    server_client: PingPongHalf,
}

struct PingPongOuter {
    lock: AtomicU8,
    inner: UnsafeCell<PingPongInner>,
}

const COUNT_FLAG: u8 = 2;

// SAFETY: PingPongOuter is send and sync.
unsafe impl Send for PingPongOuter {}
// SAFETY: PingPongOuter is send and sync.
unsafe impl Sync for PingPongOuter {}

impl PingPongOuter {
    fn new() -> NonNull<Self> {
        let layout: Layout = Layout::new::<Self>();
        // SAFETY: Layout is valid and never zero sized.
        let Some(ret) = NonNull::new(unsafe { alloc(layout) }.cast::<Self>()) else {
            handle_alloc_error(layout)
        };
        // SAFETY: Pointer points to uninitialized allocation.
        unsafe {
            write(
                ret.as_ptr(),
                Self {
                    lock: AtomicU8::new(COUNT_FLAG * 2),
                    inner: Default::default(),
                },
            );
        }

        NEW_CNT.with(|v| v.set(v.get() + 1));
        ret
    }

    unsafe fn dec(p: NonNull<Self>) {
        // SAFETY: Pointer points to valid allocation.
        let r = unsafe { p.as_ref().lock.fetch_sub(COUNT_FLAG, Release) };
        if r & !1 == COUNT_FLAG {
            fence(Acquire);

            let p = p.as_ptr();

            // SAFETY: Pointer points to valid allocation and we're about to drop it.
            unsafe {
                let layout = Layout::for_value(&*p);
                drop_in_place(p);
                dealloc(p.cast(), layout);
            }

            DROP_CNT.with(|v| v.set(v.get() + 1));
        }
    }

    fn lock(&self) -> Guard<'_> {
        if self.lock.fetch_or(1, Acquire) & 1 != 0 {
            panic!("acquiring ping pong twice");
        }

        Guard {
            lock: &self.lock,
            // SAFETY: We locked the value.
            inner: unsafe { &mut *self.inner.get() },
        }
    }
}

struct Guard<'a> {
    lock: &'a AtomicU8,
    inner: &'a mut PingPongInner,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.lock.fetch_and(!1, Release);
    }
}

impl Deref for Guard<'_> {
    type Target = PingPongInner;

    fn deref(&self) -> &PingPongInner {
        self.inner
    }
}

impl DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut PingPongInner {
        self.inner
    }
}

struct PingPong(NonNull<PingPongOuter>);

// SAFETY: PingPong is send and sync.
unsafe impl Send for PingPong {}
// SAFETY: PingPong is send and sync.
unsafe impl Sync for PingPong {}

impl Drop for PingPong {
    fn drop(&mut self) {
        // SAFETY: Pointer points to valid allocation.
        unsafe { PingPongOuter::dec(self.0) }
    }
}

impl Deref for PingPong {
    type Target = PingPongOuter;

    fn deref(&self) -> &PingPongOuter {
        // SAFETY: Pointer points to valid allocation.
        unsafe { self.0.as_ref() }
    }
}

struct ServerHalf(PingPong);

impl AsyncRead for ServerHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Pin::into_inner(self)
            .0
            .lock()
            .client_server
            .poll_read(cx, buf)
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        Pin::into_inner(self)
            .0
            .lock()
            .client_server
            .poll_read_vectored(cx, bufs)
    }
}

impl AsyncWrite for ServerHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        Pin::into_inner(self)
            .0
            .lock()
            .server_client
            .poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::into_inner(self).0.lock().server_client.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::into_inner(self).0.lock().server_client.poll_close(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        Pin::into_inner(self)
            .0
            .lock()
            .server_client
            .poll_write_vectored(cx, bufs)
    }
}

struct ClientHalf(PingPong);

impl AsyncRead for ClientHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        Pin::into_inner(self)
            .0
            .lock()
            .server_client
            .poll_read(cx, buf)
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        Pin::into_inner(self)
            .0
            .lock()
            .server_client
            .poll_read_vectored(cx, bufs)
    }
}

impl AsyncWrite for ClientHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        Pin::into_inner(self)
            .0
            .lock()
            .client_server
            .poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::into_inner(self).0.lock().client_server.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::into_inner(self).0.lock().client_server.poll_close(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        Pin::into_inner(self)
            .0
            .lock()
            .client_server
            .poll_write_vectored(cx, bufs)
    }
}

#[derive(Debug, Arbitrary, Clone)]
struct SharedData {
    client_data: Vec<u8>,
    server_data: Vec<u8>,
    client_limiter: FuzzBidiSocketLimiter,
    server_limiter: FuzzBidiSocketLimiter,
}

struct GlobalData {
    sockets: Vec<SharedData>,
}

async fn client_task(socket: Socket, shared: Arc<GlobalData>, ix: usize) {
    let shared = &shared.sockets[ix];
    let mut buf = vec![0; shared.server_data.len()];
    let mut socket = pin!(SocketLimiterWrapper::new(
        socket,
        FuzzBidiSocketLimiterShared::new(&shared.client_limiter)
    ));
    let mut read = 0;
    let mut write = 0;
    let mut closed = false;

    poll_fn(|cx| {
        let mut pending = false;

        // Poll read
        if read < shared.server_data.len() {
            if let Poll::Ready(v) = socket.as_mut().poll_read(cx, &mut buf[read..]) {
                let n = v.unwrap();
                assert!(n != 0, "read 0 bytes");
                assert_eq!(
                    &buf[read..read + n],
                    &shared.server_data[read..read + n],
                    "index mismatch at range {read}..{}",
                    read + n
                );
                read += n;
            } else {
                pending = true;
            }
        } else if let Poll::Ready(v) = socket.as_mut().poll_read(cx, &mut []) {
            assert_eq!(v.unwrap(), 0);
        } else {
            pending = true;
        }

        // Poll write
        if !closed {
            if write < shared.client_data.len() {
                if let Poll::Ready(v) = socket.as_mut().poll_write(cx, &shared.client_data[write..])
                {
                    let n = v.unwrap();
                    assert!(n != 0, "written 0 bytes");
                    write += n;
                } else {
                    pending = true;
                }
            } else if let Poll::Ready(v) = socket.as_mut().poll_close(cx) {
                v.unwrap();
                closed = true;
            } else {
                pending = true;
            }
        }

        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
}

async fn server_task(socket: ServerHalf, shared: Arc<GlobalData>, ix: usize) {
    let shared = &shared.sockets[ix];
    let mut buf = vec![0; shared.client_data.len()];
    let mut socket = pin!(SocketLimiterWrapper::new(
        socket,
        FuzzBidiSocketLimiterShared::new(&shared.server_limiter)
    ));
    let mut read = 0;
    let mut write = 0;
    let mut closed = false;

    poll_fn(|cx| {
        let mut pending = false;

        // Poll read
        if read < shared.client_data.len() {
            if let Poll::Ready(v) = socket.as_mut().poll_read(cx, &mut buf[read..]) {
                let n = v.unwrap();
                assert!(n != 0, "read 0 bytes");
                assert_eq!(
                    &buf[read..read + n],
                    &shared.client_data[read..read + n],
                    "index mismatch at range {read}..{}",
                    read + n
                );
                read += n;
            } else {
                pending = true;
            }
        } else if let Poll::Ready(v) = socket.as_mut().poll_read(cx, &mut []) {
            assert_eq!(v.unwrap(), 0);
        } else {
            pending = true;
        }

        // Poll write
        if !closed {
            if write < shared.server_data.len() {
                if let Poll::Ready(v) = socket.as_mut().poll_write(cx, &shared.server_data[write..])
                {
                    let n = v.unwrap();
                    assert!(n != 0, "written 0 bytes");
                    write += n;
                } else {
                    pending = true;
                }
            } else if let Poll::Ready(v) = socket.as_mut().poll_close(cx) {
                v.unwrap();
                closed = true;
            } else {
                pending = true;
            }
        }

        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
}

const IPV4_ADDR: Ipv4Addr = Ipv4Addr::from_bits(0x00535299);
const IPV6_ADDR: Ipv6Addr = Ipv6Addr::from_bits(0x00518776_00522415_00535453_00437573);

struct Network {
    shared: Arc<GlobalData>,
}

impl SocketHandler for Network {
    fn open(&mut self, args: OpenOpt<'_>) -> SocketOpener {
        let rt = args.rt.clone();
        let l = self.shared.sockets.len();
        let Some((ix, &a)) = args
            .addrs
            .iter()
            .flat_map(|a| {
                let i = match a {
                    SocketAddr::V4(a) => *a.ip() == IPV4_ADDR,
                    SocketAddr::V6(a) => *a.ip() == IPV6_ADDR,
                };
                if !i {
                    return None;
                }

                let ix = a.port() as usize;
                (ix < l).then_some((ix, a))
            })
            .next()
        else {
            return Box::pin(async { Err(ErrorKind::HostUnreachable.into()) });
        };

        let outer = PingPongOuter::new();
        let server = ServerHalf(PingPong(outer));
        let client = ClientHalf(PingPong(outer));
        let shared = self.shared.clone();

        Box::pin(async move {
            rt.spawn(server_task(server, shared.clone(), ix));

            Ok((a, Box::pin(client) as DynSocket))
        })
    }
}

type ClientConnectorData = (usize, bool, Vec<(IpAddr, u16)>);

async fn client(rt: Runtime, shared: Arc<GlobalData>, (ix, addr_ty, other): ClientConnectorData) {
    let mut addrs = other.into_iter().map(SocketAddr::from).collect::<Vec<_>>();
    if addrs.len() > 0 {
        let ip = if addr_ty {
            IpAddr::from(IPV4_ADDR)
        } else {
            IpAddr::from(IPV6_ADDR)
        };
        let ix = ix % addrs.len();
        addrs[ix].set_ip(ip);
    }

    let r = rt.connect(&addrs).await;

    let l = shared.sockets.len();
    let Some((ix, addr)) = addrs
        .into_iter()
        .flat_map(|a| {
            let i = match &a {
                SocketAddr::V4(a) => *a.ip() == IPV4_ADDR,
                SocketAddr::V6(a) => *a.ip() == IPV6_ADDR,
            };
            if !i {
                return None;
            }

            let ix = a.port() as usize;
            (ix < l).then_some((ix, a))
        })
        .next()
    else {
        assert_eq!(r.unwrap_err().kind(), ErrorKind::HostUnreachable);
        return;
    };

    let client = r.unwrap();
    assert_eq!(client.addr(), addr);

    client_task(client, shared, ix).await;
}

type Data = (Vec<SharedData>, Vec<ClientConnectorData>, FuzzSchedule);

fuzz_target!(|data: Data| {
    reset();

    let (sockets, connect, schedule) = data;
    let shared = Arc::new(GlobalData { sockets });
    let network = Network {
        shared: shared.clone(),
    };
    let mut executor = Executor::builder()
        .with_schedule(schedule)
        .with_network(network)
        .build();

    let rt = executor.runtime();
    for data in connect {
        rt.spawn(client(rt.clone(), shared.clone(), data));
    }
    drop((rt, shared));

    executor.run();

    assert_eq!(
        NEW_CNT.get(),
        DROP_CNT.get(),
        "item creation and drop is not equal"
    );
});
