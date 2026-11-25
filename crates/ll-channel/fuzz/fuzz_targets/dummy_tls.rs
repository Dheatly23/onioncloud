#![no_main]

use std::io::{ErrorKind, Read, Result as IoResult, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::task::Poll::*;

use futures_util::{AsyncReadExt, AsyncWriteExt};
use libfuzzer_sys::fuzz_target;
use onioncloud_ll_channel::controller::open;
use onioncloud_ll_channel::error::ChannelError;
use onioncloud_ll_channel::handle::{ChannelHandle, Handle, Return};
use onioncloud_ll_channel::stream::{StreamDummyClient, transform_server_message};
use onioncloud_tart::rt::schedule::FuzzSchedule;
use onioncloud_tart::rt::{Executor, Runtime};
use onioncloud_tart::socket::emulation::{
    FuzzBidiSocketLimiter, FuzzBidiSocketLimiterShared, SocketLimiterWrapper,
};
use onioncloud_tart::socket::pipe::{Pipe, ReadHalf, WriteHalf, make_pipe};
use onioncloud_tart::socket::{OpenOpt, Socket as DynSocket, SocketHandler, SocketOpener};
use tracing::{instrument, trace};

struct SharedData {
    client_read: Vec<u8>,
    client_write: Vec<u8>,
    server_read: Vec<u8>,
    server_write: Vec<u8>,

    client_limiter: FuzzBidiSocketLimiter,
    server_limiter: FuzzBidiSocketLimiter,
}

struct ClientLimiterWrapper(Arc<SharedData>);

impl AsRef<FuzzBidiSocketLimiter> for ClientLimiterWrapper {
    fn as_ref(&self) -> &FuzzBidiSocketLimiter {
        &self.0.client_limiter
    }
}

struct ServerLimiterWrapper(Arc<SharedData>);

impl AsRef<FuzzBidiSocketLimiter> for ServerLimiterWrapper {
    fn as_ref(&self) -> &FuzzBidiSocketLimiter {
        &self.0.server_limiter
    }
}

fn server(rt: Runtime, shared: Arc<SharedData>, socket: Pipe) {
    let (read, write) = Pipe::split(socket);

    #[instrument(skip_all)]
    async fn server_read(shared: Arc<SharedData>, mut read: ReadHalf) {
        let mut buf = [0u8; 256];
        let mut ix = 0;
        loop {
            let n = read.read(&mut buf).await.unwrap();
            let exp = &shared.server_read[ix..];
            if exp.is_empty() {
                assert_eq!(n, 0);
                break;
            }

            assert_ne!(n, 0);
            assert_eq!(&buf[..n], &exp[..n]);
            ix += n;
        }
    }

    let s = shared.clone();
    rt.spawn(async move { server_read(s, read).await });

    #[instrument(skip_all)]
    async fn server_write(shared: Arc<SharedData>, mut write: WriteHalf) {
        write.write_all(&shared.server_write).await.unwrap();
        write.flush().await.unwrap();
        write.close().await.unwrap();
    }

    rt.spawn(async move { server_write(shared, write).await });
}

struct CHandle {
    shared: Arc<SharedData>,
    buf: Vec<u8>,
    read: usize,
    write: usize,
    limiter: FuzzBidiSocketLimiterShared<ClientLimiterWrapper>,
}

impl ChannelHandle<Runtime> for CHandle {
    type Error = ChannelError;

    #[instrument(skip_all)]
    fn handle(self: Pin<&mut Self>, mut args: Handle<Runtime>) -> Result<Return, Self::Error> {
        let this = Pin::into_inner(self);
        let mut socket = SocketLimiterWrapper::new(&mut args, &mut this.limiter);

        // Poll read
        while this.read < this.shared.client_read.len()
            && let Ready(v) = poll_io_unwrap(socket.read(&mut this.buf[this.read..]))
        {
            let n = v.unwrap();
            assert!(n != 0, "read 0 bytes");
            trace!("read {n} bytes");
            assert_eq!(
                &this.buf[this.read..this.read + n],
                &this.shared.client_read[this.read..this.read + n],
                "index mismatch at range {}..{}",
                this.read,
                this.read + n
            );
            this.read += n;
        }

        // Poll write
        while this.write < this.shared.client_write.len()
            && let Ready(v) = poll_io_unwrap(socket.write(&this.shared.client_write[this.write..]))
        {
            let n = v.unwrap();
            assert!(n != 0, "written 0 bytes");
            trace!("written {n} bytes");
            this.write += n;
        }

        if this.read >= this.shared.client_read.len()
            && this.write >= this.shared.client_write.len()
        {
            trace!("shutting down");
            return Ok(Return::new(&args).with_shutdown());
        }

        trace!("client pending");
        Ok(Return::new(&args))
    }
}

#[instrument(skip_all)]
async fn client(rt: Runtime, shared: Arc<SharedData>) {
    open(
        rt,
        &[SocketAddr::from((IPV4_ADDR, 80))],
        async move |socket| Ok(StreamDummyClient::new_uninit(socket).unwrap()),
        move || CHandle {
            buf: vec![0; shared.client_read.len()],
            read: 0,
            write: 0,
            limiter: FuzzBidiSocketLimiterShared::new(ClientLimiterWrapper(shared.clone())),
            shared,
        },
    )
    .await
    .unwrap()
    .await
    .unwrap();
}

const IPV4_ADDR: Ipv4Addr = Ipv4Addr::from_bits(0x00629496);
const IPV6_ADDR: Ipv6Addr = Ipv6Addr::from_bits(0x00650199_00564962_00505869_00529506);

struct Network {
    shared: Arc<SharedData>,
}

impl SocketHandler for Network {
    fn open(&mut self, args: OpenOpt<'_>) -> SocketOpener {
        let Some(&a) = args
            .addrs
            .iter()
            .filter(|a| match a {
                SocketAddr::V4(a) => *a.ip() == IPV4_ADDR,
                SocketAddr::V6(a) => *a.ip() == IPV6_ADDR,
            })
            .next()
        else {
            return Box::pin(async { Err(ErrorKind::HostUnreachable.into()) });
        };

        let rt = args.rt.clone();
        let shared = self.shared.clone();

        Box::pin(async move {
            let (c, s) = make_pipe(&rt);
            server(rt, shared.clone(), s);
            Ok((
                a,
                Box::pin(SocketLimiterWrapper::new(
                    c,
                    FuzzBidiSocketLimiterShared::new(ServerLimiterWrapper(shared)),
                )) as DynSocket,
            ))
        })
    }
}

type Data = (
    FuzzBidiSocketLimiter,
    FuzzBidiSocketLimiter,
    FuzzSchedule,
    Vec<u8>,
    Vec<u8>,
);

fuzz_target!(|data: Data| {
    let (client_limiter, server_limiter, schedule, read, write) = data;
    let shared = Arc::new(SharedData {
        server_read: transform_server_message(&write),
        server_write: transform_server_message(&read),
        client_read: read,
        client_write: write,

        client_limiter,
        server_limiter,
    });

    let network = Network {
        shared: shared.clone(),
    };

    let mut executor = Executor::builder()
        .with_schedule(schedule)
        .with_network(network)
        .build();

    let rt = executor.runtime();
    let rt_ = executor.runtime();
    rt_.spawn(async move { client(rt, shared).await });

    executor.run();
});

fn poll_io_unwrap<R>(v: IoResult<R>) -> Poll<IoResult<R>> {
    match v {
        Err(e) if e.kind() == ErrorKind::WouldBlock => Pending,
        v => Ready(v),
    }
}
