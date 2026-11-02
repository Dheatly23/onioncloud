#![no_main]

use std::future::poll_fn;
use std::io::{ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::{AsyncRead, AsyncWrite};
use libfuzzer_sys::fuzz_target;
use onioncloud_ll_channel::stream::{Stream, StreamDummyClient, transform_server_message};
use onioncloud_tart::rt::schedule::FuzzSchedule;
use onioncloud_tart::rt::{Executor, Runtime};
use onioncloud_tart::socket::emulation::{
    FuzzBidiSocketLimiter, FuzzBidiSocketLimiterShared, SocketLimiterWrapper,
};
use onioncloud_tart::socket::{OpenOpt, Socket as DynSocket, SocketHandler, SocketOpener};

struct SharedData {
    client_read: Vec<u8>,
    client_write: Vec<u8>,
    server_read: Vec<u8>,
    server_write: Vec<u8>,
}

struct Server {
    shared: Arc<SharedData>,
    read_ix: usize,
    write_ix: usize,
}

impl AsyncRead for Server {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let this = Pin::into_inner(self);
        let n = buf.len().min(this.shared.server_read.len() - this.read_ix);
        buf[..n].copy_from_slice(&this.shared.server_read[this.read_ix..this.read_ix + n]);
        this.read_ix += n;
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for Server {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let this = Pin::into_inner(self);
        let n = buf
            .len()
            .min(this.shared.server_write.len() - this.write_ix);
        assert_eq!(
            &buf[..n],
            &this.shared.server_write[this.write_ix..this.write_ix + n],
            "mismatch at index {}..{}",
            this.write_ix,
            this.write_ix + n
        );
        this.write_ix += n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn client(rt: Runtime, shared: Arc<SharedData>, limiter: FuzzBidiSocketLimiter) {
    let socket = rt
        .connect(&[SocketAddr::from((IPV4_ADDR, 80))])
        .await
        .unwrap();
    let mut socket = pin!(SocketLimiterWrapper::new(
        StreamDummyClient::new_uninit(socket).unwrap(),
        limiter
    ));

    let mut buf = vec![0; shared.client_read.len()];
    let mut read = 0;
    let mut write = 0;
    let mut closed = false;

    poll_fn(|cx| {
        let mut is_same_poll = false;
        loop {
            if let Poll::Ready(v) = socket
                .as_mut()
                .socket_pin_mut()
                .poll_inner(cx, is_same_poll)
            {
                v.unwrap();
                return Poll::Ready(());
            }
            is_same_poll = true;

            // Poll read
            if read < shared.client_read.len()
                && let Poll::Ready(v) = socket.as_mut().poll_read(cx, &mut buf[read..])
            {
                let n = v.unwrap();
                assert!(n != 0, "read 0 bytes");
                assert_eq!(
                    &buf[read..read + n],
                    &shared.client_read[read..read + n],
                    "index mismatch at range {read}..{}",
                    read + n
                );
                read += n;
            }

            // Poll write
            if !closed {
                if write < shared.client_write.len() {
                    if let Poll::Ready(v) = socket
                        .as_mut()
                        .poll_write(cx, &shared.client_write[write..])
                    {
                        let n = v.unwrap();
                        assert!(n != 0, "written 0 bytes");
                        write += n;
                    }
                } else if let Poll::Ready(v) = socket.as_mut().poll_close(cx) {
                    v.unwrap();
                    closed = true;
                }
            }

            if !socket.as_mut().socket_pin_mut().wants_poll() {
                if read == shared.client_read.len() && closed {
                    return Poll::Ready(());
                }
                return Poll::Pending;
            }
        }
    })
    .await;
}

const IPV4_ADDR: Ipv4Addr = Ipv4Addr::from_bits(0x00535299);
const IPV6_ADDR: Ipv6Addr = Ipv6Addr::from_bits(0x00518776_00522415_00535453_00437573);

struct Network {
    shared: Arc<SharedData>,
    limiter: Arc<FuzzBidiSocketLimiter>,
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

        let server = Box::pin(SocketLimiterWrapper::new(
            Server {
                shared: self.shared.clone(),
                read_ix: 0,
                write_ix: 0,
            },
            FuzzBidiSocketLimiterShared::new(self.limiter.clone()),
        )) as DynSocket;

        Box::pin(async move { Ok((a, server)) })
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
        server_read: transform_server_message(&read),
        server_write: transform_server_message(&write),
        client_read: read,
        client_write: write,
    });

    let network = Network {
        shared: shared.clone(),
        limiter: Arc::new(server_limiter),
    };

    let mut executor = Executor::builder()
        .with_schedule(schedule)
        .with_network(network)
        .build();

    {
        let rt = executor.runtime();
        rt.spawn(client(rt.clone(), shared, client_limiter));
    }

    executor.run();
});
