#![no_main]

use std::future::poll_fn;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;

use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libfuzzer_sys::fuzz_target;
use onioncloud_ll_channel::stream::{Stream, StreamDummyClient, transform_server_message};
use onioncloud_tart::rt::schedule::FuzzSchedule;
use onioncloud_tart::rt::{Executor, Runtime};
use onioncloud_tart::socket::emulation::{
    FuzzBidiSocketLimiter, FuzzBidiSocketLimiterShared, SocketLimiterWrapper,
};
use onioncloud_tart::socket::pipe::{Pipe, make_pipe};
use onioncloud_tart::socket::{OpenOpt, Socket as DynSocket, SocketHandler, SocketOpener};

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
    let (mut read, mut write) = Pipe::split(socket);
    let sr = shared.clone();
    let sw = shared;

    rt.spawn(async move {
        let mut buf = [0u8; 256];
        let mut ix = 0;
        loop {
            let n = read.read(&mut buf).await.unwrap();
            let exp = &sr.server_read[ix..];
            if exp.is_empty() {
                assert_eq!(n, 0);
                break;
            }

            assert_ne!(n, 0);
            assert_eq!(&buf[..n], &exp[..n]);
            ix += n;
        }
    });

    rt.spawn(async move {
        write.write_all(&sw.server_write).await.unwrap();
        write.close().await.unwrap();
    });
}

async fn client(rt: Runtime, shared: Arc<SharedData>) {
    let socket = rt
        .connect(&[SocketAddr::from((IPV4_ADDR, 80))])
        .await
        .unwrap();
    let mut socket = pin!(SocketLimiterWrapper::new(
        StreamDummyClient::new_uninit(socket).unwrap(),
        FuzzBidiSocketLimiterShared::new(ClientLimiterWrapper(shared.clone()))
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
    rt.spawn(client(rt.clone(), shared));

    executor.run();
});
