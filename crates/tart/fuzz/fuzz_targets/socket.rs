#![no_main]

use std::future::poll_fn;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;

use futures_util::{AsyncRead, AsyncWrite};
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use onioncloud_tart::rt::schedule::FuzzSchedule;
use onioncloud_tart::rt::{Executor, Runtime, Socket};
use onioncloud_tart::socket::emulation::{
    FuzzBidiSocketLimiter, FuzzBidiSocketLimiterShared, SocketLimiterWrapper,
};
use onioncloud_tart::socket::pipe::{Pipe, make_pipe};
use onioncloud_tart::socket::{OpenOpt, Socket as DynSocket, SocketHandler, SocketOpener};

#[derive(Debug, Arbitrary, Clone)]
struct SharedData {
    client_data: Vec<u8>,
    server_data: Vec<u8>,
    server_limiter: FuzzBidiSocketLimiter,
}

struct GlobalData {
    sockets: Vec<SharedData>,
}

async fn client_task(
    socket: Socket,
    shared: Arc<GlobalData>,
    ix: usize,
    limiter: FuzzBidiSocketLimiter,
) {
    let shared = &shared.sockets[ix];
    let mut buf = vec![0; shared.server_data.len()];
    let mut socket = pin!(SocketLimiterWrapper::new(socket, limiter));
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

async fn server_task(socket: Pipe, shared: Arc<GlobalData>, ix: usize) {
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

        let shared = self.shared.clone();

        Box::pin(async move {
            let (server, client) = make_pipe(&rt);
            rt.spawn(server_task(server, shared.clone(), ix));

            Ok((a, Box::pin(client) as DynSocket))
        })
    }
}

type ClientConnectorData = (usize, bool, u16, Vec<(IpAddr, u16)>, FuzzBidiSocketLimiter);

async fn client(
    rt: Runtime,
    shared: Arc<GlobalData>,
    (ix, addr_ty, mut port, other, limiter): ClientConnectorData,
) {
    let mut addrs = other.into_iter().map(SocketAddr::from).collect::<Vec<_>>();

    let l = shared.sockets.len();
    let ip = if addr_ty {
        IpAddr::from(IPV4_ADDR)
    } else {
        IpAddr::from(IPV6_ADDR)
    };
    if l > 0 {
        port %= u16::try_from(l).ok().unwrap_or(u16::MAX);
    }
    let socket = SocketAddr::from((ip, port));
    if addrs.len() > 0 {
        let ix = ix % addrs.len();
        addrs[ix] = socket;
    } else {
        addrs.push(socket);
    }

    let r = rt.connect(&addrs).await;

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

    client_task(client, shared, ix, limiter).await;
}

type Data = (Vec<SharedData>, Vec<ClientConnectorData>, FuzzSchedule);

fuzz_target!(|data: Data| {
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
});
