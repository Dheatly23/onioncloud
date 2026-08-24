#![no_main]

use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::{Cursor, ErrorKind, Read, Result as IoResult, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{AsyncRead, AsyncWrite};
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::CellHeader;
use onioncloud_ll_cell::error::{CellFinished, CellReadError};
use onioncloud_ll_cell::read::{CellType, ReadConfig, Reader};
use onioncloud_ll_cell::write::{WriteConfig, Writer};
use onioncloud_tart::rt::Executor;
use onioncloud_tart::rt::schedule::FuzzSchedule;
use onioncloud_tart::socket::emulation::{FuzzSocketLimiter, SocketLimiterWrapper};

#[derive(Debug, Arbitrary)]
struct ConfigData {
    map: [u8; 32],
    is_4bytes: Vec<u8>,
}

struct Config<'a> {
    data: &'a ConfigData,
    off: usize,
}

impl ReadConfig for Config<'_> {
    fn is_circ_id_4bytes(&self) -> bool {
        self.data
            .is_4bytes
            .get(self.off / 8)
            .copied()
            .unwrap_or_default()
            & (1 << (self.off % 8))
            == 0
    }

    fn cell_type(&self, header: &CellHeader) -> Option<CellType> {
        let ix = header.command as usize;
        Some(if self.data.map[ix / 8] & (1 << (ix % 8)) == 0 {
            CellType::Fixed
        } else {
            CellType::Variable
        })
    }
}

impl WriteConfig for Config<'_> {
    fn is_circ_id_4bytes(&self) -> bool {
        <Self as ReadConfig>::is_circ_id_4bytes(self)
    }
}

struct PendingWrapper<T> {
    mask: Vec<u8>,
    ix: usize,
    inner: T,
}

impl<T> Unpin for PendingWrapper<T> {}

impl<T> PendingWrapper<T> {
    fn take_pending(&mut self) -> bool {
        let ix = self.ix;
        self.ix = ix.saturating_add(1).min(self.mask.len() * 8);
        self.mask.get(ix / 8).copied().unwrap_or_default() & (1 << (ix % 8)) != 0
    }
}

impl<T: Read> AsyncRead for PendingWrapper<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let this = Pin::into_inner(self);
        if this.take_pending() {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(this.inner.read(buf))
        }
    }
}

impl<T: Write> AsyncWrite for PendingWrapper<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        let this = Pin::into_inner(self);
        if this.take_pending() {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(this.inner.write(buf))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = Pin::into_inner(self);
        if this.take_pending() {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(this.inner.flush())
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = Pin::into_inner(self);
        if this.take_pending() {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

struct AsyncWrapper<'a, 'b, T> {
    inner: Pin<&'a mut T>,
    cx: &'a mut Context<'b>,
}

fn pending_to_would_block<T>(v: Poll<IoResult<T>>) -> IoResult<T> {
    match v {
        Poll::Pending => Err(ErrorKind::WouldBlock.into()),
        Poll::Ready(v) => v,
    }
}

impl<'a, 'b, T: AsyncRead> Read for AsyncWrapper<'a, 'b, T> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        pending_to_would_block(self.inner.as_mut().poll_read(self.cx, buf))
    }
}

impl<'a, 'b, T: AsyncWrite> Write for AsyncWrapper<'a, 'b, T> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        pending_to_would_block(self.inner.as_mut().poll_write(self.cx, buf))
    }

    fn flush(&mut self) -> IoResult<()> {
        pending_to_would_block(self.inner.as_mut().poll_flush(self.cx))
    }
}

#[derive(Debug, Arbitrary)]
struct Data {
    config: ConfigData,
    bytes: Vec<u8>,
    read_limiter: FuzzSocketLimiter,
    read_mask: Vec<u8>,
    write_limiter: FuzzSocketLimiter,
    write_mask: Vec<u8>,
    schedule: FuzzSchedule,
}

fuzz_target!(|data: Data| {
    let Data {
        config,
        bytes,
        read_limiter,
        read_mask,
        write_limiter,
        write_mask,
        schedule,
    } = data;

    let mut executor = Executor::builder().with_schedule(schedule).build();

    executor.runtime().spawn(async move {
        let mut read = SocketLimiterWrapper::new(
            PendingWrapper {
                mask: read_mask,
                ix: 0,
                inner: Cursor::new(&bytes[..]),
            },
            read_limiter,
        );

        let mut cells = VecDeque::new();
        let mut reader = Reader::new(Config {
            data: &config,
            off: 0,
        });
        let mut pos = 0;
        loop {
            let r = poll_fn(|cx| {
                match reader.read(&mut AsyncWrapper {
                    inner: Pin::new(&mut read),
                    cx,
                }) {
                    Ok(None) => Poll::Pending,
                    Ok(Some(v)) => Poll::Ready(Ok(v)),
                    Err(e) => Poll::Ready(Err(e)),
                }
            })
            .await;

            let c = match r {
                Err(CellReadError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => {
                    assert_eq!(
                        reader.is_finished(),
                        e.get_ref()
                            .and_then(|v| v.downcast_ref::<CellFinished>())
                            .is_some()
                    );
                    break;
                }
                v => v.unwrap(),
            };
            cells.push_back(c);
            pos = read.socket_mut().inner.position() as usize;
            reader.config.off = reader.config.off.saturating_add(1);
        }

        drop((read, reader));

        let mut write = SocketLimiterWrapper::new(
            PendingWrapper {
                mask: write_mask,
                ix: 0,
                inner: Cursor::new(vec![0u8; pos].into_boxed_slice()),
            },
            write_limiter,
        );
        let mut writer = Writer::new(Config {
            data: &config,
            off: 0,
        });
        assert!(writer.is_ready());
        while writer.maybe_receive(|| cells.pop_front()) {
            let start = write.socket_mut().inner.position() as usize;
            poll_fn(|cx| {
                match writer.write(&mut AsyncWrapper {
                    inner: Pin::new(&mut write),
                    cx,
                }) {
                    Ok(false) => Poll::Pending,
                    Ok(true) => Poll::Ready(Ok(())),
                    Err(e) => Poll::Ready(Err(e)),
                }
            })
            .await
            .unwrap();

            let end = write.socket_mut().inner.position() as usize;
            for i in start..end {
                assert_eq!(
                    &bytes[i],
                    &write.socket_mut().inner.get_ref()[i],
                    "mismatch at index {i} in range {start}..{end}"
                );
            }
            assert!(writer.is_ready());

            writer.config.off = writer.config.off.saturating_add(1);
        }
    });

    executor.run();
});
