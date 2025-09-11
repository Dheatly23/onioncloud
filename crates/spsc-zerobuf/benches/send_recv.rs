use std::env::var;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::hint::black_box;
use std::thread::available_parallelism;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures_util::{SinkExt, StreamExt};
use tokio::runtime::{Builder, Runtime};
use tokio::spawn;

use onioncloud_spsc_zerobuf::new;

trait SendRecvTask: Display {
    fn send_recv_pair(
        &self,
        n: u64,
    ) -> (
        impl Future<Output = ()> + Send + 'static,
        impl Future<Output = ()> + Send + 'static,
    );
}

#[derive(Clone)]
struct SpscZerobuf;

impl Display for SpscZerobuf {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "SPSC zerobuf")
    }
}

impl SendRecvTask for SpscZerobuf {
    fn send_recv_pair(
        &self,
        n: u64,
    ) -> (
        impl Future<Output = ()> + Send + 'static,
        impl Future<Output = ()> + Send + 'static,
    ) {
        let (mut send, mut recv) = new::<u64>();

        (
            async move {
                for i in 0..n {
                    send.feed(black_box(i)).await.unwrap();
                }
                send.close().await.unwrap();
            },
            async move {
                for i in 0..n {
                    assert_eq!(recv.next().await, Some(i));
                }
                assert_eq!(recv.next().await, None);
            },
        )
    }
}

#[derive(Clone)]
enum Flume {
    Zerobuf,
    Buffered,
}

impl Display for Flume {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "Flume {}",
            match self {
                Self::Zerobuf => "zerobuf",
                Self::Buffered => "128 buffered",
            }
        )
    }
}

impl SendRecvTask for Flume {
    fn send_recv_pair(
        &self,
        n: u64,
    ) -> (
        impl Future<Output = ()> + Send + 'static,
        impl Future<Output = ()> + Send + 'static,
    ) {
        let (send, recv) = flume::bounded::<u64>(match self {
            Self::Zerobuf => 0,
            Self::Buffered => 128,
        });

        (
            async move {
                let mut send = send.into_sink();
                for i in 0..n {
                    send.feed(black_box(i)).await.unwrap();
                }
                send.close().await.unwrap();
            },
            async move {
                let mut recv = recv.into_stream();
                for i in 0..n {
                    assert_eq!(recv.next().await, Some(i));
                }
                assert_eq!(recv.next().await, None);
            },
        )
    }
}

#[derive(Clone)]
enum Crossfire {
    Onebuf,
    Buffered,
}

impl Display for Crossfire {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "Crossfire {} buffered",
            match self {
                Self::Onebuf => 1u8,
                Self::Buffered => 128u8,
            }
        )
    }
}

impl SendRecvTask for Crossfire {
    fn send_recv_pair(
        &self,
        n: u64,
    ) -> (
        impl Future<Output = ()> + Send + 'static,
        impl Future<Output = ()> + Send + 'static,
    ) {
        let (send, recv) = crossfire::spsc::bounded_async::<u64>(match self {
            Self::Onebuf => 1,
            Self::Buffered => 128,
        });

        (
            async move {
                for i in 0..n {
                    send.send(black_box(i)).await.unwrap();
                }
            },
            async move {
                for i in 0..n {
                    assert_eq!(recv.recv().await.ok(), Some(i));
                }
                assert_eq!(recv.recv().await.ok(), None);
            },
        )
    }
}

async fn multi_thread(task: &impl SendRecvTask, n_threads: usize, n: u64) {
    let handles = (0..n_threads)
        .flat_map(|_| {
            let (send, recv) = task.send_recv_pair(n);
            [spawn(send), spawn(recv)]
        })
        .collect::<Vec<_>>();

    for h in handles {
        h.await.unwrap();
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let n_threads = var("N_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| available_parallelism().ok().map(usize::from))
        .unwrap_or(4);

    let rt = Builder::new_multi_thread()
        .worker_threads(n_threads)
        .enable_time()
        .build()
        .unwrap();

    fn inner(
        c: &mut Criterion,
        rt: &Runtime,
        n_threads: usize,
        task: impl SendRecvTask + Clone + Send,
    ) {
        c.bench_function(&format!("{} (many)", task), move |b| {
            b.to_async(rt).iter_custom(|n| {
                let task = task.clone();
                async move {
                    let start = Instant::now();
                    multi_thread(&task, n_threads, n).await;
                    start.elapsed()
                }
            });
        });
    }

    inner(c, &rt, n_threads, SpscZerobuf);
    inner(c, &rt, n_threads, Flume::Zerobuf);
    inner(c, &rt, n_threads, Flume::Buffered);
    inner(c, &rt, n_threads, Crossfire::Onebuf);
    inner(c, &rt, n_threads, Crossfire::Buffered);
}

criterion_group!(
    name = benches;
    config = Criterion::default().warm_up_time(Duration::from_secs(60)).measurement_time(Duration::from_secs(60)).sample_size(500);
    targets = criterion_benchmark
);
criterion_main!(benches);
