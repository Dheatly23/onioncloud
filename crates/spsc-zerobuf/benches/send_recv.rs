use std::env::var;
use std::thread::available_parallelism;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures_util::{SinkExt, StreamExt};
use tokio::runtime::Builder;
use tokio::spawn;

use onioncloud_spsc_zerobuf::new;

async fn zerobuf_task(n: u64) {
    let (mut send, mut recv) = new::<Box<u64>>();

    let handle = spawn(async move {
        for i in 0..n {
            send.feed(Box::new(i)).await.unwrap();
        }
        send.close().await.unwrap();
    });

    for i in 0..n {
        let v = recv.next().await;
        assert_eq!(v.as_deref(), Some(&i));
    }
    assert_eq!(recv.next().await, None);

    handle.await.unwrap();
}

async fn flume_task(buf: usize, n: u64) {
    let (send, recv) = flume::bounded::<Box<u64>>(buf);

    let handle = spawn(async move {
        let mut send = send.into_sink();
        for i in 0..n {
            send.feed(Box::new(i)).await.unwrap();
        }
        send.close().await.unwrap();
    });

    let mut recv = recv.into_stream();
    for i in 0..n {
        let v = recv.next().await;
        assert_eq!(v.as_deref(), Some(&i));
    }
    assert_eq!(recv.next().await, None);

    handle.await.unwrap();
}

async fn crossfire_task(buf: usize, n: u64) {
    let (send, recv) = crossfire::spsc::bounded_async::<Box<u64>>(buf);

    let handle = spawn(async move {
        for i in 0..n {
            send.send(Box::new(i)).await.unwrap();
        }
    });

    for i in 0..n {
        let v = recv.recv().await.ok();
        assert_eq!(v.as_deref(), Some(&i));
    }
    assert_eq!(recv.recv().await.ok(), None);

    handle.await.unwrap();
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

    c.bench_function("SPSC zerobuf (small)", |b| {
        b.to_async(&rt).iter(|| zerobuf_task(3));
    });

    c.bench_function("SPSC zerobuf (many)", |b| {
        b.to_async(&rt).iter_custom(|n| async move {
            let start = Instant::now();
            zerobuf_task(n).await;
            start.elapsed()
        });
    });

    c.bench_function("flume zerobuf (many)", |b| {
        b.to_async(&rt).iter_custom(|n| async move {
            let start = Instant::now();
            flume_task(0, n).await;
            start.elapsed()
        });
    });

    c.bench_function("flume 128 buffered (many)", |b| {
        b.to_async(&rt).iter_custom(|n| async move {
            let start = Instant::now();
            flume_task(128, n).await;
            start.elapsed()
        });
    });

    c.bench_function("crossfire 1 buffered (many)", |b| {
        b.to_async(&rt).iter_custom(|n| async move {
            let start = Instant::now();
            crossfire_task(1, n).await;
            start.elapsed()
        });
    });

    c.bench_function("crossfire 128 buffered (many)", |b| {
        b.to_async(&rt).iter_custom(|n| async move {
            let start = Instant::now();
            crossfire_task(128, n).await;
            start.elapsed()
        });
    });

    {
        let mut c = c.benchmark_group("throughput");
        c.warm_up_time(Duration::from_secs(10));

        for n in [1, 10, 100, 1000, 10_000] {
            c.throughput(Throughput::Elements(n));

            for t in 1..=n_threads {
                c.bench_with_input(
                    BenchmarkId::new(format!("SPSC zerobuf ({t} threads)"), n),
                    &(t, n),
                    |b, &(t, n)| {
                        b.to_async(&rt).iter(|| async move {
                            let handles =
                                (0..t).map(|_| spawn(zerobuf_task(n))).collect::<Vec<_>>();
                            for h in handles {
                                h.await.unwrap();
                            }
                        })
                    },
                );

                c.bench_with_input(
                    BenchmarkId::new(format!("flume zerobuf ({t} threads)"), n),
                    &(t, n),
                    |b, &(t, n)| {
                        b.to_async(&rt).iter(|| async move {
                            let handles =
                                (0..t).map(|_| spawn(flume_task(0, n))).collect::<Vec<_>>();
                            for h in handles {
                                h.await.unwrap();
                            }
                        })
                    },
                );

                c.bench_with_input(
                    BenchmarkId::new(format!("flume 128 buffered ({t} threads)"), n),
                    &(t, n),
                    |b, &(t, n)| {
                        b.to_async(&rt).iter(|| async move {
                            let handles = (0..t)
                                .map(|_| spawn(flume_task(128, n)))
                                .collect::<Vec<_>>();
                            for h in handles {
                                h.await.unwrap();
                            }
                        })
                    },
                );

                c.bench_with_input(
                    BenchmarkId::new(format!("crossfire 1 buffered ({t} threads)"), n),
                    &(t, n),
                    |b, &(t, n)| {
                        b.to_async(&rt).iter(|| async move {
                            let handles = (0..t)
                                .map(|_| spawn(crossfire_task(1, n)))
                                .collect::<Vec<_>>();
                            for h in handles {
                                h.await.unwrap();
                            }
                        })
                    },
                );

                c.bench_with_input(
                    BenchmarkId::new(format!("crossfire 128 buffered ({t} threads)"), n),
                    &(t, n),
                    |b, &(t, n)| {
                        b.to_async(&rt).iter(|| async move {
                            let handles = (0..t)
                                .map(|_| spawn(crossfire_task(128, n)))
                                .collect::<Vec<_>>();
                            for h in handles {
                                h.await.unwrap();
                            }
                        })
                    },
                );
            }
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().warm_up_time(Duration::from_secs(30)).measurement_time(Duration::from_secs(30)).sample_size(250);
    targets = criterion_benchmark
);
criterion_main!(benches);
