#![no_main]

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use onioncloud_tart::rt::{Executor, Runtime};
use onioncloud_tart::timer::Timer;

#[derive(Default)]
struct Yield(bool);

impl Future for Yield {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = Pin::into_inner(self);
        if this.0 {
            return Poll::Ready(());
        }
        this.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[derive(Debug, Arbitrary, Clone)]
enum TaskAction {
    PollReady,
    WaitDuration(u64),
    WaitEpoch(u64),
}

impl TaskAction {
    async fn run_action(&self, rt: &Runtime, epoch: &Instant) {
        match self {
            Self::PollReady => Yield::default().await,
            Self::WaitDuration(dur) => {
                Timer::with_duration(rt.clone(), Duration::from_nanos(*dur)).await
            }
            Self::WaitEpoch(dur) => {
                Timer::with_instant(rt.clone(), *epoch + Duration::from_nanos(*dur)).await
            }
        }
    }
}

type TaskActions = Vec<TaskAction>;

async fn run_task(rt: Runtime, tasks: TaskActions) {
    let epoch = rt.get_time();
    for t in tasks {
        t.run_action(&rt, &epoch).await
    }
}

fuzz_target!(|tasks_actions: Vec<TaskActions>| {
    let mut executor = Executor::builder().build();

    let rt = executor.runtime();
    for tasks in tasks_actions {
        rt.spawn(run_task(rt.clone(), tasks));
    }

    executor.run();
});
