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
        match *self {
            Self::PollReady => {
                let start = rt.get_time();
                Yield::default().await;
                let end = rt.get_time();
                assert_eq!(start, end, "yielding should not pass time");
            }
            Self::WaitDuration(d) => {
                let start = rt.get_time();
                let dur = Duration::from_nanos(d);
                Timer::with_duration(rt.clone(), dur).await;
                let end = rt.get_time();
                assert_eq!(
                    end.checked_duration_since(start),
                    Some(dur),
                    "duration should pass"
                );
            }
            Self::WaitEpoch(d) => {
                let start = rt.get_time();
                let epoch = *epoch + Duration::from_nanos(d);
                Timer::with_instant(rt.clone(), epoch).await;
                let end = rt.get_time();
                assert_eq!(
                    end,
                    start.max(epoch),
                    "end must be maximum of start & epoch"
                );
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
