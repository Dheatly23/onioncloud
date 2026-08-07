//! Fuzzing runtime scheduling.
//!
//! Allows for fuzzing scheduling to uncover order-dependent task bugs.
//! By default, runtime have a deterministic (but not specified) order of task invocation.

use arbitrary::{Arbitrary, MaxRecursionReached, Result as ArbResult, Unstructured};

#[derive(Debug, Clone)]
pub struct FuzzSchedule {
    schedule: Vec<u64>,
}

impl<'a> Arbitrary<'a> for FuzzSchedule {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        let mut ret = Self {
            schedule: Arbitrary::arbitrary(u)?,
        };
        ret.schedule.reverse();
        Ok(ret)
    }

    fn arbitrary_take_rest(u: Unstructured<'a>) -> ArbResult<Self> {
        let mut ret = Self {
            schedule: Arbitrary::arbitrary_take_rest(u)?,
        };
        ret.schedule.reverse();
        Ok(ret)
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        <Vec<u64> as Arbitrary<'a>>::size_hint(depth)
    }

    fn try_size_hint(depth: usize) -> Result<(usize, Option<usize>), MaxRecursionReached> {
        <Vec<u64> as Arbitrary<'a>>::try_size_hint(depth)
    }
}

impl FuzzSchedule {
    pub(crate) fn take_schedule(&mut self) -> u64 {
        self.schedule.pop().unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering::*};
    use std::task::{Context, Poll};

    use test_log::test;
    use tracing::{info, instrument};

    use crate::rt::Executor;
    use crate::utils::run_test;

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

    #[test]
    fn test_scheduler_schedule() {
        #[instrument]
        fn test() {
            let schedule = FuzzSchedule {
                schedule: vec![1, 2, u64::MAX],
            };

            let mut executor = Executor::builder().with_schedule(schedule).build();

            let rt = executor.runtime();
            let shared_ = Arc::new(AtomicUsize::new(0));

            let shared = shared_.clone();
            rt.spawn(async move {
                info!("called from task 1");
                assert_eq!(shared.load(Relaxed), 0);

                Yield::default().await;

                info!("called from task 1 again");
                assert_eq!(shared.swap(1, Relaxed), 2);

                Yield::default().await;

                info!("called from task 1 again part 2");
                assert_eq!(shared.swap(3, Relaxed), 1);
            });

            let shared = shared_.clone();
            rt.spawn(async move {
                info!("called from task 2");
                assert_eq!(shared.load(Relaxed), 0);

                Yield::default().await;

                info!("called from task 2 again");
                assert_eq!(shared.swap(2, Relaxed), 0);

                Yield::default().await;

                info!("called from task 2 again part 2");
                assert_eq!(shared.swap(4, Relaxed), 3);
            });

            executor.run();

            assert_eq!(shared_.load(Relaxed), 4);
        }

        run_test(test);
    }
}
