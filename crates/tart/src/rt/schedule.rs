//! Fuzzing runtime scheduling.
//!
//! Allows for fuzzing scheduling to uncover order-dependent task bugs.
//! By default, runtime have a deterministic (but not specified) order of task invocation.

use arbitrary::Arbitrary;

use crate::utils::RevVec;

/// Runtime schedule fuzzer.
///
/// Allows for fuzzing scheduling to uncover order-dependent task bugs.
///
/// The internal structure is not part of it's public interface.
/// Use [`Arbitrary`] to generate it.
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzSchedule {
    schedule: RevVec<u64>,
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
                schedule: vec![1, 2, u64::MAX].into(),
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
