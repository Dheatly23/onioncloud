use std::debug_assert_matches;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::future::Future;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use futures_core::FusedFuture;
use humantime::Duration as HumanDuration;
use slab::Slab;
use tracing::{info, instrument};

use crate::rt::Runtime;

/// Inner value for timer.
#[derive(Debug)]
struct InnerTimer {
    waker: Option<Waker>,
    delta: Option<Duration>,
}

impl InnerTimer {
    fn wake(&mut self) -> bool {
        let ret = if let Some(w) = self.waker.take() {
            w.wake();
            true
        } else {
            false
        };
        self.delta = None;
        ret
    }
}

/// Controller for timers.
pub(crate) struct Timers {
    timers: Slab<InnerTimer>,

    pub(crate) epoch: Instant,
    delta: Duration,
}

impl Timers {
    pub(crate) fn new(epoch: Instant) -> Self {
        Self {
            timers: Slab::new(),

            epoch,
            delta: Duration::ZERO,
        }
    }

    pub(crate) fn get_time(&self) -> Instant {
        self.epoch + self.delta
    }

    #[instrument(skip_all)]
    pub(crate) fn advance_time(&mut self) -> bool {
        let mut min_delta = None;
        let mut n = 0;

        for (_ix, i) in self.timers.iter_mut() {
            debug_assert_matches!(
                i,
                InnerTimer {
                    waker: None,
                    delta: None
                } | InnerTimer {
                    waker: None,
                    delta: Some(_)
                } | InnerTimer {
                    waker: Some(_),
                    delta: Some(_)
                },
                "invalid inner timer state"
            );

            let Some(ref delta) = i.delta else {
                continue;
            };
            if *delta > self.delta {
                min_delta = match min_delta {
                    None => Some(*delta),
                    Some(t) => Some(t.min(*delta)),
                };
                continue;
            }

            #[cfg(test)]
            {
                tracing::trace!(id = _ix, time = %HumanDuration::new(*delta), "waking timer");
            }

            if i.wake() {
                n += 1;
            }
        }

        if let Some(t) = min_delta {
            assert!(t > self.delta);
            info!("advance time by {}", HumanDuration::new(t - self.delta));
            self.delta = t;

            for (_ix, i) in self.timers.iter_mut() {
                if let Some(ref delta) = i.delta
                    && *delta <= self.delta
                {
                    #[cfg(test)]
                    {
                        tracing::trace!(id = _ix, time = %HumanDuration::new(*delta), "waking timer");
                    }

                    if i.wake() {
                        n += 1;
                    }
                }
            }
        }

        info!(awakened = n, "done processing timers");
        n > 0
    }
}

/// Handle to timer.
///
/// # Re-await safety
///
/// Timer is always safe to poll, even after it resolves.
/// Timer will only do two things when polled:
/// - Register waker and return [`Poll::Pending`].
/// - Return [`Poll::Ready`].
///
/// That way, you can reuse the same timer indefinitely.
///
/// # Example
///
/// ```
/// # use std::pin::pin;
/// # use std::time::Duration;
/// # use onioncloud_tart::{rt::Executor, timer::Timer};
/// // Make executor
/// let mut executor = Executor::builder().build();
/// let rt = executor.runtime();
///
/// rt.spawn({
///     let rt = rt.clone();
///     async move {
///         // Wait for a long time.
///         Timer::with_duration(rt.clone(), Duration::from_secs(595627)).await;
///
///         // Alternate construction with get_time()
///         Timer::with_instant(rt.clone(), rt.get_time() + Duration::from_secs(551840)).await;
///
///         let mut timer = pin!(Timer::with_duration(rt.clone(), Duration::from_secs(225475)));
///         // Reset timer so it waits for nothing.
///         timer.as_mut().reset();
///         timer.await;
///     }
/// });
///
/// // Run executor
/// executor.run();
/// ```
#[must_use]
pub struct Timer {
    rt: Runtime,
    index: usize,
    _pinned: PhantomPinned,
}

impl Drop for Timer {
    fn drop(&mut self) {
        let Some(inner) = self.rt.maybe_inner() else {
            return;
        };
        let mut rt = inner.runtime();
        let timers = &mut rt.timers().timers;
        if timers.contains(self.index) {
            timers.remove(self.index);
        }

        #[cfg(test)]
        {
            tracing::trace!(id = self.index, "dropped timer");
        }
    }
}

impl Debug for Timer {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Timer")
            .field("rt", &self.rt)
            .field("index", &self.index)
            .finish()
    }
}

impl Future for Timer {
    type Output = ();

    #[cfg_attr(test, instrument(skip_all))]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let inner = self.rt.inner();
        let mut rt = inner.runtime();
        let t = rt
            .timers()
            .timers
            .get_mut(self.index)
            .expect("timer must exist");

        if t.delta.is_none() {
            #[cfg(test)]
            {
                tracing::trace!(id = self.index, "timer finished");
            }

            return Poll::Ready(());
        }

        match t.waker {
            Some(ref mut w) => w.clone_from(cx.waker()),
            ref mut w @ None => *w = Some(cx.waker().clone()),
        }

        #[cfg(test)]
        {
            tracing::trace!(id = self.index, "registered timer waker");
        }

        Poll::Pending
    }
}

/// Marks [`Timer`] as never terminated so it can be used for `select!`.
impl FusedFuture for Timer {
    fn is_terminated(&self) -> bool {
        false
    }
}

impl Timer {
    fn allocate(timers: &mut Timers, delta: Option<Duration>) -> usize {
        let index = timers.timers.insert(InnerTimer { waker: None, delta });

        #[cfg(test)]
        if let Some(delta) = delta {
            tracing::trace!(id = index, time = %HumanDuration::new(delta), "created new timer");
        } else {
            tracing::trace!(id = index, "created new finished timer");
        }

        index
    }

    /// Create timer with [`Duration`].
    #[cfg_attr(test, instrument(skip_all))]
    pub fn with_duration(rt: Runtime, delta: Duration) -> Self {
        let inner = rt.inner();
        let mut g = inner.runtime();
        let timers = g.timers();

        let delta = delta_validate(delta + timers.delta, timers.delta);
        let index = Self::allocate(timers, delta);

        Self {
            rt,
            index,
            _pinned: PhantomPinned,
        }
    }

    /// Create timer with [`Instant`].
    #[cfg_attr(test, instrument(skip_all))]
    pub fn with_instant(rt: Runtime, time: Instant) -> Self {
        let inner = rt.inner();
        let mut g = inner.runtime();
        let timers = g.timers();

        let delta = delta_validate(time.saturating_duration_since(timers.epoch), timers.delta);
        let index = Self::allocate(timers, delta);

        Self {
            rt,
            index,
            _pinned: PhantomPinned,
        }
    }

    /// Create timer that always resolves.
    #[cfg_attr(test, instrument(skip_all))]
    pub fn always_resolve(rt: Runtime) -> Self {
        let inner = rt.inner();
        let mut g = inner.runtime();
        let timers = g.timers();
        let index = Self::allocate(timers, None);

        Self {
            rt,
            index,
            _pinned: PhantomPinned,
        }
    }

    fn set_delta(&self, timers: &mut Timers, delta: Option<Duration>) {
        let t = timers.timers.get_mut(self.index).expect("timer must exist");
        t.delta = delta;
        if t.delta.is_none() {
            t.waker = None;
        }

        #[cfg(test)]
        if let Some(delta) = delta {
            tracing::trace!(id = self.index, time = %HumanDuration::new(delta), "reset timer");
        } else {
            tracing::trace!(id = self.index, "reset timer");
        }
    }

    /// Reset timer to [`Duration`] from now.
    ///
    /// See also: [`Timer::with_duration`].
    #[cfg_attr(test, instrument(skip_all))]
    pub fn set_duration(self: Pin<&mut Self>, delta: Duration) {
        let inner = self.rt.inner();
        let mut rt = inner.runtime();
        let timers = rt.timers();

        let delta = delta_validate(delta + timers.delta, timers.delta);
        self.set_delta(timers, delta);
    }

    /// Reset timer to [`Instant`].
    ///
    /// See also: [`Timer::with_instant`].
    #[cfg_attr(test, instrument(skip_all))]
    pub fn set_instant(self: Pin<&mut Self>, time: Instant) {
        let inner = self.rt.inner();
        let mut rt = inner.runtime();
        let timers = rt.timers();

        let delta = delta_validate(time.saturating_duration_since(timers.epoch), timers.delta);
        self.set_delta(timers, delta);
    }

    /// Reset timer.
    ///
    /// Timer will instantly resolves.
    ///
    /// See also: [`Timer::always_resolve`].
    #[cfg_attr(test, instrument(skip_all))]
    pub fn reset(self: Pin<&mut Self>) {
        let inner = self.rt.inner();
        let mut rt = inner.runtime();
        let timers = rt.timers();
        *timers.timers.get_mut(self.index).expect("timer must exist") = InnerTimer {
            waker: None,
            delta: None,
        };

        #[cfg(test)]
        {
            tracing::trace!(id = self.index, "reset timer");
        }
    }
}

fn delta_validate(delta: Duration, cur: Duration) -> Option<Duration> {
    (delta > cur).then_some(delta)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::hint::black_box;
    use std::pin::pin;

    use futures_util::select_biased;
    use test_log::test;

    use crate::rt::Executor;
    use crate::utils::run_test;

    #[test]
    fn test_timer_create() {
        #[instrument]
        fn test() {
            let executor = Executor::builder().build();
            let rt = executor.runtime();
            let _t1 = black_box(Timer::with_duration(
                rt.clone(),
                Duration::from_secs(354643),
            ));
            let _t2a = black_box(Timer::with_instant(
                rt.clone(),
                rt.get_time() + Duration::from_secs(400641),
            ));
            let _t2b = black_box(Timer::with_instant(rt.clone(), rt.get_time()));
            let _t3 = black_box(Timer::always_resolve(rt.clone()));
        }

        run_test(test);
    }

    #[test]
    fn test_timer_always_resolve() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();
            let rt = executor.runtime();

            let rt_ = rt.clone();
            rt_.spawn(async move {
                info!("waiting for 0 seconds");
                Timer::always_resolve(rt).await;
                info!("done waiting");
            });

            executor.run();
        }

        run_test(test);
    }

    #[test]
    fn test_timer_wait() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();
            let rt = executor.runtime();

            rt.spawn({
                let rt = rt.clone();
                async move {
                    info!("waiting for 265409 seconds");
                    Timer::with_duration(rt, Duration::from_secs(265409)).await;
                    info!("done waiting");
                }
            });

            rt.spawn({
                let rt = rt.clone();
                async move {
                    info!("waiting for 274028 seconds");
                    Timer::with_duration(rt, Duration::from_secs(274028)).await;
                    info!("done waiting");
                }
            });

            rt.spawn({
                let rt = rt.clone();
                async move {
                    info!("waiting for 288693 seconds");
                    Timer::with_duration(rt, Duration::from_secs(288693)).await;
                    info!("done waiting");
                }
            });

            executor.run();
        }

        run_test(test);
    }

    #[test]
    fn test_timer_multi() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();
            let rt_ = executor.runtime();

            for i in 0..10 {
                let rt = rt_.clone();
                rt_.spawn(async move {
                    info!("waiting for {i} seconds");
                    Timer::with_duration(rt, Duration::from_secs(i)).await;
                    info!("done waiting");
                });
            }

            executor.run();
        }

        run_test(test);
    }

    #[test]
    fn test_timer_select() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();
            let rt = executor.runtime();

            let rt_ = rt.clone();
            rt_.spawn(async move {
                info!("waiting...");

                select_biased!{
                    _ = Timer::with_duration(rt.clone(), Duration::from_secs(2)) => panic!("longer timer fires before shorter timer"),
                    _ = Timer::with_duration(rt.clone(), Duration::from_secs(1)) => (),
                    _ = Timer::with_duration(rt.clone(), Duration::from_secs(3)) => panic!("longer timer fires before shorter timer"),
                }

                info!("done waiting");
            });

            executor.run();
        }

        run_test(test);
    }

    #[test]
    fn test_timer_reset() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();
            let rt = executor.runtime();

            let rt_ = rt.clone();
            rt_.spawn(async move {
                info!("waiting...");

                let mut t1 = pin!(Timer::with_duration(rt.clone(), Duration::from_secs(2)));
                let mut t2 = pin!(Timer::with_duration(rt.clone(), Duration::from_secs(1)));
                let mut t3 = pin!(Timer::with_duration(rt.clone(), Duration::from_secs(2)));

                select_biased! {
                    _ = t1 => panic!("longer timer fires before shorter timer"),
                    _ = t2 => (),
                    _ = t3 => panic!("longer timer fires before shorter timer"),
                }

                info!("done waiting, resetting timer");

                t2.as_mut().set_duration(Duration::from_secs(5));

                select_biased! {
                    _ = t1 => (),
                    _ = t2 => panic!("longer timer fires before shorter timer"),
                    _ = t3 => panic!("longer timer fires before shorter timer"),
                }

                info!("done waiting, resetting another timer");

                t3.as_mut().set_duration(Duration::from_secs(1));

                select_biased! {
                    _ = t2 => panic!("longer timer fires before shorter timer"),
                    _ = t3 => (),
                }

                t2.await;

                info!("done waiting");
            });

            executor.run();
        }

        run_test(test);
    }
}
