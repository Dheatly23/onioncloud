use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::*;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{instrument, trace};

use crate::private::Sealed;
use crate::runtime::Timer;
use crate::util::set_option_waker;

pub(super) struct Timers {
    time: Arc<RefTime>,
    timers: Mutex<Vec<Weak<Mutex<TimerInner>>>>,
}

struct RefTime {
    ref_time: Instant,
    off_time: AtomicU64,
}

impl RefTime {
    fn current_time(&self) -> Instant {
        let off = self.off_time.load(Acquire);
        let secs = off >> 32;
        let nanos = off as u32;
        self.ref_time + Duration::new(secs, nanos)
    }

    #[instrument(skip_all)]
    fn advance_time(&self, delta: Duration) {
        trace!(
            "advance timer by {} secs, {} nanos",
            delta.as_secs(),
            delta.subsec_nanos()
        );
        if delta.is_zero() {
            return;
        }

        let off = self.off_time.load(Relaxed);
        let mut secs = off >> 32;
        let mut nanos = off as u32;

        secs += delta.as_secs();
        nanos += delta.subsec_nanos();
        secs += (nanos / 1_000_000_000) as u64;
        nanos %= 1_000_000_000;

        let new_off = secs << 32 | nanos as u64;
        self.off_time.store(new_off, Release);
    }
}

impl Default for Timers {
    fn default() -> Self {
        Self {
            time: Arc::new(RefTime {
                ref_time: Instant::now(),
                off_time: 0u64.into(),
            }),
            timers: Mutex::default(),
        }
    }
}

impl Timers {
    pub(super) fn current_time(&self) -> Instant {
        self.time.current_time()
    }

    pub(super) fn advance_time(&self, delta: Duration) {
        self.time.advance_time(delta)
    }

    #[instrument(skip_all)]
    pub(super) fn wake_timers(&self) {
        let cur = self.current_time();
        let mut n = 0;

        self.timers.try_lock().unwrap().retain(|i| {
            let Some(i) = i.upgrade() else { return false };
            let mut i = i.lock();
            if let Some(t) = i.time
                && cur >= t
            {
                i.time = None;
                n += 1;
                if let Some(w) = i.waker.take() {
                    w.wake();
                }
            }
            true
        });

        trace!("woken {n} timers");
    }

    #[instrument(skip_all)]
    pub(super) fn advance_and_wake_timers(&self) {
        let mut n = 0;
        let cur = self.current_time();
        let mut time: Option<Instant> = None;

        let mut guard = self.timers.try_lock().unwrap();
        guard.retain(|i| {
            let Some(i) = i.upgrade() else { return false };
            let i = i.lock();
            if i.waker.is_some()
                && let Some(v) = i.time
                && v >= cur
            {
                time = Some(match time {
                    Some(a) => a.min(v),
                    None => v,
                });
            }
            true
        });

        let time = time.unwrap_or(cur);
        self.advance_time(time.saturating_duration_since(cur));

        for i in guard.iter() {
            let Some(i) = i.upgrade() else { continue };
            let mut i = i.lock();
            if let Some(t) = i.time
                && time >= t
            {
                i.time = None;
                n += 1;
                if let Some(w) = i.waker.take() {
                    w.wake();
                }
            }
        }

        trace!("woken {n} timers");
    }

    pub(super) fn create_timer(&self, timeout: Option<Instant>) -> TestTimer {
        let ret = TestTimer {
            inner: Arc::new(Mutex::new(TimerInner {
                time: timeout,
                waker: None,
            })),
            time: self.time.clone(),
        };
        self.timers.lock().push(Arc::downgrade(&ret.inner));
        ret
    }
}

#[derive(Default)]
struct TimerInner {
    time: Option<Instant>,
    waker: Option<Waker>,
}

/// A test timer.
#[must_use = "timer does nothing if not polled"]
pub struct TestTimer {
    inner: Arc<Mutex<TimerInner>>,
    time: Arc<RefTime>,
}

impl Sealed for TestTimer {}

impl Future for TestTimer {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let Self { inner, time } = &*Pin::into_inner(self);
        let mut inner = inner.lock();

        if let Some(t) = inner.time
            && time.current_time() < t
        {
            set_option_waker(&mut inner.waker, cx);
            Poll::Pending
        } else {
            inner.time = None;
            inner.waker = None;
            Poll::Ready(())
        }
    }
}

impl Timer for TestTimer {
    fn reset(self: Pin<&mut Self>, timeout: Instant) {
        let Self { inner, time } = &*Pin::into_inner(self);
        let mut inner = inner.lock();

        if time.current_time() < timeout {
            inner.time = Some(timeout);
        } else {
            inner.time = None;
            inner.waker = None;
        }
    }
}
