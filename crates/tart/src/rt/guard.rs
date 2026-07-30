use std::cell::UnsafeCell;
use std::marker::PhantomPinned;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU8, Ordering::*};

use super::{InnerRuntime, Tasklist};

/// Runtime guard.
pub(crate) struct RuntimeGuard {
    state: AtomicU8,

    tasklist: UnsafeCell<Tasklist>,
    inner: UnsafeCell<InnerRuntime>,

    _pinned: PhantomPinned,
}

// SAFETY: RuntimeGuard is sync if it's inner types are send.
unsafe impl Sync for RuntimeGuard
where
    Tasklist: Send,
    InnerRuntime: Send,
{
}

const TASKLIST_FLAG: u8 = 1;
const INNER_FLAG: u8 = 1 << 2;

impl RuntimeGuard {
    pub(crate) fn new(rt: InnerRuntime) -> Self {
        Self {
            state: AtomicU8::new(0),

            tasklist: Default::default(),
            inner: UnsafeCell::new(rt),

            _pinned: PhantomPinned,
        }
    }

    pub(crate) fn tasklist(&self) -> TasklistGuard<'_> {
        let r = self.state.fetch_or(TASKLIST_FLAG, Acquire);
        assert!(r & TASKLIST_FLAG == 0, "acquiring runtime twice");

        TasklistGuard {
            state: &self.state,
            // SAFETY: We locked tasklist.
            inner: unsafe { &mut *self.tasklist.get() },
        }
    }

    pub(crate) fn runtime(&self) -> InnerGuard<'_> {
        let r = self.state.fetch_or(INNER_FLAG, Acquire);
        assert!(r & INNER_FLAG == 0, "acquiring runtime twice");

        InnerGuard {
            state: &self.state,
            // SAFETY: We locked inner.
            inner: unsafe { &mut *self.inner.get() },
        }
    }
}

pub(crate) struct TasklistGuard<'a> {
    state: &'a AtomicU8,
    inner: &'a mut Tasklist,
}

impl Drop for TasklistGuard<'_> {
    fn drop(&mut self) {
        self.state.fetch_and(!TASKLIST_FLAG, Release);
    }
}

impl Deref for TasklistGuard<'_> {
    type Target = Tasklist;

    fn deref(&self) -> &Tasklist {
        self.inner
    }
}

impl DerefMut for TasklistGuard<'_> {
    fn deref_mut(&mut self) -> &mut Tasklist {
        self.inner
    }
}

pub(crate) struct InnerGuard<'a> {
    state: &'a AtomicU8,
    inner: &'a mut InnerRuntime,
}

impl Drop for InnerGuard<'_> {
    fn drop(&mut self) {
        self.state.fetch_and(!INNER_FLAG, Release);
    }
}

impl Deref for InnerGuard<'_> {
    type Target = InnerRuntime;

    fn deref(&self) -> &InnerRuntime {
        self.inner
    }
}

impl DerefMut for InnerGuard<'_> {
    fn deref_mut(&mut self) -> &mut InnerRuntime {
        self.inner
    }
}
