mod guard;

use std::future::Future;
use std::mem::ManuallyDrop;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Instant;

use futures_core::FusedFuture;
use pin_project::pin_project;
use tracing::{Span, error, info, info_span, instrument, trace};

use crate::oneshot::{Receiver, Sender, oneshot};
use crate::timer::Timers;
use crate::waker::{MultiWaker, Selector};
use guard::RuntimeGuard;

/// A task
struct Task {
    fut: ManuallyDrop<Pin<Box<dyn Future<Output = ()> + Send + Sync>>>,
    span: Span,
}

impl Drop for Task {
    fn drop(&mut self) {
        let _g = self.span.enter();
        // SAFETY: future will never be used again after.
        unsafe { ManuallyDrop::drop(&mut self.fut) }
    }
}

/// Task list.
#[derive(Default)]
pub(crate) struct Tasklist {
    tasks: Vec<Option<Task>>,
    wakers: Vec<MultiWaker>,
    selector: Selector,
}

/// Inner runtime.
pub(crate) struct InnerRuntime {
    offset: usize,
    queued: Vec<Task>,
    timers: Timers,
}

impl InnerRuntime {
    fn new(timers: Timers) -> Self {
        Self {
            offset: 0,
            queued: Vec::new(),
            timers,
        }
    }

    pub(crate) fn timers(&mut self) -> &mut Timers {
        &mut self.timers
    }

    pub(crate) fn queue_task(&mut self, fut: Pin<Box<dyn Future<Output = ()> + Send + Sync>>) {
        let span = info_span!(parent: None, "task", id = self.offset + self.queued.len());
        span.follows_from(Span::current());
        self.queued.push(Task {
            fut: ManuallyDrop::new(fut),
            span,
        });
    }
}

pub(crate) struct RunResult {
    pub(crate) any_task: bool,
    pub(crate) any_running: bool,
}

impl Tasklist {
    #[instrument(skip_all)]
    pub(crate) fn register_queued(&mut self, rt: &mut InnerRuntime) -> bool {
        let mut n = 0usize;
        for task in rt.queued.drain(..) {
            let i = self.tasks.len();
            if i.is_multiple_of(64) {
                self.wakers.push(MultiWaker::new(self.selector.clone()));
            }
            self.wakers[i / 64].wake_flag((i % 64) as u8);
            self.tasks.push(Some(task));

            n += 1;
        }

        rt.offset = self.tasks.len();
        info!(registered = n, "done registering queued tasks");
        n > 0
    }

    #[instrument(skip_all)]
    pub(crate) fn run_tasks(&mut self) -> RunResult {
        let mut pending = 0usize;
        let mut running = 0usize;
        let mut finished = 0usize;
        let sel = self.selector.switch();
        let mut f = 0;

        trace!(
            "waker bank switched from {} to {}",
            if sel { "left" } else { "right" },
            if !sel { "left" } else { "right" }
        );

        for (i, p) in self.tasks.iter_mut().enumerate() {
            let w = &self.wakers[i / 64];
            if i % 64 == 0 {
                f = w.take_flags(sel);

                trace!(id = i / 64, "loaded waker flags: {f:064b}");
            }

            let Some(task) = p else {
                continue;
            };

            if f & (1 << (i % 64)) == 0 {
                pending += 1;
                trace!(id = i, "task is pending");
                continue;
            }

            trace!(id = i, "task is running");
            let ret = task.span.in_scope(|| {
                task.fut
                    .as_mut()
                    .poll(&mut Context::from_waker(&w.make_waker((i % 64) as u8)))
            });
            if ret.is_ready() {
                *p = None;
                finished += 1;
                trace!(id = i, "task is finished");
            } else {
                running += 1;
            }
        }

        info!(running, finished, pending, "done running tasks");

        RunResult {
            any_running: running > 0 || finished > 0,
            any_task: pending > 0 || running > 0,
        }
    }
}

/// Handle of spawned task.
///
/// Spawned task will run independently. You can safely discards the handle if you don't need it.
/// When `await`-ed, it will either return the return value of subtask or panic if subtask panicked.
pub struct TaskHandle<T: Sized>(Receiver<T>);

impl<T: Sized> Future for TaskHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        Pin::new(&mut Pin::into_inner(self).0).poll(cx)
    }
}

impl<T: Sized> FusedFuture for TaskHandle<T> {
    fn is_terminated(&self) -> bool {
        self.0.is_terminated()
    }
}

/// Handle to runtime.
#[derive(Clone)]
pub struct Runtime(Weak<RuntimeGuard>);

impl Runtime {
    pub(crate) fn maybe_inner(&self) -> Option<Arc<RuntimeGuard>> {
        self.0.upgrade()
    }

    pub(crate) fn inner(&self) -> Arc<RuntimeGuard> {
        self.maybe_inner().expect("executor is dropped")
    }

    /// Gets current time.
    ///
    /// Unlike [`Instant::now`], this returns deterministic time in runtime.
    pub fn get_time(&self) -> Instant {
        self.inner().runtime().timers().get_time()
    }

    /// Spawns a new task.
    ///
    /// The resulting handle can be `await`ed to get the return value of subtask.
    pub fn spawn<T: Send>(
        &self,
        task: impl Future<Output = T> + 'static + Send + Sync,
    ) -> TaskHandle<T> {
        #[pin_project]
        struct Handle<F: Future> {
            #[pin]
            fut: F,
            send: Sender<F::Output>,
        }

        impl<F: Future> Future for Handle<F> {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                let this = self.project();
                let Poll::Ready(ret) = this.fut.poll(cx) else {
                    return Poll::Pending;
                };
                this.send.send(Some(ret));
                Poll::Ready(())
            }
        }

        let this = self.inner();
        let mut rt = this.runtime();
        let (send, recv) = oneshot::<T>();
        rt.queue_task(Box::pin(Handle { fut: task, send }));
        TaskHandle(recv)
    }
}

/// Runtime executor.
pub struct Executor {
    rt: Arc<RuntimeGuard>,
}

impl Executor {
    /// Create default builder for executor.
    #[must_use]
    pub fn builder() -> ExecutorBuilder {
        ExecutorBuilder::default()
    }

    /// Gets runtime of executor.
    #[must_use]
    pub fn runtime(&self) -> Runtime {
        Runtime(Arc::downgrade(&self.rt))
    }

    /// Run executor until all tasks finished.
    #[instrument(skip_all)]
    pub fn run(&mut self) {
        let mut tasklist = self.rt.tasklist();
        let mut res = RunResult {
            any_task: true,
            any_running: true,
        };

        for i in 0usize.. {
            info!("loop {i}");

            {
                let mut rt = self.rt.runtime();
                let r = tasklist.register_queued(&mut rt);
                // Registered tasks will run.
                res.any_task |= r;
                res.any_running |= r;

                // If previous loop has no task running, only then advance time.
                if !res.any_running {
                    res.any_running |= rt.timers().advance_time();
                }
            }

            if !res.any_task {
                return;
            }
            let r = tasklist.run_tasks();

            // Deadlock: previous and current loop yielded no task running.
            if !res.any_running && !r.any_running {
                error!("deadlock detected");
                panic!("all tasks are waiting");
            }

            res = r;
        }
    }
}

/// Builder for [`Executor`].
#[derive(Default)]
#[non_exhaustive]
pub struct ExecutorBuilder {
    epoch: Option<Instant>,
}

impl ExecutorBuilder {
    pub fn with_epoch(mut self, epoch: Instant) -> Self {
        self.epoch = Some(epoch);
        self
    }

    #[must_use]
    pub fn build(self) -> Executor {
        Executor {
            rt: Arc::new(RuntimeGuard::new(InnerRuntime::new(Timers::new(
                self.epoch.unwrap_or_else(Instant::now),
            )))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::future::poll_fn;
    use std::hint::black_box;
    use std::task::Poll;

    use futures_util::future::pending;
    use test_log::test;

    use crate::utils::run_test;

    #[test]
    fn test_executor_build() {
        #[instrument]
        fn test() {
            black_box(Executor::builder().build());
        }

        run_test(test);
    }

    #[test]
    fn test_executor_run_one() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();

            executor.runtime().spawn(async {
                info!("called from task");
            });

            executor.run();
        }

        run_test(test);
    }

    #[test]
    fn test_executor_run_multi() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();
            let rt = executor.runtime();
            rt.spawn(async {
                info!("called from task");
            });
            rt.spawn(async {
                struct S();

                impl Drop for S {
                    fn drop(&mut self) {
                        info!("task is dropped");
                    }
                }

                let _s = S();

                let mut yielded = false;
                poll_fn(|cx| {
                    if yielded {
                        return Poll::Ready(());
                    }

                    yielded = true;
                    cx.waker().wake_by_ref();

                    Poll::Pending
                })
                .await;

                info!("called from task");
            });

            executor.run();
        }

        run_test(test);
    }

    #[test]
    #[should_panic(expected = "all tasks are waiting")]
    fn test_executor_pending() {
        #[instrument]
        fn test() {
            let mut executor = Executor::builder().build();

            let rt = executor.runtime();
            rt.spawn(async {
                info!("called from task");
                pending::<()>().await;
                info!("finished from task");
            });
            rt.spawn(async {
                info!("called from task");
            });

            executor.run();
        }

        run_test(test);
    }
}
