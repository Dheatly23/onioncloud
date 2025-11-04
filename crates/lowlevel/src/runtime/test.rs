mod mpsc;
mod socket;
mod spsc;
mod task;
mod timer;

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::future::Future;
use std::io::Result as IoResult;
use std::mem::take;
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{error, info_span, instrument, trace};

use super::Runtime;
use crate::private::Sealed;

pub use mpsc::*;
pub use socket::*;
pub use spsc::*;
pub use task::*;
pub use timer::*;

/// Test runtime executor.
///
/// Executor for test runtime.
pub struct TestExecutor {
    tasks: task::Tasks,
    rt: TestRuntime,
}

impl Debug for TestExecutor {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("TestExecutor")
    }
}

/// Test runtime.
///
/// It is a custom runtime with single thread.
#[derive(Clone)]
pub struct TestRuntime(Arc<RuntimeInner>);

impl Debug for TestRuntime {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("TestRuntime")
    }
}

#[derive(Default)]
struct RuntimeInner {
    pending: Mutex<Vec<Pin<Box<dyn Send + Future<Output = ()>>>>>,

    timers: timer::Timers,
    sockets: Arc<Mutex<socket::Sockets>>,
}

impl Sealed for TestRuntime {}

impl Runtime for TestRuntime {
    type Task<T: Send> = Handle<T>;
    type Timer = TestTimer;
    type Stream = TestSocket;
    type SPSCSender<T: 'static + Send> = spsc::SPSCPipeSender<T>;
    type SPSCReceiver<T: 'static + Send> = spsc::SPSCPipeReceiver<T>;
    type MPSCSender<T: 'static + Send> = mpsc::MPSCPipeSender<T>;
    type MPSCReceiver<T: 'static + Send> = mpsc::MPSCPipeReceiver<T>;

    fn spawn<F>(&self, fut: F) -> Self::Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (handle, task) = spawn(fut);
        self.0.pending.lock().push(task);

        handle
    }

    fn get_time(&self) -> Instant {
        self.0.timers.current_time()
    }

    fn timer(&self, timeout: Instant) -> Self::Timer {
        self.0.timers.create_timer(Some(timeout))
    }

    fn connect(&self, addrs: &[SocketAddr]) -> impl Future<Output = IoResult<Self::Stream>> + Send {
        socket::SocketConnectFut::from(socket::create_socket(&self.0.sockets, addrs))
    }

    fn spsc_make<T: 'static + Send>(
        &self,
        size: usize,
    ) -> (Self::SPSCSender<T>, Self::SPSCReceiver<T>) {
        spsc::make_spsc_pair(size)
    }

    fn mpsc_make<T: 'static + Send>(
        &self,
        size: usize,
    ) -> (Self::MPSCSender<T>, Self::MPSCReceiver<T>) {
        mpsc::make_mpsc_pair(size)
    }
}

impl Default for TestExecutor {
    fn default() -> Self {
        Self {
            tasks: Default::default(),
            rt: TestRuntime(Default::default()),
        }
    }
}

impl TestExecutor {
    pub fn runtime(&self) -> &TestRuntime {
        &self.rt
    }

    pub fn task_len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_task_finished(&self, ix: usize) -> bool {
        self.tasks.is_task_finished(ix)
    }

    pub fn is_task_awake(&self, ix: usize) -> bool {
        self.tasks.is_task_awake(ix)
    }

    pub fn advance_time(&mut self, delta: Duration) {
        self.rt.0.timers.advance_time(delta);
    }

    pub fn sockets(&mut self) -> impl '_ + DerefMut<Target = Sockets> {
        self.rt.0.sockets.lock()
    }

    #[instrument(skip(self))]
    pub fn run_task(&mut self, ix: usize) -> bool {
        self.rt.0.timers.wake_timers();
        let pending = take(&mut *self.rt.0.pending.lock());
        self.tasks.add_pending(pending);
        self.tasks.run_task(ix)
    }

    #[instrument(skip_all)]
    pub fn run_tasks(&mut self) -> bool {
        self.rt.0.timers.wake_timers();
        let pending = take(&mut *self.rt.0.pending.lock());
        self.tasks.add_pending(pending);
        let ret = self.tasks.run_tasks();
        trace!("run {ret} tasks");
        ret != 0
    }

    #[instrument(skip_all)]
    fn run_tasks_until(&mut self, mut f: impl FnMut(&mut Self, usize) -> bool) {
        let mut i = 0u64;
        loop {
            let _scope = info_span!("loop", i).entered();

            self.rt.0.timers.advance_and_wake_timers();
            let pending = take(&mut *self.rt.0.pending.lock());
            let pending_len = pending.len();
            self.tasks.add_pending(pending);
            let active = self.tasks.task_count();
            let run = self.tasks.run_tasks();
            trace!(pending = pending_len, active, run, "finished loop");
            i = i.wrapping_add(1);

            if f(self, run) {
                return;
            }
        }
    }

    #[instrument(skip_all)]
    pub fn run_tasks_until_finished(&mut self) {
        self.run_tasks_until(|this, run| {
            if run == 0 {
                if this.tasks.is_finished() && this.rt.0.pending.lock().is_empty() {
                    trace!("all tasks finished");
                    true
                } else {
                    error!("runtime deadlocks");
                    panic!("runtime deadlocks");
                }
            } else {
                false
            }
        })
    }

    #[instrument(skip_all)]
    pub fn spawn_blocking(&mut self, fut: impl 'static + Send + Future<Output = ()>) {
        let id = self.tasks.len();
        self.tasks
            .add_pending([Box::pin(fut) as Pin<Box<dyn Send + Future<Output = ()>>>]);

        self.run_tasks_until(|this, run| {
            if run == 0 {
                if this.tasks.is_finished() && this.rt.0.pending.lock().is_empty() {
                    trace!("all tasks finished");
                    true
                } else {
                    error!("runtime deadlocks");
                    panic!("runtime deadlocks");
                }
            } else {
                this.tasks.is_task_finished(id)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::pin::pin;

    use futures_util::{SinkExt as _, StreamExt as _};
    use test_log::test;
    use tracing::info;

    use crate::runtime::Timer;

    #[test]
    #[instrument]
    fn test_task_one() {
        TestExecutor::default().spawn_blocking(async {
            info!("test");
        });
    }

    #[test]
    #[instrument]
    fn test_task_many() {
        let mut exec = TestExecutor::default();

        for i in 0..10 {
            exec.runtime().spawn(async move {
                info!("test {i}");
            });
        }

        exec.run_tasks_until_finished();
    }

    #[test]
    #[instrument]
    fn test_task_many_timed() {
        let mut exec = TestExecutor::default();

        for i in 0..10 {
            for _ in 0..2 {
                let rt = exec.runtime().clone();
                exec.runtime().spawn(async move {
                    rt.timer(rt.get_time() + Duration::from_secs(i)).await;
                    info!("test {i}");
                });
            }
        }

        exec.run_tasks_until_finished();
    }

    #[test]
    #[instrument]
    fn test_task_spsc() {
        let mut exec = TestExecutor::default();

        let rt = exec.runtime();
        let (send, recv) = rt.spsc_make::<u64>(2);
        rt.spawn(async move {
            let mut send = pin!(send);
            for i in 0..10 {
                info!("send {i}");
                send.feed(i).await.unwrap();
            }
            send.close().await.unwrap();
        });

        rt.spawn(async move {
            let mut recv = pin!(recv);
            while let Some(i) = recv.next().await {
                info!("received {i}");
            }
        });

        exec.run_tasks_until_finished();
    }

    #[test]
    #[instrument]
    fn test_task_spsc_delay() {
        let mut exec = TestExecutor::default();

        let rt = exec.runtime();
        let (send, recv) = rt.spsc_make::<u64>(2);
        rt.spawn({
            let rt = rt.clone();
            async move {
                let mut t = rt.get_time();
                let mut timer = pin!(rt.timer(t));
                let mut send = pin!(send);
                for i in 0..10 {
                    info!("send {i}");
                    send.feed(i).await.unwrap();
                    t += Duration::from_secs(2);
                    timer.as_mut().reset(t);
                    timer.as_mut().await;
                }
                send.close().await.unwrap();
            }
        });

        rt.spawn({
            let rt = rt.clone();
            async move {
                let mut t = rt.get_time();
                let mut timer = pin!(rt.timer(t));
                let mut recv = pin!(recv);
                while let Some(i) = recv.next().await {
                    info!("received {i}");
                    t += Duration::from_secs(3);
                    timer.as_mut().reset(t);
                    timer.as_mut().await;
                }
            }
        });

        exec.run_tasks_until_finished();
    }

    #[test]
    #[instrument]
    fn test_task_mpsc() {
        let mut exec = TestExecutor::default();

        let rt = exec.runtime();
        let (send, recv) = rt.mpsc_make::<u64>(3);
        for i in 0..10 {
            let i = i * 10;
            let send = send.clone();
            rt.spawn(async move {
                let mut send = pin!(send);
                for j in 0..10 {
                    let i = i + j;
                    info!("send {i}");
                    send.feed(i).await.unwrap();
                }
                send.close().await.unwrap();
            });
        }
        drop(send);

        rt.spawn(async move {
            let mut recv = pin!(recv);
            while let Some(i) = recv.next().await {
                info!("received {i}");
            }
        });

        exec.run_tasks_until_finished();
    }

    #[test]
    #[instrument]
    fn test_task_mpsc_delay() {
        let mut exec = TestExecutor::default();

        let rt = exec.runtime();
        let (send, recv) = rt.mpsc_make::<u64>(3);
        for i in 0..10 {
            let d = Duration::from_secs(i);
            let i = i as u64 * 10;
            let send = send.clone();
            let rt_ = rt.clone();
            rt.spawn(async move {
                let mut t = rt_.get_time();
                let mut timer = pin!(rt_.timer(t));
                let mut send = pin!(send);
                for j in 0..10 {
                    let i = i + j;
                    info!("send {i}");
                    send.feed(i).await.unwrap();
                    t += d;
                    timer.as_mut().reset(t);
                    timer.as_mut().await;
                }
                send.close().await.unwrap();
            });
        }
        drop(send);

        rt.spawn({
            let rt = rt.clone();
            async move {
                let mut t = rt.get_time();
                let mut timer = pin!(rt.timer(t));
                let mut recv = pin!(recv);
                while let Some(i) = recv.next().await {
                    info!("received {i}");
                    t += Duration::from_secs(3);
                    timer.as_mut().reset(t);
                    timer.as_mut().await;
                }
            }
        });

        exec.run_tasks_until_finished();
    }
}
