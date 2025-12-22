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

struct RuntimeInner {
    pending: Mutex<Vec<task::Task>>,

    timers: timer::Timers,
    sockets: Mutex<socket::Sockets>,
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
        let (handle, fut) = spawn(fut);
        self.0
            .pending
            .lock()
            .push(task::Task::with_current_span(fut));

        handle
    }

    fn get_time(&self) -> Instant {
        self.0.timers.current_time()
    }

    fn timer(&self, timeout: Instant) -> Self::Timer {
        self.0.timers.create_timer(Some(timeout))
    }

    async fn connect(&self, addrs: &[SocketAddr]) -> IoResult<Self::Stream> {
        self.0.sockets.lock().create_socket(addrs)
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
            rt: TestRuntime(Arc::new(RuntimeInner {
                pending: Default::default(),
                timers: Default::default(),
                sockets: Mutex::new(socket::Sockets::new()),
            })),
        }
    }
}

impl TestExecutor {
    /// Gets reference to runtime.
    pub fn runtime(&self) -> &TestRuntime {
        &self.rt
    }

    /// Gets the number of tasks (alive or finished).
    pub fn task_len(&self) -> usize {
        self.tasks.len()
    }

    /// Checks if task finished.
    ///
    /// # Parameters
    ///
    /// - `ix` : Index of task. Must be in range of 0 - [`task_len`].
    ///
    /// # Return
    ///
    /// Returns [`true`] if task is finished.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::runtime::Runtime;
    /// use onioncloud_lowlevel::runtime::test::TestExecutor;
    ///
    /// let mut exec = TestExecutor::default();
    ///
    /// // Task is not yet registered
    /// exec.runtime().spawn(async { println!("test") });
    /// assert_eq!(exec.task_len(), 0);
    ///
    /// // Task is registered but not yet running
    /// exec.register_pending_tasks();
    /// assert_eq!(exec.task_len(), 1);
    /// assert!(!exec.is_task_finished(0));
    ///
    /// // Task is finished
    /// exec.run_tasks();
    /// assert!(exec.is_task_finished(0));
    /// ```
    pub fn is_task_finished(&self, ix: usize) -> bool {
        self.tasks.is_task_finished(ix)
    }

    /// Checks if task is woken.
    ///
    /// # Parameters
    ///
    /// - `ix` : Index of task. Must be in range of 0 - [`task_len`].
    ///
    /// # Return
    ///
    /// Returns [`true`] if task is awake and will be run.
    pub fn is_task_awake(&self, ix: usize) -> bool {
        self.tasks.is_task_awake(ix)
    }

    /// Advance time.
    ///
    /// # Parameters
    ///
    /// - `delta` : Duration to advance time by.
    pub fn advance_time(&mut self, delta: Duration) {
        self.rt.0.timers.advance_time(delta);
    }

    /// Gets reference to [`Sockets`].
    pub fn sockets(&mut self) -> impl '_ + DerefMut<Target = Sockets> {
        self.rt.0.sockets.lock()
    }

    /// Registers pending tasks.
    ///
    /// # Return
    ///
    /// Returns number of pending tasks.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::runtime::Runtime;
    /// use onioncloud_lowlevel::runtime::test::TestExecutor;
    ///
    /// let mut exec = TestExecutor::default();
    ///
    /// exec.runtime().spawn(async { println!("test") });
    /// assert_eq!(exec.task_len(), 0);
    /// exec.register_pending_tasks();
    /// assert_eq!(exec.task_len(), 1);
    /// ```
    pub fn register_pending_tasks(&mut self) -> usize {
        let pending = take(&mut *self.rt.0.pending.lock());
        let len = pending.len();
        self.tasks.add_pending(pending);
        len
    }

    /// Run a single task.
    ///
    /// # Parameters
    ///
    /// - `ix` : Index of task. Must be in range of 0 - [`task_len`].
    ///
    /// # Return
    ///
    /// Returns [`true`] if task is ran.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::runtime::Runtime;
    /// use onioncloud_lowlevel::runtime::test::TestExecutor;
    ///
    /// let mut exec = TestExecutor::default();
    ///
    /// exec.runtime().spawn(async { println!("test") });
    /// exec.register_pending_tasks();
    /// assert!(exec.run_task(0));
    /// ```
    #[instrument(skip(self))]
    pub fn run_task(&mut self, ix: usize) -> bool {
        self.rt.0.timers.wake_timers();
        self.register_pending_tasks();
        self.tasks.run_task(ix)
    }

    /// Run tasks. Emulates a single event loop step.
    ///
    /// # Return
    ///
    /// Returns [`true`] if any task is ran.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::runtime::Runtime;
    /// use onioncloud_lowlevel::runtime::test::TestExecutor;
    ///
    /// let mut exec = TestExecutor::default();
    ///
    /// exec.runtime().spawn(async { println!("test") });
    /// assert!(exec.run_tasks());
    /// assert!(!exec.run_tasks());
    /// ```
    #[instrument(skip_all)]
    pub fn run_tasks(&mut self) -> bool {
        self.rt.0.timers.wake_timers();
        self.register_pending_tasks();
        self.sockets().handle_all();
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
            let pending = self.register_pending_tasks();
            let active = self.tasks.task_count();
            self.sockets().handle_all();
            let run = self.tasks.run_tasks();
            trace!(pending, active, run, "finished loop");
            i = i.wrapping_add(1);

            if f(self, run) {
                return;
            }
        }
    }

    /// Run tasks until all tasks finished.
    ///
    /// # Panic
    ///
    /// Panics if tasks deadlocks (no task can make progress).
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::runtime::Runtime;
    /// use onioncloud_lowlevel::runtime::test::TestExecutor;
    ///
    /// let mut exec = TestExecutor::default();
    ///
    /// for i in 0..10 {
    ///     exec.runtime().spawn(async move { println!("test {i}") });
    /// }
    /// exec.run_tasks_until_finished();
    /// ```
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

    /// Spawns a task and run it until it finished.
    ///
    /// # Panic
    ///
    /// Panics if tasks deadlocks (no task can make progress).
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::runtime::Runtime;
    /// use onioncloud_lowlevel::runtime::test::TestExecutor;
    ///
    /// TestExecutor::default().spawn_blocking(async { println!("test") });
    /// ```
    #[instrument(skip_all)]
    pub fn spawn_blocking(&mut self, fut: impl 'static + Send + Future<Output = ()>) {
        let id = self.tasks.len();
        self.tasks
            .add_pending([task::Task::with_current_span(Box::pin(fut))]);

        self.run_tasks_until(|this, run| {
            if run == 0 {
                if this.tasks.is_finished() && this.rt.0.pending.lock().is_empty() {
                    trace!("all tasks finished");
                    true
                } else {
                    error!("runtime deadlocks");

                    for i in 0..this.tasks.len() {
                        if !this.tasks.is_task_finished(i) {
                            error!("task {i} deadlocks");
                        }
                    }

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

    use std::io::ErrorKind;
    use std::pin::pin;

    use futures_util::{AsyncReadExt as _, AsyncWriteExt as _, SinkExt as _, StreamExt as _};
    use rand::prelude::*;
    use test_log::test;
    use tracing::info;

    use crate::runtime::Timer;
    use crate::util::print_bytes;

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
    fn test_task_handle() {
        let mut exec = TestExecutor::default();

        let rt = exec.runtime().clone();
        exec.runtime().spawn(async move {
            let (send, recv) = rt.spsc_make::<u64>(2);
            let handle = rt.spawn(async move {
                let mut acc = 0;
                let mut recv = pin!(recv);
                while let Some(i) = recv.next().await {
                    info!("received {i}");
                    acc += i;
                }
                acc
            });

            let mut acc = 0;
            let mut send = pin!(send);
            for i in 0..10 {
                info!("send {i}");
                send.feed(i).await.unwrap();
                acc += i;
            }
            send.close().await.unwrap();

            assert_eq!(acc, handle.await);
        });

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

    #[test]
    #[instrument]
    fn test_task_net_simple() {
        let mut exec = TestExecutor::default();

        static HOST_TO_STREAM: &[u8] = b"hello from host";
        static STREAM_TO_HOST: &[u8] = b"hello from stream";

        exec.sockets().set_handle(Box::new(|a| {
            let a = *a
                .iter()
                .find(|a| a.ip().is_loopback() && a.port() == 80)
                .ok_or(ErrorKind::NotFound)?;
            Ok(OpenSocket::new(
                a,
                Box::new(|h| {
                    if h.is_recv_closed() {
                        let v = h.recv_stream();
                        let (a, b) = v.as_slices();
                        info!("host received \"{}{}\"", print_bytes(a), print_bytes(b));
                        assert_eq!(v, &STREAM_TO_HOST);
                        v.clear();
                    }

                    Ok(())
                }),
            )
            .with_send(HOST_TO_STREAM.iter().copied().collect())
            .with_send_eof(true))
        }));

        let rt = exec.runtime();
        rt.spawn({
            let rt = rt.clone();
            async move {
                let mut socket = pin!(rt.connect(&[([127, 0, 0, 1], 80).into()]).await.unwrap());

                {
                    let mut v = Vec::new();
                    socket.read_to_end(&mut v).await.unwrap();
                    info!("task received \"{}\"", print_bytes(&v));
                    assert_eq!(v, HOST_TO_STREAM);
                }

                socket.write_all(STREAM_TO_HOST).await.unwrap();
                socket.close().await.unwrap();
                info!("finished");
            }
        });

        exec.run_tasks_until_finished();
    }

    #[test]
    #[instrument]
    fn test_task_net_ping_pong() {
        let mut exec = TestExecutor::default();

        exec.sockets().set_handle(Box::new(|a| {
            let a = *a
                .iter()
                .find(|a| a.ip().is_loopback() && a.port() == 80)
                .ok_or(ErrorKind::NotFound)?;

            let mut v = Vec::new();
            Ok(OpenSocket::new(
                a,
                Box::new(move |h| {
                    let (a, b) = h.recv_stream().as_slices();
                    v.clear();
                    v.extend_from_slice(a);
                    v.extend_from_slice(b);
                    h.recv_stream().clear();
                    if !v.is_empty() {
                        info!("host received \"{}\"", print_bytes(&v));
                        h.send_stream().extend(&v);
                    }

                    if !v.is_empty() {
                        h.wake_send();
                    }
                    if h.is_recv_closed() {
                        h.close_send();
                        h.wake_send();
                    }

                    Ok(())
                }),
            ))
        }));

        let rt = exec.runtime();
        for t in 0..10 {
            rt.spawn({
                let rt = rt.clone();
                async move {
                    let mut socket =
                        pin!(rt.connect(&[([127, 0, 0, 1], 80).into()]).await.unwrap());

                    let mut v = Vec::new();
                    for _ in 0..10 {
                        let t_ =
                            rt.get_time() + Duration::from_secs(thread_rng().gen_range(1..=30));
                        rt.timer(t_).await;

                        let s = format!("item #{:016x} in task {t}", random::<u64>()).into_bytes();
                        socket.write_all(&s).await.unwrap();
                        socket.flush().await.unwrap();
                        info!("sent bytes");

                        v.resize(s.len(), 0);
                        socket.read_exact(&mut v).await.unwrap();
                        info!("task received \"{}\"", print_bytes(&v));
                        assert_eq!(v, s);
                    }

                    socket.close().await.unwrap();
                    v.clear();
                    socket.read_to_end(&mut v).await.unwrap();
                    assert_eq!(v.len(), 0);
                    info!("finished");
                }
            });
        }

        exec.run_tasks_until_finished();
    }
}
