#![no_main]

use std::assert_matches;
use std::cell::Cell;
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::num::NonZeroU16;
use std::pin::{Pin, pin};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use onioncloud_tart::mpsc::{Receiver, Sender, make_channel};
use onioncloud_tart::rt::{Executor, Runtime};
use onioncloud_tart::timer::Timer;
use pin_project::pin_project;

thread_local! {
    pub(crate) static NEW_CNT: Cell<usize> = Cell::new(0);
    pub(crate) static DROP_CNT: Cell<usize> = Cell::new(0);
}

pub(crate) fn reset() {
    NEW_CNT.set(0);
    DROP_CNT.set(0);
}

#[derive(Debug, PartialEq, Eq)]
struct Item(u64);

impl Item {
    fn new(v: u64) -> Self {
        NEW_CNT.with(|v| v.set(v.get() + 1));
        Self(v)
    }
}

impl Drop for Item {
    fn drop(&mut self) {
        DROP_CNT.with(|v| v.set(v.get() + 1));
    }
}

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

#[derive(Debug, Arbitrary)]
enum TaskActionSend {
    PollReady,
    Send(u64),
    WaitReady,
    WaitFlush,
    Close,
    WaitDuration(u64),
}

#[pin_project]
struct SendTask {
    rt: Runtime,
    index: usize,
    #[pin]
    send: Sender<(usize, Item)>,
    closed: bool,
}

impl SendTask {
    async fn run_action(self: Pin<&mut Self>, task: TaskActionSend) {
        match task {
            TaskActionSend::PollReady => Yield::default().await,
            TaskActionSend::Send(v) => {
                let mut this = self.project();
                let fut = this.send.feed((*this.index, Item::new(v)));
                if *this.closed {
                    fut.await.unwrap_err();
                } else if fut.await.is_err() {
                    *this.closed = true;
                }
            }
            TaskActionSend::WaitReady => {
                let mut this = self.project();
                let fut = poll_fn(|cx| this.send.as_mut().poll_ready_unpin(cx));
                if *this.closed {
                    fut.await.unwrap_err();
                } else if fut.await.is_err() {
                    *this.closed = true;
                }
            }
            TaskActionSend::WaitFlush => {
                let mut this = self.project();
                let fut = this.send.flush();
                if *this.closed {
                    fut.await.unwrap_err();
                } else if fut.await.is_err() {
                    *this.closed = true;
                }
            }
            TaskActionSend::Close => {
                let mut this = self.project();
                this.send.close().await.unwrap();
                *this.closed = true;
            }
            TaskActionSend::WaitDuration(dur) => {
                Timer::with_duration(self.rt.clone(), Duration::from_nanos(dur)).await
            }
        }
    }
}

#[derive(Debug, Arbitrary)]
enum TaskActionRecv {
    PollReady,
    Recv,
    WaitDuration(u64),
}

#[pin_project]
struct RecvTask {
    rt: Runtime,
    #[pin]
    recv: Receiver<(usize, Item)>,
    expect: Vec<VecDeque<u64>>,
}

impl RecvTask {
    async fn run_action(self: Pin<&mut Self>, task: TaskActionRecv) {
        match task {
            TaskActionRecv::PollReady => Yield::default().await,
            TaskActionRecv::Recv => {
                let mut this = self.project();
                let ret = this.recv.next().await;
                if let Some((index, ref ret)) = ret {
                    let expect = this.expect[index].pop_front();
                    assert_eq!(Some(ret.0), expect, "mismatch at index {index}");
                }
                assert_matches!(
                    (ret, this.recv.is_disconnected()),
                    (Some(_), _) | (None, true)
                );
            }
            TaskActionRecv::WaitDuration(dur) => {
                Timer::with_duration(self.rt.clone(), Duration::from_nanos(dur)).await
            }
        }
    }
}

#[derive(Debug, Arbitrary)]
struct TaskActionPair {
    size: NonZeroU16,
    send: Vec<Vec<TaskActionSend>>,
    recv: Vec<TaskActionRecv>,
}

impl TaskActionPair {
    fn make_tasks(
        self,
        rt: Runtime,
    ) -> (
        impl Iterator<Item = (SendTask, Vec<TaskActionSend>)>,
        RecvTask,
        Vec<TaskActionRecv>,
    ) {
        let (send, recv) = make_channel(u16::from(self.size).into());

        let mut expect = Vec::new();
        for a in self.send.iter() {
            let mut v = VecDeque::new();
            for t in a.iter() {
                match *t {
                    TaskActionSend::Send(i) => v.push_back(i),
                    TaskActionSend::Close => break,
                    _ => (),
                }
            }
            expect.push(v);
        }

        let rt_ = rt.clone();

        (
            self.send.into_iter().enumerate().map(move |(i, t)| {
                (
                    SendTask {
                        rt: rt_.clone(),
                        index: i,
                        send: send.clone(),
                        closed: false,
                    },
                    t,
                )
            }),
            RecvTask { rt, recv, expect },
            self.recv,
        )
    }
}

fuzz_target!(|tasks_actions: Vec<TaskActionPair>| {
    reset();

    let mut executor = Executor::builder().build();

    let rt = executor.runtime();
    for task in tasks_actions {
        let (send, recv_task, recv_actions) = task.make_tasks(rt.clone());
        for (task, actions) in send {
            rt.spawn(async move {
                let mut t = pin!(task);
                for a in actions {
                    t.as_mut().run_action(a).await
                }
            });
        }
        rt.spawn(async move {
            let mut t = pin!(recv_task);
            for a in recv_actions {
                t.as_mut().run_action(a).await
            }
        });
    }

    executor.run();

    assert_eq!(
        NEW_CNT.get(),
        DROP_CNT.get(),
        "item creation and drop is not equal"
    );
});
