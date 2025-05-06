use std::collections::hash_map::{Entry, HashMap, VacantEntry};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::task::{Context, Poll};

use flume::r#async::RecvStream;
use flume::{Receiver, Sender, TryRecvError, TrySendError, bounded};
use futures_core::stream::Stream;
use rand::distr::Uniform;
use rand::prelude::*;

use crate::errors;

/// Circuit data.
///
/// Items of [`CircuitMap`].
#[derive(Debug)]
pub struct Circuit<Cell, Meta> {
    /// Circuit metadata.
    ///
    /// Use this to store specific data for each circuit.
    pub meta: Meta,

    /// Sender for circuit handler.
    send: Sender<Cell>,
}

type MapTy<Cell, Meta> = HashMap<NonZeroU32, Circuit<Cell, Meta>>;
type VacantMapE<'a, Cell, Meta> = VacantEntry<'a, NonZeroU32, Circuit<Cell, Meta>>;

/// Circuit manager.
///
/// Manages circuits, send, and receive cells from it.
/// Used by [`ChannelController`](`super::controller::ChannelController`).
#[derive(Debug)]
pub struct CircuitMap<Cell: 'static, Meta = ()> {
    /// Map data.
    map: MapTy<Cell, Meta>,

    /// Agrregate cell sender.
    send: Sender<Cell>,

    /// Duplicate of stream until we have `RecvStream::receiver`.
    recv: Receiver<Cell>,

    /// Aggregate cell receiver.
    stream: RecvStream<'static, Cell>,

    /// Size of buffer for circuit channel.
    chan_len: usize,
}

impl<Cell, Meta> Default for CircuitMap<Cell, Meta> {
    fn default() -> Self {
        Self::new(256, 256)
    }
}

impl<Cell: 'static, Meta> CircuitMap<Cell, Meta> {
    /// Create new [`CircuitMap`].
    ///
    /// # Parameters
    /// - `circuit_cap` : Size of circuit channels. Should not be zero.
    /// - `aggregate_cap` : Size of aggregate channel. Should not be zero. It's recommended to be bigger than or equal to `circuit_cap`.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::channel::circ_map::CircuitMap;
    /// use onioncloud_lowlevel::cell::Cell;
    ///
    /// let circ_map = CircuitMap::<Cell>::new(16, 16);
    /// ```
    pub fn new(circuit_cap: usize, aggregate_cap: usize) -> Self {
        assert_ne!(circuit_cap, 0, "channel size is zero");
        assert_ne!(aggregate_cap, 0, "channel size is zero");
        let (send, recv) = bounded(aggregate_cap);

        Self {
            map: HashMap::new(),
            send,
            stream: recv.clone().into_stream(),
            recv,
            chan_len: circuit_cap,
        }
    }

    /// Get reference to aggregate sender.
    ///
    /// **NOTE: Do not use the return value to send cells from [`ChannelController`](`super::controller::ChannelController`).**
    /// It will reawake itself and might cause infinite loop.
    pub fn sender(&self) -> &Sender<Cell> {
        &self.send
    }

    /// Get number of circuits.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns [`true`] if there is no open circuit.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Get circuit data.
    pub fn get(&mut self, id: NonZeroU32) -> Option<&mut Circuit<Cell, Meta>> {
        self.map.get_mut(&id)
    }

    /// Check if circuit ID is used.
    pub fn has(&self, id: NonZeroU32) -> bool {
        self.map.contains_key(&id)
    }

    fn insert_entry<'a>(
        entry: VacantMapE<'a, Cell, Meta>,
        send: &Sender<Cell>,
        id: NonZeroU32,
        chan_len: usize,
        meta: Meta,
    ) -> (NewCircuit<Cell>, &'a mut Circuit<Cell, Meta>) {
        let (circ, recv) = Circuit::new(chan_len, meta);
        (NewCircuit::new(id, recv, send.clone()), entry.insert(circ))
    }

    /// Insert new circuit at ID.
    ///
    /// Returns [`None`] if ID is occupied.
    ///
    /// # Parameters
    /// - `id` : Circuit ID. Must be free.
    /// - `meta` : Function to create metadata for the new circuit.
    pub fn insert_with(
        &mut self,
        id: NonZeroU32,
        meta: impl FnOnce() -> Meta,
    ) -> Option<(NewCircuit<Cell>, &mut Circuit<Cell, Meta>)> {
        let Entry::Vacant(e) = self.map.entry(id) else {
            return None;
        };

        Some(Self::insert_entry(e, &self.send, id, self.chan_len, meta()))
    }

    /// Same as [`insert_with`], but with [`Default`] metadata.
    pub fn insert(&mut self, id: NonZeroU32) -> Option<(NewCircuit<Cell>, &mut Circuit<Cell, Meta>)>
    where
        Meta: Default,
    {
        self.insert_with(id, Default::default)
    }

    /// Open a new circuit at random free ID.
    ///
    /// # Parameters
    /// - `set_msb` : Set MSB of ID.
    /// - `id_32bit` : Use 32-bit circuit ID instead of legacy 16-bit circuit ID.
    /// - `n_attempts` : Number of attempts to allocate ID. Tor spec recommends setting it to 64.
    /// - `meta` : Function to create metadata for the new circuit.
    pub fn open_with(
        &mut self,
        set_msb: bool,
        id_32bit: bool,
        n_attempts: usize,
        meta: impl FnOnce(NonZeroU32) -> Meta,
    ) -> Result<(NewCircuit<Cell>, &mut Circuit<Cell, Meta>), errors::NoFreeCircIDError> {
        fn f<Cell, Meta>(
            map: &mut MapTy<Cell, Meta>,
            set_msb: bool,
            id_32bit: bool,
            n_attempts: usize,
        ) -> Result<(NonZeroU32, VacantMapE<'_, Cell, Meta>), errors::NoFreeCircIDError> {
            let d: Uniform<_> = match (set_msb, id_32bit) {
                (true, true) => 0x8000_0000..=0xffff_ffff,
                (false, true) => 1..=0x7fff_ffff,
                (true, false) => 0x8000..=0xffff,
                (false, false) => 1..=0x7fff,
            }
            .try_into()
            .expect("uniform must succeed");

            for id in ThreadRng::default().sample_iter(d).take(n_attempts) {
                let id = NonZeroU32::new(id).expect("ID must be nonzero");

                // SAFETY: Lifetime extension because idk non-lexical lifetime stuff?
                #[allow(clippy::deref_addrof)]
                let map = unsafe { &mut *(&raw mut *map) };

                if let Entry::Vacant(e) = map.entry(id) {
                    return Ok((id, e));
                }
            }

            Err(errors::NoFreeCircIDError)
        }

        f(&mut self.map, set_msb, id_32bit, n_attempts)
            .map(|(id, e)| Self::insert_entry(e, &self.send, id, self.chan_len, meta(id)))
    }

    /// Same as [`open_with`], but with `[Default`] metadata.
    pub fn open(
        &mut self,
        set_msb: bool,
        id_32bit: bool,
        n_attempts: usize,
    ) -> Result<(NewCircuit<Cell>, &mut Circuit<Cell, Meta>), errors::NoFreeCircIDError>
    where
        Meta: Default,
    {
        self.open_with(set_msb, id_32bit, n_attempts, |_| Default::default())
    }

    /// Remove circuit from map.
    pub fn remove(&mut self, id: NonZeroU32) -> Option<Meta> {
        self.map.remove(&id).map(|v| v.meta)
    }

    /// Enumerates all keys.
    pub fn keys(&'_ self) -> impl Iterator<Item = &'_ NonZeroU32> {
        self.map.keys()
    }

    /// Enumerates all items.
    pub fn items(
        &'_ mut self,
    ) -> impl Iterator<Item = (&'_ NonZeroU32, &'_ mut Circuit<Cell, Meta>)> {
        self.map.iter_mut()
    }

    /// Receive cell from aggregate channel.
    ///
    /// **NOTE: Do not call this from [`ChannelController`](`super::controller::ChannelController`).**
    pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Cell>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }

    /// Receive cell from aggregate channel.
    ///
    /// **NOTE: Do not call this from [`ChannelController`](`super::controller::ChannelController`).**
    pub(crate) fn try_recv(&mut self) -> Result<Cell, TryRecvError> {
        self.recv.try_recv()
    }
}

impl<Cell, Meta> Circuit<Cell, Meta> {
    fn new(chan_len: usize, meta: Meta) -> (Self, Receiver<Cell>) {
        let (send, recv) = bounded(chan_len);
        (Self { meta, send }, recv)
    }

    /// Send a cell.
    ///
    /// Returns [`SendError`] if channel is full or closed.
    pub fn send(&self, cell: Cell) -> Result<(), TrySendError<Cell>> {
        self.send.try_send(cell)
    }

    /// Check if circuit has been closed.
    ///
    /// This happens when the corresponding [`Receiver`] is dropped.
    pub fn is_closed(&self) -> bool {
        self.send.is_disconnected()
    }
}

/// Data for new circuit.
///
/// For controller, send it to circuit task handler.
/// Once received, use destructuring let to get all the values.
#[derive(Debug)]
#[non_exhaustive]
pub struct NewCircuit<Cell> {
    /// Circuit ID.
    pub id: NonZeroU32,

    /// Receiver that receives cells from connection.
    pub receiver: Receiver<Cell>,

    /// Sender that sends cells into connection.
    ///
    /// **NOTE: Please set circuit ID of the cells before sending.**
    pub sender: Sender<Cell>,
}

impl<Cell> NewCircuit<Cell> {
    fn new(id: NonZeroU32, receiver: Receiver<Cell>, sender: Sender<Cell>) -> Self {
        Self {
            id,
            receiver,
            sender,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::pin::pin;
    use std::thread::{JoinHandle, spawn};
    use std::time::{Duration, Instant};

    use futures_channel::oneshot::channel;
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio::task::spawn as spawn_async;
    use tokio::time::timeout_at;

    fn join_all(handles: Vec<JoinHandle<()>>) {
        for h in handles {
            h.join().unwrap();
        }
    }

    fn spawn_circuit<'a, C: Send + 'static, M>(
        data: (NewCircuit<C>, &'a mut Circuit<C, M>),
        f: impl FnOnce(NonZeroU32, Receiver<C>, Sender<C>) + Send + 'static,
        handles: &mut Vec<JoinHandle<()>>,
    ) -> &'a mut Circuit<C, M> {
        let (d, r) = data;
        handles.push(spawn(move || f(d.id, d.receiver, d.sender)));
        r
    }

    #[test]
    fn test_send_recv_one() {
        let mut handles = Vec::new();

        let mut map = CircuitMap::<(u32, usize)>::new(8, 8);

        let id = NonZeroU32::new(0xc12af7ed).unwrap();
        let circ = spawn_circuit(
            map.insert(id).unwrap(),
            |id, recv, send| {
                for i in 0..256 {
                    assert_eq!(recv.recv().unwrap(), (id.get(), i));
                }

                for i in 0..256 {
                    send.send((id.get(), i)).unwrap();
                }
            },
            &mut handles,
        );

        for i in 0..256 {
            circ.send.send((id.get(), i)).unwrap();
        }

        for i in 0..256 {
            assert_eq!(map.recv.recv().unwrap(), (id.get(), i));
        }

        join_all(handles);
    }

    #[test]
    fn test_send_recv_many() {
        let mut handles = Vec::new();

        let mut map = CircuitMap::<(u32, usize), usize>::new(8, 8);

        const N_CIRC: u32 = 16;

        for id in 1..=N_CIRC {
            spawn_circuit(
                map.insert(NonZeroU32::new(id).unwrap()).unwrap(),
                |id, recv, send| {
                    for i in 0..256 {
                        assert_eq!(recv.recv().unwrap(), (id.get(), i));
                    }

                    for i in 0..256 {
                        send.send((id.get(), i)).unwrap();
                    }
                },
                &mut handles,
            );
        }

        for i in 0..256 {
            for id in 1..=N_CIRC {
                map.get(NonZeroU32::new(id).unwrap())
                    .unwrap()
                    .send
                    .send((id, i))
                    .unwrap();
            }
        }

        let mut n = 0;
        while n < map.len() {
            let (id, i) = map.recv.recv().unwrap();
            let j = &mut map.get(NonZeroU32::new(id).unwrap()).unwrap().meta;
            assert_eq!(i, *j);

            assert!(*j < 256);
            *j += 1;
            if *j == 256 {
                n += 1;
            }
        }

        join_all(handles);

        for (_, circ) in map.items() {
            assert!(circ.is_closed());
        }
    }

    #[test]
    fn test_send_recv_many_open() {
        let mut handles = Vec::new();

        let mut map = CircuitMap::<(u32, usize), usize>::new(8, 8);

        const N_CIRC: usize = 16;

        for _ in 0..N_CIRC {
            spawn_circuit(
                loop {
                    if let Ok(v) = map.open(false, false, 64) {
                        break v;
                    }
                },
                |id, recv, send| {
                    for i in 0..256 {
                        assert_eq!(recv.recv().unwrap(), (id.get(), i));
                    }

                    for i in 0..256 {
                        send.send((id.get(), i)).unwrap();
                    }
                },
                &mut handles,
            );
        }

        for i in 0..256 {
            for (id, circ) in map.items() {
                circ.send.send((id.get(), i)).unwrap();
            }
        }

        let mut n = 0;
        while n < map.len() {
            let (id, i) = map.recv.recv().unwrap();
            let j = &mut map.get(NonZeroU32::new(id).unwrap()).unwrap().meta;
            assert_eq!(i, *j);

            assert!(*j < 256);
            *j += 1;
            if *j == 256 {
                n += 1;
            }
        }

        join_all(handles);

        for (_, circ) in map.items() {
            assert!(circ.is_closed());
        }
    }

    #[tokio::test]
    async fn test_send_recv_many_open_async() {
        struct TO(Instant);

        impl TO {
            fn timeout<F: Future>(&self, f: F) -> impl use<F> + Future<Output = F::Output> {
                let t = self.0;
                async move { timeout_at(t.into(), f).await.unwrap() }
            }
        }

        let t = TO(Instant::now() + Duration::from_secs(5));
        let mut handles = Vec::new();

        let mut map = CircuitMap::<(u32, u64), (u64, u64, u64)>::new(8, 8);

        const N_CIRC: usize = 16;

        let mut rng = ThreadRng::default();
        for _ in 0..N_CIRC {
            let (a, b): (u64, u64) = rng.random();

            let (send, recv) = channel::<NewCircuit<(u32, u64)>>();
            handles.push(spawn_async(t.timeout(async move {
                let Ok(NewCircuit {
                    sender: send,
                    receiver: recv,
                    id,
                }) = recv.await
                else {
                    return;
                };

                let mut send = pin!(send.sink());
                let mut recv = pin!(recv.stream());
                while let Some((i, j)) = recv.as_mut().next().await {
                    assert_eq!(i, id.get());

                    if send
                        .as_mut()
                        .send((i, j.wrapping_mul(a).wrapping_add(b)))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            })));

            loop {
                if let Ok((data, _)) = map.open_with(false, false, 64, |_| (0, a, b)) {
                    let id = data.id;
                    if send.send(data).is_err() {
                        map.remove(id);
                    }
                    break;
                }
            }
        }

        for (&id, circ) in map.items() {
            let send = circ.send.clone();
            handles.push(spawn_async(t.timeout(async move {
                let mut send = pin!(send.sink());
                for i in 0..256 {
                    send.as_mut().send((id.get(), i)).await.unwrap();
                }
            })));
        }

        while !map.is_empty() {
            let (id, i) = t.timeout(map.recv.recv_async()).await.unwrap();
            let (ref mut j, a, b) = map.get(NonZeroU32::new(id).unwrap()).unwrap().meta;
            assert_eq!(i, j.wrapping_mul(a).wrapping_add(b));

            assert!(*j < 256);
            *j += 1;
            if *j == 256 {
                map.remove(NonZeroU32::new(id).unwrap());
            }
        }

        for h in handles {
            t.timeout(h).await.unwrap();
        }
    }
}
