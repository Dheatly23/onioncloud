use std::collections::hash_map::{Entry, HashMap, VacantEntry};
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::hash::Hash;
use std::marker::PhantomData;
use std::num::{NonZeroU16, NonZeroU32};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::stream::Stream;
use futures_sink::Sink;
use pin_project::pin_project;
use rand::prelude::*;

use crate::cell::dispatch::WithCellConfig;
use crate::errors::NoFreeCircIDError;
use crate::runtime::{PipeSender, Runtime, SendError, TrySendError};

#[derive(Debug)]
enum SendState {
    Start,
    Ready,
    Waiting,
    Closing,
    Closed,
}

/// Handler data of [`CellMap`].
#[pin_project]
pub struct HandlerData<R: Runtime, Cell: 'static + Send, Meta> {
    /// Metadata.
    meta: Option<Meta>,

    /// Sender for cell handler.
    #[pin]
    send: R::SPSCSender<Cell>,

    /// Send state flag.
    send_state: SendState,
}

impl<R: Runtime, Cell: 'static + Send, Meta: Debug> Debug for HandlerData<R, Cell, Meta> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("HandlerData")
            .field("meta", &self.meta)
            .field("send_state", &self.send_state)
            .finish_non_exhaustive()
    }
}

type MapTy<K, R, Cell, Meta> = HashMap<K, Pin<Box<HandlerData<R, Cell, Meta>>>>;
type VacantMapE<'a, K, R, Cell, Meta> = VacantEntry<'a, K, Pin<Box<HandlerData<R, Cell, Meta>>>>;

/// Cell stream manager.
///
/// Manages handlers, send, and receive cells from it.
/// Used by [`ChannelController`](`crate::channel::controller::ChannelController`) and [`CircuitController`](`crate::circuit::controller::CircuitController`).
#[pin_project]
#[derive(Debug)]
pub struct CellMap<K: Hash + Eq, R: Runtime, Cell: 'static + Send, Meta = ()> {
    /// Map data.
    map: MapTy<K, R, Cell, Meta>,

    /// Agrregate cell sender.
    #[pin]
    send: R::MPSCSender<Cell>,

    /// Aggregate cell receiver.
    #[pin]
    recv: R::MPSCReceiver<Cell>,

    /// Size of buffer for handler channel.
    chan_len: usize,
}

impl<K: Hash + Eq, R: Runtime, Cell: 'static + Send, Meta> CellMap<K, R, Cell, Meta> {
    /// Create new [`CellMap`].
    ///
    /// # Parameters
    /// - `runtime` : Reference to runtime.
    /// - `handler_cap` : Size of handler channels. Should not be zero.
    /// - `aggregate_cap` : Size of aggregate channel. Should not be zero. It's recommended to be bigger than or equal to `handler_cap`.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::util::cell_map::CellMap;
    /// use onioncloud_lowlevel::cell::Cell;
    ///
    /// let circ_map = CellMap::<Cell>::new(16, 16);
    /// ```
    pub fn new(runtime: &R, handler_cap: usize, aggregate_cap: usize) -> Self {
        assert_ne!(handler_cap, 0, "handler channel size is zero");
        assert_ne!(aggregate_cap, 0, "aggregate channel size is zero");
        let (send, recv) = runtime.mpsc_make(aggregate_cap);

        Self {
            map: HashMap::new(),
            send,
            recv,
            chan_len: handler_cap,
        }
    }

    /// Get reference to aggregate sender.
    ///
    /// **NOTE: Do not use the return value to send cells from inside of controller.
    /// It will reawake itself and might cause infinite loop.**
    pub fn sender(&self) -> &R::MPSCSender<Cell> {
        &self.send
    }

    /// Get number of handlers.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns [`true`] if there is no handler.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Get handler data.
    pub fn get(self: Pin<&mut Self>, id: &K) -> Option<Pin<&mut HandlerData<R, Cell, Meta>>> {
        self.project().map.get_mut(id).map(|p| p.as_mut())
    }

    /// Check if ID is used.
    pub fn has(&self, id: &K) -> bool {
        self.map.contains_key(id)
    }

    fn insert_entry<'a>(
        rt: &R,
        entry: VacantMapE<'a, K, R, Cell, Meta>,
        send: &R::MPSCSender<Cell>,
        chan_len: usize,
        meta: Meta,
    ) -> (
        NewHandler<K, R, Cell>,
        Pin<&'a mut HandlerData<R, Cell, Meta>>,
    )
    where
        K: Clone,
    {
        let (circ, recv) = HandlerData::new(rt, chan_len, meta);
        (
            NewHandler::new(entry.key().clone(), recv, send.clone()),
            entry.insert(Box::pin(circ)).as_mut(),
        )
    }

    /// Insert new handler at ID.
    ///
    /// Returns [`None`] if ID is occupied.
    ///
    /// # Parameters
    /// - `id` : ID. Must be free.
    /// - `meta` : Function to create metadata for the new handler.
    pub fn insert_with(
        self: Pin<&'_ mut Self>,
        rt: &R,
        id: K,
        meta: impl FnOnce() -> Meta,
    ) -> Option<(
        NewHandler<K, R, Cell>,
        Pin<&'_ mut HandlerData<R, Cell, Meta>>,
    )>
    where
        K: Clone,
    {
        let this = self.project();
        let Entry::Vacant(e) = this.map.entry(id) else {
            return None;
        };

        Some(Self::insert_entry(
            rt,
            e,
            &this.send,
            *this.chan_len,
            meta(),
        ))
    }

    /// Same as [`insert_with`], but with [`Default`] metadata.
    #[inline(always)]
    pub fn insert(
        self: Pin<&'_ mut Self>,
        rt: &R,
        id: K,
    ) -> Option<(
        NewHandler<K, R, Cell>,
        Pin<&'_ mut HandlerData<R, Cell, Meta>>,
    )>
    where
        K: Clone,
        Meta: Default,
    {
        self.insert_with(rt, id, Default::default)
    }

    /// Open a new handler at random free ID.
    ///
    /// # Parameters
    /// - `id_gen` : ID generator used.
    /// - `n_attempts` : Number of attempts to allocate ID. Tor spec recommends setting it to 64.
    /// - `meta` : Function to create metadata for the new handler.
    pub fn open_with<G: IDGenerator<K>>(
        self: Pin<&'_ mut Self>,
        rt: &R,
        id_gen: G,
        n_attempts: usize,
        meta: impl FnOnce(&K) -> Meta,
    ) -> Result<
        (
            NewHandler<K, R, Cell>,
            Pin<&'_ mut HandlerData<R, Cell, Meta>>,
        ),
        NoFreeCircIDError,
    >
    where
        K: Clone,
    {
        let this = self.project();
        let mut rng = ThreadRng::default();
        let mut n = n_attempts;

        while let Some(id) = id_gen.generate_id(&mut rng, NAttempts(&mut n)) {
            // SAFETY: Lifetime extension because idk non-lexical lifetime stuff?
            #[allow(clippy::deref_addrof)]
            let map = unsafe { &mut *(&raw mut *this.map) };

            if let Entry::Vacant(e) = map.entry(id) {
                let meta = meta(e.key());
                return Ok(Self::insert_entry(rt, e, &this.send, *this.chan_len, meta));
            }
        }

        Err(NoFreeCircIDError)
    }

    /// Same as [`open_with`], but with `[Default`] metadata.
    #[inline]
    pub fn open<G: IDGenerator<K>>(
        self: Pin<&'_ mut Self>,
        rt: &R,
        id_gen: G,
        n_attempts: usize,
    ) -> Result<
        (
            NewHandler<K, R, Cell>,
            Pin<&'_ mut HandlerData<R, Cell, Meta>>,
        ),
        NoFreeCircIDError,
    >
    where
        K: Clone,
        Meta: Default,
    {
        fn f<K, T: Default>(_: &K) -> T {
            T::default()
        }

        self.open_with(rt, id_gen, n_attempts, f)
    }

    /// Remove handler from map.
    pub fn remove(self: Pin<&mut Self>, id: &K) -> Option<Meta> {
        // SAFETY: Meta is always Some.
        self.project()
            .map
            .remove(id)
            .map(|mut v| unsafe { v.as_mut().project().meta.take().unwrap_unchecked() })
    }

    /// Enumerates all keys.
    pub fn keys(&'_ self) -> impl Iterator<Item = &'_ K> {
        self.map.keys()
    }

    /// Enumerates all items.
    pub fn items(
        self: Pin<&'_ mut Self>,
    ) -> impl Iterator<Item = (&'_ K, Pin<&'_ mut HandlerData<R, Cell, Meta>>)> {
        self.project().map.iter_mut().map(|(k, v)| (k, v.as_mut()))
    }

    /// Retains only items that satisfies predicate.
    pub fn retain(
        self: Pin<&'_ mut Self>,
        mut pred: impl FnMut(&K, Pin<&'_ mut HandlerData<R, Cell, Meta>>) -> bool,
    ) {
        self.project().map.retain(|k, v| pred(k, v.as_mut()));
    }

    /// Receive cell from aggregate channel.
    ///
    /// **NOTE: Do not call this from inside of controller.**
    pub fn poll_recv(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Cell>> {
        self.project().recv.poll_next(cx)
    }
}

impl<R: Runtime, Cell: 'static + Send, Meta> HandlerData<R, Cell, Meta> {
    fn new(rt: &R, chan_len: usize, meta: Meta) -> (Self, R::SPSCReceiver<Cell>) {
        let (send, recv) = rt.spsc_make(chan_len);
        (
            Self {
                meta: Some(meta),
                send,
                send_state: SendState::Start,
            },
            recv,
        )
    }

    pub(crate) fn is_pollable(&self) -> bool {
        !matches!(self.send_state, SendState::Closed)
    }

    /// Gets reference to metadata.
    pub fn meta(self: Pin<&mut Self>) -> &mut Meta {
        // SAFETY: Meta is always Some.
        unsafe { self.project().meta.as_mut().unwrap_unchecked() }
    }

    /// Polls sender to be ready for data.
    ///
    /// Returns [`SendError`] if channel is closed.
    pub fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), SendError<Cell>>> {
        let this = self.project();
        let ret;
        match this.send_state {
            SendState::Ready | SendState::Closed => ret = Poll::Ready(Ok(())),
            SendState::Closing => {
                ret = this.send.poll_close(cx);
                if ret.is_ready() {
                    *this.send_state = SendState::Closed;
                }
            }
            _ => {
                ret = this.send.poll_flush(cx);
                *this.send_state = match ret {
                    Poll::Ready(Ok(_)) => SendState::Ready,
                    Poll::Ready(Err(_)) => SendState::Closed,
                    Poll::Pending => SendState::Waiting,
                };
            }
        }

        ret
    }

    /// Starts sending data into sender.
    ///
    /// Returns [`SendError`] if channel is closed.
    ///
    /// **⚠NOTE: Do not call this until [`poll_ready`] returns [`Ok`]!**
    pub fn start_send(self: Pin<&mut Self>, item: Cell) -> Result<(), SendError<Cell>> {
        let this = self.project();
        if matches!(this.send_state, SendState::Closed) {
            return Err(SendError(item));
        }
        debug_assert!(
            matches!(this.send_state, SendState::Ready),
            "poll_ready() is not ready yet"
        );

        let ret = this.send.start_send(item);
        *this.send_state = match &ret {
            Ok(_) => SendState::Waiting,
            Err(_) => SendState::Closed,
        };
        ret
    }

    /// Starts closing sender.
    pub fn start_close(self: Pin<&mut Self>) {
        let state = self.project().send_state;
        if !matches!(state, SendState::Closed) {
            *state = SendState::Closing;
        }
    }

    /// Check if handler has been closed.
    ///
    /// This happens when the corresponding receiver is dropped.
    pub fn is_closed(&self) -> bool {
        self.send.is_disconnected()
    }
}

/// Reference to [`CellMap`].
pub struct CellMapRef<'a, 'b, K: Hash + Eq, R: Runtime, Cell: 'static + Send, Meta> {
    inner: Pin<&'a mut CellMap<K, R, Cell, Meta>>,
    cx: &'a mut Context<'b>,
    is_any_close: &'a mut bool,
}

impl<'a, 'b, K: Hash + Eq, R: Runtime, Cell: 'static + Send, Meta>
    CellMapRef<'a, 'b, K, R, Cell, Meta>
{
    pub(crate) fn new(
        inner: Pin<&'a mut CellMap<K, R, Cell, Meta>>,
        cx: &'a mut Context<'b>,
        is_any_close: &'a mut bool,
    ) -> Self {
        Self {
            inner,
            cx,
            is_any_close,
        }
    }

    /// Reborrow reference.
    #[inline(always)]
    pub fn reborrow(&'_ mut self) -> CellMapRef<'_, 'b, K, R, Cell, Meta> {
        CellMapRef::new(self.inner.as_mut(), self.cx, self.is_any_close)
    }

    /// Get number of handlers.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns [`true`] if there is no handler.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get handler data.
    pub fn get(&'_ mut self, id: &K) -> Option<HandleRef<'_, 'b, R, Cell, Meta>> {
        self.inner
            .as_mut()
            .get(id)
            .map(|p| HandleRef::new(p, self.cx, self.is_any_close))
    }

    /// Check if ID is used.
    #[inline(always)]
    pub fn has(&self, id: &K) -> bool {
        self.inner.has(id)
    }

    /// Insert new handler at ID.
    ///
    /// Returns [`None`] if ID is occupied.
    ///
    /// # Parameters
    /// - `id` : ID. Must be free.
    /// - `meta` : Function to create metadata for the new handler.
    pub fn insert_with(
        &'_ mut self,
        rt: &R,
        id: K,
        meta: impl FnOnce() -> Meta,
    ) -> Option<(NewHandler<K, R, Cell>, HandleRef<'_, 'b, R, Cell, Meta>)>
    where
        K: Clone,
    {
        self.inner
            .as_mut()
            .insert_with(rt, id, meta)
            .map(|(a, b)| (a, HandleRef::new(b, self.cx, self.is_any_close)))
    }

    /// Same as [`insert_with`], but with [`Default`] metadata.
    #[inline(always)]
    pub fn insert(
        &'_ mut self,
        rt: &R,
        id: K,
    ) -> Option<(NewHandler<K, R, Cell>, HandleRef<'_, 'b, R, Cell, Meta>)>
    where
        K: Clone,
        Meta: Default,
    {
        self.inner
            .as_mut()
            .insert(rt, id)
            .map(|(a, b)| (a, HandleRef::new(b, self.cx, self.is_any_close)))
    }

    /// Open a new handler at random free ID.
    ///
    /// # Parameters
    /// - `id_gen` : ID generator used.
    /// - `n_attempts` : Number of attempts to allocate ID. Tor spec recommends setting it to 64.
    /// - `meta` : Function to create metadata for the new handler.
    pub fn open_with<G: IDGenerator<K>>(
        &'_ mut self,
        rt: &R,
        id_gen: G,
        n_attempts: usize,
        meta: impl FnOnce(&K) -> Meta,
    ) -> Result<(NewHandler<K, R, Cell>, HandleRef<'_, 'b, R, Cell, Meta>), NoFreeCircIDError>
    where
        K: Clone,
    {
        self.inner
            .as_mut()
            .open_with(rt, id_gen, n_attempts, meta)
            .map(|(a, b)| (a, HandleRef::new(b, self.cx, self.is_any_close)))
    }

    /// Same as [`open_with`], but with `[Default`] metadata.
    #[inline]
    pub fn open<G: IDGenerator<K>>(
        &'_ mut self,
        rt: &R,
        id_gen: G,
        n_attempts: usize,
    ) -> Result<(NewHandler<K, R, Cell>, HandleRef<'_, 'b, R, Cell, Meta>), NoFreeCircIDError>
    where
        K: Clone,
        Meta: Default,
    {
        self.inner
            .as_mut()
            .open(rt, id_gen, n_attempts)
            .map(|(a, b)| (a, HandleRef::new(b, self.cx, self.is_any_close)))
    }

    /// Remove handler from map.
    pub fn remove(&mut self, id: &K) -> Option<Meta> {
        self.inner.as_mut().remove(id)
    }

    /// Enumerates all keys.
    pub fn keys(&'_ self) -> impl Iterator<Item = &'_ K> {
        self.inner.keys()
    }
}

/// Reference to [`HandlerData`].
pub struct HandleRef<'a, 'b, R: Runtime, Cell: 'static + Send, Meta> {
    inner: Pin<&'a mut HandlerData<R, Cell, Meta>>,
    cx: &'a mut Context<'b>,
    is_any_close: &'a mut bool,
}

impl<'a, 'b, R: Runtime, Cell: 'static + Send, Meta> HandleRef<'a, 'b, R, Cell, Meta> {
    fn new(
        inner: Pin<&'a mut HandlerData<R, Cell, Meta>>,
        cx: &'a mut Context<'b>,
        is_any_close: &'a mut bool,
    ) -> Self {
        Self {
            inner,
            cx,
            is_any_close,
        }
    }

    /// Reborrow reference.
    #[inline(always)]
    pub fn reborrow(&'_ mut self) -> HandleRef<'_, 'b, R, Cell, Meta> {
        HandleRef::new(self.inner.as_mut(), self.cx, self.is_any_close)
    }

    /// Gets reference to metadata.
    #[inline(always)]
    pub fn meta(&mut self) -> &mut Meta {
        self.inner.as_mut().meta()
    }

    /// Checks if handle is closed.
    pub fn is_closed(&self) -> bool {
        matches!(self.inner.send_state, SendState::Closed)
    }

    /// Checks if handle is closing.
    pub fn is_closing(&self) -> bool {
        matches!(
            self.inner.send_state,
            SendState::Closed | SendState::Closing
        )
    }

    /// Checks if handle is flushed and ready to send item.
    ///
    /// It is guaranteed if it returns [`true`] then [`try_send`] will not return [`TrySendError::NotReady`].
    /// (It might return [`TrySendError::Disconnected`]).
    pub fn is_ready(&mut self) -> bool {
        match self.inner.send_state {
            SendState::Start => match self.inner.as_mut().poll_ready(self.cx) {
                Poll::Ready(Ok(())) => true,
                Poll::Pending => false,
                // Should be impossible because SendError contains value that the channel does not know how to construct it
                Poll::Ready(Err(_)) => {
                    unreachable!("channel at starting state cannot return SendError")
                }
            },
            SendState::Ready | SendState::Closed => true,
            _ => false,
        }
    }

    /// Try to send value.
    ///
    /// Returns [`TrySendError`] if channel is not ready or disconnected.
    pub fn try_send(&mut self, item: Cell) -> Result<(), TrySendError<Cell>> {
        loop {
            break match &self.inner.send_state {
                SendState::Start => match self.inner.as_mut().poll_ready(self.cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Pending => Err(TrySendError::NotReady(item)),
                    // Should be impossible because SendError contains value that the channel does not know how to construct it
                    Poll::Ready(Err(_)) => {
                        unreachable!("channel at starting state cannot return SendError")
                    }
                },
                SendState::Waiting => Err(TrySendError::NotReady(item)),
                SendState::Closed => Err(TrySendError::Disconnected(item)),
                SendState::Closing => Err(match self.inner.as_mut().poll_ready(self.cx) {
                    Poll::Pending => TrySendError::NotReady(item),
                    Poll::Ready(Ok(())) => {
                        *self.is_any_close = true;
                        TrySendError::Disconnected(item)
                    }
                    Poll::Ready(Err(e)) => {
                        *self.is_any_close = true;
                        e.into()
                    }
                }),
                SendState::Ready => match self.inner.as_mut().start_send(item).and_then(|_| {
                    match self.inner.as_mut().poll_ready(self.cx) {
                        Poll::Ready(v) => v,
                        Poll::Pending => Ok(()),
                    }
                }) {
                    Err(e) => {
                        *self.is_any_close = true;
                        Err(e.into())
                    }
                    Ok(()) => {
                        debug_assert!(matches!(
                            self.inner.send_state,
                            SendState::Ready | SendState::Waiting
                        ));
                        Ok(())
                    }
                },
            };
        }
    }

    /// Starts closing sender.
    pub fn start_close(&mut self) {
        self.inner.as_mut().start_close();
        // Starts poll for close (otherwise it never will be polled).
        if let Poll::Ready(Err(_)) = self.inner.as_mut().poll_ready(self.cx) {
            *self.is_any_close = true;
        }
    }
}

/// Trait for generating IDs.
pub trait IDGenerator<ID> {
    /// Generate random ID with RNG.
    ///
    /// NOTE: You must take attempt (by calling [`NAttempts::attempt`]) **before** generating a random value.
    fn generate_id<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        attempts: NAttempts<'_>,
    ) -> Option<ID>;
}

impl<ID, T: IDGenerator<ID>> IDGenerator<ID> for &T {
    fn generate_id<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        attempts: NAttempts<'_>,
    ) -> Option<ID> {
        (**self).generate_id(rng, attempts)
    }
}

/// Type wrapping attempts at generating ID.
#[derive(Debug)]
pub struct NAttempts<'a>(&'a mut usize);

impl NAttempts<'_> {
    /// Reborrows value.
    pub fn reborrow<'a>(&'a mut self) -> NAttempts<'a> {
        NAttempts(&mut *self.0)
    }

    /// Take an attempt.
    ///
    /// Returns [`None`] if all attempts are exhausted.
    pub fn attempt(&mut self) -> Option<()> {
        *self.0 = self.0.checked_sub(1)?;
        Some(())
    }
}

/// Extension trait for [`IDGenerator`].
pub trait IDGeneratorExt<ID>: IDGenerator<ID> {
    /// Filter the generated IDs.
    #[inline(always)]
    fn filter<F>(self, pred: F) -> FilterIDGenerator<ID, Self, F>
    where
        Self: Sized,
        F: Fn(&ID) -> bool,
    {
        FilterIDGenerator::new(self, pred)
    }

    /// Map the generated IDs.
    #[inline(always)]
    fn map<R, F>(self, map: F) -> MapIDGenerator<ID, Self, F>
    where
        Self: Sized,
        F: Fn(ID) -> R,
    {
        MapIDGenerator::new(self, map)
    }
}

impl<ID, T: IDGenerator<ID>> IDGeneratorExt<ID> for T {}

/// Wrapping type for filtering generated IDs.
pub struct FilterIDGenerator<ID, T, F> {
    inner: T,
    pred: F,
    _p: PhantomData<ID>,
}

impl<ID, T: IDGenerator<ID>, F: Fn(&ID) -> bool> FilterIDGenerator<ID, T, F> {
    /// Create ID filter.
    #[inline(always)]
    pub const fn new(src: T, pred: F) -> Self {
        Self {
            inner: src,
            pred,
            _p: PhantomData,
        }
    }
}

impl<ID, T: IDGenerator<ID>, F: Fn(&ID) -> bool> IDGenerator<ID> for FilterIDGenerator<ID, T, F> {
    fn generate_id<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        mut attempts: NAttempts<'_>,
    ) -> Option<ID> {
        Some(loop {
            let v = self.inner.generate_id(rng, attempts.reborrow())?;
            if (self.pred)(&v) {
                break v;
            }
        })
    }
}

/// Wrapping type for mapping generated IDs.
pub struct MapIDGenerator<ID, T, F> {
    inner: T,
    map: F,
    _p: PhantomData<ID>,
}

impl<ID, R, T: IDGenerator<ID>, F: Fn(ID) -> R> MapIDGenerator<ID, T, F> {
    /// Create ID filter.
    #[inline(always)]
    pub const fn new(src: T, map: F) -> Self {
        Self {
            inner: src,
            map,
            _p: PhantomData,
        }
    }
}

impl<ID, R, T: IDGenerator<ID>, F: Fn(ID) -> R> IDGenerator<R> for MapIDGenerator<ID, T, F> {
    fn generate_id<Rng: RngCore + CryptoRng>(
        &self,
        rng: &mut Rng,
        attempts: NAttempts<'_>,
    ) -> Option<R> {
        self.inner.generate_id(rng, attempts).map(&self.map)
    }
}

/// ID generator that generates all possible IDs.
#[derive(Debug)]
pub struct AnyIDGenerator {
    /// `true` if ID should be 32 bit
    id_32bit: bool,
}

impl Default for AnyIDGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AnyIDGenerator {
    /// Create new `AnyIDGenerator`.
    pub const fn new() -> Self {
        Self { id_32bit: false }
    }

    /// Create new `AnyIDGenerator` from configuration data.
    pub fn from_config<C: WithCellConfig>(cfg: &C) -> Self {
        Self {
            id_32bit: cfg.is_circ_id_4bytes(),
        }
    }

    /// Set if ID should be 32 bits wide.
    ///
    /// Defaults to `false`.
    pub const fn id_32bit(&mut self, value: bool) -> &mut Self {
        self.id_32bit = value;
        self
    }

    /// Set self with configuration data.
    pub fn with_config<C: WithCellConfig>(&mut self, cfg: &C) -> &mut Self {
        self.id_32bit(cfg.is_circ_id_4bytes())
    }
}

impl IDGenerator<NonZeroU32> for AnyIDGenerator {
    fn generate_id<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        mut att: NAttempts<'_>,
    ) -> Option<NonZeroU32> {
        loop {
            att.attempt()?;
            let v = rng.next_u32();
            let v = if self.id_32bit {
                NonZeroU32::new(v)
            } else {
                NonZeroU16::new(v as u16)
                    .or_else(|| NonZeroU16::new((v >> 16) as u16))
                    .map(NonZeroU32::from)
            };
            if v.is_some() {
                break v;
            }
        }
    }
}

/// ID generator for initiator side.
#[derive(Debug)]
pub struct InitiatorIDGenerator {
    /// `true` if ID should be 32 bit
    id_32bit: bool,
}

impl Default for InitiatorIDGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl InitiatorIDGenerator {
    /// Create new `InitiatorIDGenerator`.
    pub const fn new() -> Self {
        Self { id_32bit: false }
    }

    /// Create new `InitiatorIDGenerator` from configuration data.
    pub fn from_config<C: WithCellConfig>(cfg: &C) -> Self {
        Self {
            id_32bit: cfg.is_circ_id_4bytes(),
        }
    }

    /// Set if ID should be 32 bits wide.
    ///
    /// Defaults to `false`.
    pub const fn id_32bit(&mut self, value: bool) -> &mut Self {
        self.id_32bit = value;
        self
    }

    /// Set self with configuration data.
    pub fn with_config<C: WithCellConfig>(&mut self, cfg: &C) -> &mut Self {
        self.id_32bit(cfg.is_circ_id_4bytes())
    }
}

impl IDGenerator<NonZeroU32> for InitiatorIDGenerator {
    fn generate_id<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        mut att: NAttempts<'_>,
    ) -> Option<NonZeroU32> {
        loop {
            att.attempt()?;
            let v = rng.next_u32()
                | if self.id_32bit {
                    0x8000_0000
                } else {
                    0x8000_8000
                };
            let v = if self.id_32bit {
                NonZeroU32::new(v)
            } else {
                NonZeroU16::new(v as u16)
                    .or_else(|| NonZeroU16::new((v >> 16) as u16))
                    .map(NonZeroU32::from)
            };
            if v.is_some() {
                break v;
            }
        }
    }
}

/// ID generator for responder side.
#[derive(Debug)]
pub struct ResponderIDGenerator {
    /// `true` if ID should be 32 bit
    id_32bit: bool,
}

impl Default for ResponderIDGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponderIDGenerator {
    /// Create new `ResponderIDGenerator`.
    pub const fn new() -> Self {
        Self { id_32bit: false }
    }

    /// Create new `ResponderIDGenerator` from configuration data.
    pub fn from_config<C: WithCellConfig>(cfg: &C) -> Self {
        Self {
            id_32bit: cfg.is_circ_id_4bytes(),
        }
    }

    /// Set if ID should be 32 bits wide.
    ///
    /// Defaults to `false`.
    pub const fn id_32bit(&mut self, value: bool) -> &mut Self {
        self.id_32bit = value;
        self
    }

    /// Set self with configuration data.
    pub fn with_config<C: WithCellConfig>(&mut self, cfg: &C) -> &mut Self {
        self.id_32bit(cfg.is_circ_id_4bytes())
    }
}

impl IDGenerator<NonZeroU32> for ResponderIDGenerator {
    fn generate_id<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        mut att: NAttempts<'_>,
    ) -> Option<NonZeroU32> {
        loop {
            att.attempt()?;
            let v = rng.next_u32()
                | if self.id_32bit {
                    0x7fff_ffff
                } else {
                    0x7fff_7fff
                };
            let v = if self.id_32bit {
                NonZeroU32::new(v)
            } else {
                NonZeroU16::new(v as u16)
                    .or_else(|| NonZeroU16::new((v >> 16) as u16))
                    .map(NonZeroU32::from)
            };
            if v.is_some() {
                break v;
            }
        }
    }
}

/// ID generator for stream ID.
#[derive(Debug)]
pub struct StreamIDGenerator {
    _p: (),
}

impl Default for StreamIDGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamIDGenerator {
    /// Create new `StreamIDGenerator`.
    pub const fn new() -> Self {
        Self { _p: () }
    }
}

impl IDGenerator<NonZeroU16> for StreamIDGenerator {
    fn generate_id<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        mut att: NAttempts<'_>,
    ) -> Option<NonZeroU16> {
        loop {
            att.attempt()?;
            let v = rng.next_u32();
            let v = NonZeroU16::new(v as u16).or_else(|| NonZeroU16::new((v >> 16) as u16));
            if v.is_some() {
                break v;
            }
        }
    }
}

/// Data for new handler.
///
/// For controller, send it to task handler.
/// Once received, use destructuring let to get all the values.
#[non_exhaustive]
pub struct NewHandler<ID, R: Runtime, Cell: 'static + Send> {
    /// Handler ID.
    pub id: ID,

    /// Receiver that receives cells from manager.
    pub receiver: R::SPSCReceiver<Cell>,

    /// Sender that sends cells into manager.
    pub sender: R::MPSCSender<Cell>,
}

impl<ID: Debug, R: Runtime, Cell: 'static + Send> Debug for NewHandler<ID, R, Cell> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("NewHandler")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<ID, R: Runtime, Cell: 'static + Send> NewHandler<ID, R, Cell> {
    fn new(id: ID, receiver: R::SPSCReceiver<Cell>, sender: R::MPSCSender<Cell>) -> Self {
        Self {
            id,
            receiver,
            sender,
        }
    }

    pub fn map_id<RID>(self, f: impl FnOnce(ID) -> RID) -> NewHandler<RID, R, Cell> {
        let Self {
            id,
            receiver,
            sender,
        } = self;
        NewHandler {
            receiver,
            sender,
            id: f(id),
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
        data: (NewHandler<C>, &'a mut HandlerData<C, M>),
        f: impl FnOnce(NonZeroU32, Receiver<C>, Sender<C>) + Send + 'static,
        handles: &mut Vec<JoinHandle<()>>,
    ) -> &'a mut HandlerData<C, M> {
        let (d, r) = data;
        handles.push(spawn(move || f(d.id, d.receiver, d.sender)));
        r
    }

    #[test]
    fn test_send_recv_one() {
        let mut handles = Vec::new();

        let mut map = CellMap::<(u32, usize)>::new(8, 8);

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

        let mut map = CellMap::<(u32, usize), usize>::new(8, 8);

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

        let mut map = CellMap::<(u32, usize), usize>::new(8, 8);

        const N_CIRC: usize = 16;

        for _ in 0..N_CIRC {
            spawn_circuit(
                loop {
                    if let Ok(v) = map.open(AnyIDGenerator::new().id_32bit(true), 64) {
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

        let mut map = CellMap::<(u32, u64), (u64, u64, u64)>::new(8, 8);

        const N_CIRC: usize = 16;

        let mut rng = ThreadRng::default();
        for _ in 0..N_CIRC {
            let (a, b): (u64, u64) = rng.r#gen();

            let (send, recv) = channel::<NewHandler<(u32, u64)>>();
            handles.push(spawn_async(t.timeout(async move {
                let Ok(NewHandler {
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
                if let Ok((data, _)) =
                    map.open_with(AnyIDGenerator::new().id_32bit(true), 64, |_| (0, a, b))
                {
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
