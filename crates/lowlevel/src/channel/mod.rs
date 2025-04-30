pub mod controller;
pub mod manager;

use std::borrow::Cow;
use std::collections::hash_map::{Entry, HashMap, VacantEntry};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use flume::r#async::{RecvStream, SendSink};
use flume::{Receiver, SendError, SendTimeoutError, Sender, bounded};
use futures_core::{Stream as _, ready};
use futures_sink::Sink;
use rand::distr::Uniform;
use rand::prelude::*;

use crate::crypto::relay::RelayId;
use crate::errors;

/// Circuit fanout channel capacity.
const CHANNEL_CAP: usize = 256;
/// Circuit fanin channel capacity.
const CHANNEL_AGG_CAP: usize = 256;

/// Trait for channel configuration.
pub trait ChannelConfig {
    /// Get peer relay ID.
    fn peer_id(&self) -> &RelayId;

    // Get peer Ed25519 public key.
    //fn peer_ed25519_id(&self)

    /// Get peer addresses.
    fn peer_addrs(&self) -> Cow<'_, [SocketAddr]>;
}

/// Reference to channel data.
pub struct ChannelInput<'a, 'b, Cell: 'static, Meta> {
    stream: &'a mut dyn Stream,
    cx: Option<&'a mut Context<'b>>,
    map: &'a mut CircuitMap<Cell, Meta>,
    time: Instant,
}

impl<'a, 'b, Cell, Meta> ChannelInput<'a, 'b, Cell, Meta> {
    pub(crate) fn new(
        stream: &'a mut dyn Stream,
        cx: Option<&'a mut Context<'b>>,
        map: &'a mut CircuitMap<Cell, Meta>,
        time: Instant,
    ) -> Self {
        Self {
            stream,
            cx,
            map,
            time,
        }
    }

    /// Get stream reader.
    pub fn reader(&mut self) -> &mut dyn Read {
        &mut self.stream
    }

    /// Get stream writer.
    pub fn writer(&mut self) -> &mut dyn Write {
        &mut self.stream
    }

    /// Get link certificate.
    ///
    /// The certificate returned is only leaf certificate.
    pub fn link_cert(&self) -> Option<&[u8]> {
        self.stream.link_cert()
    }

    /// Get current time.
    pub fn time(&self) -> Instant {
        self.time
    }

    /// Get channel [`CircuitMapRef`].
    pub fn circ_map(&mut self) -> CircuitMapRef<'_, 'b, Cell, Meta> {
        CircuitMapRef::new(self.cx.as_deref_mut(), self.map)
    }
}

/// Return value for [`controller::ChannelController`] handler.
pub struct ChannelOutput {
    pub(crate) timeout: Option<Instant>,
    pub(crate) shutdown: bool,
}

impl ChannelOutput {
    /// Create new [`ChannelOutput`].
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            timeout: None,
            shutdown: false,
        }
    }

    /// Set timeout to be notified.
    pub fn timeout(&mut self, timeout: Instant) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Start graceful shutdown sequence.
    pub fn shutdown(&mut self, value: bool) -> &mut Self {
        self.shutdown = value;
        self
    }
}

/// Internal trait for a TLS stream.
pub(crate) trait Stream: Read + Write {
    fn link_cert(&self) -> Option<&[u8]>;
}

/// A circuit data.
#[derive(Debug)]
pub struct CircuitData<Cell: 'static, Meta> {
    sink: SendSink<'static, Cell>,

    /// Metadata to store alongside.
    pub meta: Meta,
}

impl<Cell, Meta> CircuitData<Cell, Meta> {
    fn new(sender: Sender<Cell>, meta: Meta) -> Self {
        Self {
            sink: sender.into_sink(),
            meta,
        }
    }

    /// Get the underlying [`Sender`].
    pub fn sender(&self) -> &Sender<Cell> {
        self.sink.sender()
    }
}

impl<Cell, Meta> Sink<Cell> for CircuitData<Cell, Meta>
where
    Self: Unpin,
{
    type Error = SendError<Cell>;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Cell) -> Result<(), Self::Error> {
        Pin::new(&mut self.sink).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.sink).poll_close(cx)
    }
}

/// Circuit mapping handler.
#[derive(Debug)]
pub struct CircuitMap<Cell: 'static, Meta> {
    map: HashMap<NonZeroU32, CircuitData<Cell, Meta>>,
    stream: RecvStream<'static, Cell>,
    // TODO: Remove this when RecvStream::receiver exists.
    receiver: Receiver<Cell>,
    sender: Sender<Cell>,
}

impl<Cell, Meta> Default for CircuitMap<Cell, Meta> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Cell, Meta> CircuitMap<Cell, Meta> {
    /// Create new [`CircuitMap`].
    pub fn new() -> Self {
        let (send, recv) = bounded(CHANNEL_AGG_CAP);
        Self {
            map: HashMap::new(),
            sender: send,
            receiver: recv.clone(),
            stream: recv.into_stream(),
        }
    }

    /// Get combined sender for circuits to send response cells.
    pub fn sender(&self) -> Sender<Cell> {
        self.sender.clone()
    }

    /// Get the number of active circuits.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns [`true`] if circuit map is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Get circuit data.
    pub fn get(&self, id: NonZeroU32) -> Option<&CircuitData<Cell, Meta>> {
        self.map.get(&id)
    }

    /// Get circuit data mutably.
    pub fn get_mut(&mut self, id: NonZeroU32) -> Option<&mut CircuitData<Cell, Meta>> {
        self.map.get_mut(&id)
    }

    /// Try to open new circuit at ID.
    /// Returns [`None`] if ID is occupied.
    ///
    /// ## Parameters
    /// - `id` : Circuit ID. Must be free.
    /// - `meta` : Function to create metadata for the new circuit.
    pub fn try_insert_with(
        &mut self,
        id: NonZeroU32,
        meta: impl FnOnce() -> Meta,
    ) -> Option<(NewCircuit<Cell>, &mut CircuitData<Cell, Meta>)> {
        let Entry::Vacant(e) = self.map.entry(id) else {
            return None;
        };
        let (send, recv) = bounded(CHANNEL_CAP);
        Some((
            NewCircuit::new(id, recv, self.sender.clone()),
            e.insert(CircuitData::new(send, meta())),
        ))
    }

    /// Same as [`try_insert_with`], but with [`Default`] metadata.
    pub fn try_insert(
        &mut self,
        id: NonZeroU32,
    ) -> Option<(NewCircuit<Cell>, &mut CircuitData<Cell, Meta>)>
    where
        Meta: Default,
    {
        self.try_insert_with(id, Default::default)
    }

    /// Open a new circuit at random free ID.
    ///
    /// ## Parameters
    /// - `set_msb` : Set MSB of ID.
    /// - `n_attempts` : Number of attempts to allocate ID. Tor spec recommends setting it to 64.
    /// - `id_32bit` : Use 32-bit circuit ID instead of legacy 16-bit circuit ID.
    /// - `meta` : Function to create metadata for the new circuit.
    pub fn try_open_with(
        &mut self,
        set_msb: bool,
        n_attempts: usize,
        id_32bit: bool,
        meta: impl FnOnce(NonZeroU32) -> Meta,
    ) -> Result<(NewCircuit<Cell>, &mut CircuitData<Cell, Meta>), errors::NoFreeCircIDError> {
        #[allow(clippy::type_complexity)]
        fn f<Cell, Meta>(
            map: &mut HashMap<NonZeroU32, CircuitData<Cell, Meta>>,
            set_msb: bool,
            n_attempts: usize,
            id_32bit: bool,
        ) -> Result<
            (
                NonZeroU32,
                VacantEntry<'_, NonZeroU32, CircuitData<Cell, Meta>>,
            ),
            errors::NoFreeCircIDError,
        > {
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

                // SAFETY: Lifetime extension because idk non-linear lifetime?
                #[allow(clippy::deref_addrof)]
                let map = unsafe { &mut *(&raw mut *map) };

                if let Entry::Vacant(e) = map.entry(id) {
                    return Ok((id, e));
                }
            }

            Err(errors::NoFreeCircIDError)
        }

        let (id, e) = f(&mut self.map, set_msb, n_attempts, id_32bit)?;
        let (send, recv) = bounded(CHANNEL_CAP);
        Ok((
            NewCircuit::new(id, recv, self.sender.clone()),
            e.insert(CircuitData::new(send, meta(id))),
        ))
    }

    /// Same as [`try_open_with`], but with `[Default`] metadata.
    pub fn try_open(
        &mut self,
        set_msb: bool,
        n_attempts: usize,
        id_32bit: bool,
    ) -> Result<(NewCircuit<Cell>, &mut CircuitData<Cell, Meta>), errors::NoFreeCircIDError>
    where
        Meta: Default,
    {
        self.try_open_with(set_msb, n_attempts, id_32bit, |_| Default::default())
    }

    /// Close circuit.
    pub fn remove(&mut self, id: NonZeroU32) -> Option<Meta> {
        self.map.remove(&id).map(|CircuitData { meta, .. }| meta)
    }
}

pub struct CircuitDataRef<'a, 'b, Cell: 'static, Meta> {
    inner: &'a mut CircuitData<Cell, Meta>,
    cx: Option<&'a mut Context<'b>>,
}

impl<Cell, Meta> CircuitDataRef<'_, '_, Cell, Meta> {
    /// Get inner [`CircuitData`].
    pub fn inner(&mut self) -> &mut CircuitData<Cell, Meta> {
        self.inner
    }

    /// Try to send cell into circuit.
    ///
    /// **NOTE: Make sure to set circuit ID of the cell.**
    ///
    /// # Parameter
    /// - `cell` : Cell reference. If succeed, cell will be taken. Use [`None`] value to only poll if circuit is ready to receive data.
    ///
    /// # Return
    /// - `Poll::Pending` : Sender is not ready yet. Cell **will not** be taken.
    /// - `Poll::Ready(Ok(()))` : Cell is successfully taken and queued for sending.
    /// - `Poll::Ready(Err(...))` : Circuit is closed. Cell might be taken.
    pub fn try_send(&mut self, cell: &mut Option<Cell>) -> Poll<Result<(), Cell>> {
        Poll::Ready(if let Some(cx) = self.cx.as_mut() {
            let mut sink = Pin::new(&mut self.inner.sink);

            if let Err(e) = ready!(sink.as_mut().poll_ready(cx)) {
                Err(e.into_inner())
            } else if let Some(c) = cell.take() {
                sink.as_mut().start_send(c).map_err(|e| e.into_inner())
            } else {
                Ok(())
            }
        } else if let Some(c) = cell.take() {
            // No async, use timeout to poll sender
            match self
                .inner
                .sender()
                .send_timeout(c, Duration::from_millis(100))
            {
                Ok(v) => Ok(v),
                Err(SendTimeoutError::Timeout(c)) => {
                    // Restore cell
                    *cell = Some(c);
                    return Poll::Pending;
                }
                Err(SendTimeoutError::Disconnected(c)) => Err(c),
            }
        } else if self.inner.sender().is_full() {
            return Poll::Pending;
        } else {
            Ok(())
        })
    }
}

pub struct CircuitMapRef<'a, 'b, Cell: 'static, Meta> {
    cx: Option<&'a mut Context<'b>>,
    map: &'a mut CircuitMap<Cell, Meta>,
}

impl<'a, 'b, Cell, Meta> CircuitMapRef<'a, 'b, Cell, Meta> {
    pub(crate) fn new(
        cx: Option<&'a mut Context<'b>>,
        map: &'a mut CircuitMap<Cell, Meta>,
    ) -> Self {
        Self { cx, map }
    }

    /// Get the number of active circuits.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns [`true`] if circuit map is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Get circuit data.
    pub fn get(&self, id: NonZeroU32) -> Option<&CircuitData<Cell, Meta>> {
        self.map.get(id)
    }

    /// Get circuit data mutably.
    pub fn get_mut(&mut self, id: NonZeroU32) -> Option<CircuitDataRef<'_, 'b, Cell, Meta>> {
        Some(CircuitDataRef {
            inner: self.map.get_mut(id)?,
            cx: self.cx.as_deref_mut(),
        })
    }

    /// Try to open new circuit at ID.
    /// Returns [`None`] if ID is occupied.
    ///
    /// ## Parameters
    /// - `id` : Circuit ID. Must be free.
    /// - `meta` : Function to create metadata for the new circuit.
    pub fn try_insert_with(
        &mut self,
        id: NonZeroU32,
        meta: impl FnOnce() -> Meta,
    ) -> Option<(NewCircuit<Cell>, CircuitDataRef<'_, 'b, Cell, Meta>)> {
        let (data, inner) = self.map.try_insert_with(id, meta)?;
        Some((
            data,
            CircuitDataRef {
                inner,
                cx: self.cx.as_deref_mut(),
            },
        ))
    }

    /// Same as [`try_insert_with`], but with [`Default`] metadata.
    pub fn try_insert(
        &mut self,
        id: NonZeroU32,
    ) -> Option<(NewCircuit<Cell>, CircuitDataRef<'_, 'b, Cell, Meta>)>
    where
        Meta: Default,
    {
        let (data, inner) = self.map.try_insert(id)?;
        Some((
            data,
            CircuitDataRef {
                inner,
                cx: self.cx.as_deref_mut(),
            },
        ))
    }

    /// Open a new circuit at random free ID.
    ///
    /// ## Parameters
    /// - `set_msb` : Set MSB of ID.
    /// - `n_attempts` : Number of attempts to allocate ID. Tor spec recommends setting it to 64.
    /// - `meta` : Function to create metadata for the new circuit.
    pub fn try_open_with(
        &mut self,
        set_msb: bool,
        n_attempts: usize,
        id_32bit: bool,
        meta: impl FnOnce(NonZeroU32) -> Meta,
    ) -> Result<(NewCircuit<Cell>, CircuitDataRef<'_, 'b, Cell, Meta>), errors::NoFreeCircIDError>
    {
        let (data, inner) = self
            .map
            .try_open_with(set_msb, n_attempts, id_32bit, meta)?;
        Ok((
            data,
            CircuitDataRef {
                inner,
                cx: self.cx.as_deref_mut(),
            },
        ))
    }

    /// Same as [`try_open_with`], but with `[Default`] metadata.
    pub fn try_open(
        &mut self,
        set_msb: bool,
        n_attempts: usize,
        id_32bit: bool,
    ) -> Result<(NewCircuit<Cell>, CircuitDataRef<'_, 'b, Cell, Meta>), errors::NoFreeCircIDError>
    where
        Meta: Default,
    {
        let (data, inner) = self.map.try_open(set_msb, n_attempts, id_32bit)?;
        Ok((
            data,
            CircuitDataRef {
                inner,
                cx: self.cx.as_deref_mut(),
            },
        ))
    }

    /// Close circuit.
    pub fn remove(&mut self, id: NonZeroU32) -> Option<Meta> {
        self.map.remove(id)
    }

    /// Try to receive cell from circuits.
    ///
    /// Returns [`None`] if stream is empty.
    ///
    /// **NOTE: The responsibility to set circuit ID is on each circuit handler.**
    pub fn try_recv(&mut self) -> Option<Cell> {
        if let Some(cx) = self.cx.as_mut() {
            match Pin::new(&mut self.map.stream).poll_next(cx) {
                Poll::Ready(Some(v)) => Some(v),
                _ => None,
            }
        } else {
            // No async, use timeout to poll receiver
            self.map
                .receiver
                .recv_timeout(Duration::from_millis(100))
                .ok()
        }
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
