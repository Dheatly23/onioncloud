use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use flume::TrySendError;

use crate::cell::destroy::DestroyReason;
use crate::circuit::controller::CircuitController;
use crate::circuit::{AggSender, CircuitInput, CircuitOutput};
use crate::util::cell_map::CellMap;
use crate::util::sans_io::event::{ChildCellMsg, ControlMsg, ParentCellMsg, Timeout};

pub struct TestController<C: CircuitController> {
    pair: TestPair<C::Cell>,
    circ_id: NonZeroU32,
    time: Instant,
    timeout: Option<Instant>,
    controller: C,
    ctrl_msgs: Vec<C::ControlMsg>,
    circ_map: CellMap<C::Cell, C::StreamMeta>,
    parent_cell_msg_pause: bool,
    child_cell_msg_pause: bool,
}

impl<C: CircuitController> TestController<C> {
    /// Create new [`TestController`].
    ///
    /// # Parameters
    /// - `config` : Configuration.
    /// - `circ_id` : Circuit ID.
    pub fn new(
        config: Arc<impl 'static + Send + Sync + AsRef<C::Config>>,
        circ_id: NonZeroU32,
        linkver: u16,
    ) -> Self {
        let cfg = (*config).as_ref();
        let circ_map = CellMap::new(C::channel_cap(cfg), C::channel_aggregate_cap(cfg));

        let mut controller = C::new(config, circ_id);
        controller.set_linkver(linkver);

        Self {
            controller,
            circ_id,
            pair: TestPair {
                send: VecDeque::new(),
                recv: VecDeque::new(),
            },
            time: Instant::now(),
            timeout: None,
            ctrl_msgs: Vec::new(),
            circ_map,
            parent_cell_msg_pause: true,
            child_cell_msg_pause: true,
        }
    }

    /// Get reference to controller.
    pub fn controller(&mut self) -> &mut C {
        &mut self.controller
    }

    /// Get reference to [`CellMap`].
    pub fn circ_map(&mut self) -> &mut CellMap<C::Cell, C::StreamMeta> {
        &mut self.circ_map
    }

    /// Get current time.
    pub fn cur_time(&self) -> Instant {
        self.time
    }

    /// Get timeout value (if any).
    pub fn timeout(&self) -> Option<Instant> {
        self.timeout
    }

    /// Advance time.
    pub fn advance_time(&mut self, dur: Duration) {
        self.time += dur;
    }

    /// Submit control message.
    pub fn submit_msg(&mut self, msg: C::ControlMsg) {
        self.ctrl_msgs.push(msg);
    }

    /// Send cell into circuit.
    pub fn send_cell(&mut self, cell: C::Cell) {
        self.pair.recv.push_back(cell);
    }

    /// Receives cell.
    pub fn recv_cell(&mut self) -> Option<C::Cell> {
        self.pair.send.pop_front()
    }

    /// Run controller handler.
    pub fn process(&mut self) -> Result<ProcessedCircuitOutput, C::Error> {
        let mut empty_handle = false;

        loop {
            let mut has_event = false;

            if self.timeout.as_ref().is_some_and(|t| *t <= self.time) {
                self.timeout = None;
                // Event: timeout
                self.controller.handle(Timeout)?;
                has_event = true;
            }

            for m in self.ctrl_msgs.drain(..) {
                // Event: control message
                self.controller.handle(ControlMsg(m))?;
                has_event = true;
            }

            while !self.parent_cell_msg_pause {
                let Some(m) = self.pair.recv.pop_front() else {
                    break;
                };

                // Event: parent cell message
                self.parent_cell_msg_pause = self.controller.handle(ParentCellMsg(m))?.0;
                has_event = true;
            }

            let mut cell_msg_block = false;
            while !self.child_cell_msg_pause {
                let Ok(m) = self.circ_map.try_recv() else {
                    cell_msg_block = true;
                    break;
                };

                // Event: child cell message
                self.child_cell_msg_pause = self.controller.handle(ChildCellMsg(m))?.0;
                has_event = true;
            }

            if has_event || !empty_handle {
                let CircuitOutput {
                    shutdown,
                    timeout,
                    parent_cell_msg_pause,
                    child_cell_msg_pause,
                } = self.controller.handle((
                    CircuitInput::new(self.circ_id, self.time, &mut self.pair),
                    &mut self.circ_map,
                ))?;
                empty_handle = true;
                self.parent_cell_msg_pause = parent_cell_msg_pause;
                self.child_cell_msg_pause = child_cell_msg_pause;
                self.timeout = timeout;

                if let shutdown @ Some(_) = shutdown {
                    return Ok(ProcessedCircuitOutput { shutdown });
                } else if self.timeout.is_some()
                    || (!self.pair.recv.is_empty() && !self.parent_cell_msg_pause)
                    || (!cell_msg_block && !self.child_cell_msg_pause)
                {
                    // Repoll
                    continue;
                }
            }

            return Ok(ProcessedCircuitOutput { shutdown: None });
        }
    }
}

/// Wrapper type for [`CircuitOutput`].
#[non_exhaustive]
pub struct ProcessedCircuitOutput {
    /// [`Some`] if controller request for shutdown and it's reason.
    pub shutdown: Option<DestroyReason>,
}

struct TestPair<Cell> {
    send: VecDeque<Cell>,
    recv: VecDeque<Cell>,
}

impl<Cell> AggSender for TestPair<Cell> {
    type Cell = Cell;

    fn try_send_unchecked(&mut self, cell: Cell) -> Result<(), TrySendError<Cell>> {
        self.send.push_back(cell);
        Ok(())
    }
}
