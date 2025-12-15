/// Timeout.
#[derive(Debug, PartialEq, Eq)]
pub struct Timeout;

/// Control message received.
#[derive(Debug)]
pub struct ControlMsg<M>(pub M);

impl<M> ControlMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Cell is received from child.
///
/// Exact interpretation of this event:
/// - Channel controller: Cell received from circuit.
/// - Circuit controller: Cell received from stream.
#[derive(Debug)]
pub struct ChildCellMsg<M>(pub M);

impl<M> ChildCellMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Cell is received from parent.
///
/// Exact interpretation of this event:
/// - Circuit controller: Cell received from channel.
#[derive(Debug)]
pub struct ParentCellMsg<M>(pub M);

impl<M> ParentCellMsg<M> {
    /// Unwraps into inner value.
    pub fn into_inner(self) -> M {
        self.0
    }
}

/// Channel is closed.
#[derive(Debug)]
#[non_exhaustive]
pub struct ChannelClosed<'a, ID, C, M> {
    /// Channel ID.
    pub id: ID,

    /// Last cell that fails to send.
    pub cell: Option<C>,

    /// Channel metadata.
    pub meta: &'a mut M,
}
