//! Lowlevel relay cell type definitions and processing.

mod traits;
pub mod v0;
pub mod v1;
pub mod ver;

pub use traits::*;

/*
use onioncloud_ll_cell::typed::{Relay, RelayEarly};
use onioncloud_ll_cell::fixed::FixedCell;

/// Trait for casting from [`Relay`] cell.
///
/// # Implementer's Note
///
/// **[`Self::try_from_relay`] should not mutate nor drop the cell.**
/// If the cell does not match, it should return the cell back.
/// This allows user to match for multiple types.
///
/// # Errors
///
/// It **should not** return error if the [`command`](`CellHeader::command`) ID does not match.
/// If the command ID does not match, return `Ok(None)` instead.
pub trait TryFromRelay {
}
*/
