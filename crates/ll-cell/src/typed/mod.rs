//! Defines typed cell.
//!
//! See also: [Cell format](https://spec.torproject.org/tor-spec/cell-packet-format.html).

pub mod create;
pub mod padding;

#[doc(no_inline)]
pub use create::{Create2, CreateFast, Created2, CreatedFast};
#[doc(no_inline)]
pub use padding::{Padding, VPadding};
