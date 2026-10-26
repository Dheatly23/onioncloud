//! `onioncloud-tart`: Klapping them taart cheeks :)
//!
//! ## Introduction
//!
//! `onioncloud-tart` is an async runtime focused on testing and fuzzing async code.

pub mod error;
pub mod mpsc;
mod oneshot;
pub mod rt;
pub mod socket;
pub mod spsc;
pub mod timer;
mod utils;
mod waker;
