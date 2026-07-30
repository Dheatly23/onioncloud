//! `onioncloud-tart`: Klapping them taart cheeks :)
//!
//! ## Introduction
//!
//! `onioncloud-tart` is an async runtime focused on testing and fuzzing async code.

mod oneshot;
mod rt;
mod utils;
mod waker;

pub use rt::*;
