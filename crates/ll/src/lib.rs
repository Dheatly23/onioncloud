//! Combination crate for low level onioncloud code.
//!
//! # Feature Flags
//!
//! This crate uses feature flags to gate re-export of dependencies.

pub mod utils;

macro_rules! feat_import {
    {$($feat:literal => $cr:ident as $alias:ident,)+} => {$(
        #[cfg(feature = $feat)]
        #[doc(no_inline)]
        pub use $cr as $alias;
    )+}
}

feat_import! {
    "cell" => onioncloud_ll_cell as cell,
    "channel" => onioncloud_ll_channel as channel,
    "crypto" => onioncloud_ll_crypto as crypto,
    "relay-cell" => onioncloud_ll_relay_cell as relay_cell,
}

/// Helper macro for error enum conversion.
///
/// ```no_run
/// # use onioncloud_ll::error_from_enum;
/// use std::any::Any;
///
/// struct ErrA;
/// struct ErrB;
///
/// enum CombinedErr {
///     ErrA(ErrA),
///     ErrB(ErrB),
/// }
///
/// enum CombinedErr2 {
///     Any(Box<dyn 'static + Any + Send + Sync>),
///     ErrA(ErrA),
///     ErrB(ErrB),
/// }
///
/// impl From<ErrA> for CombinedErr2 {
///     fn from(v: ErrA) -> Self {
///         Self::ErrA(v)
///     }
/// }
///
/// impl From<ErrB> for CombinedErr2 {
///     fn from(v: ErrB) -> Self {
///         Self::ErrB(v)
///     }
/// }
///
/// error_from_enum! {
///     CombinedErr2 {
///         else a => Self::Any(Box::new(a) as _),
///         CombinedErr => [ErrA, ErrB],
///     }
/// }
/// ```
#[macro_export]
macro_rules! error_from_enum {
    {$t:ty { else $v:ident => $e:expr, $($a:ident => [$($f:ident),* $(,)?],)* }} => {$(
        impl From<$a> for $t {
            fn from(err: $a) -> $t {
                match err {
                    $($a::$f(v) => <$t as From<_>>::from(v),)*
                    $v => $e,
                }
            }
        }
    )*}
}
