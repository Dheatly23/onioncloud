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
///     CombinedErr => CombinedErr2 {
///         [ErrA, ErrB],
///         a => CombinedErr2::Any(Box::new(a) as _),
///     }
/// }
/// ```
#[macro_export]
macro_rules! error_from_enum {
    {$a:ident => $b:ty { [$($f:ident),* $(,)?], $v:ident => $e:expr $(,)? }} => {
        impl From<$a> for $b {
            fn from(err: $a) -> $b {
                match err {
                    $($a::$f(v) => <$b as From<_>>::from(v),)*
                    $v => $e,
                }
            }
        }
    }
}
