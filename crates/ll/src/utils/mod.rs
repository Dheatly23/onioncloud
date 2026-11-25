//! Miscellaneous utility types.

#[cfg(not(fuzzing))]
mod hex;
#[cfg(fuzzing)]
pub mod hex;

use std::debug_assert_matches;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::mem::{MaybeUninit, transmute};
use std::str::{from_utf8, from_utf8_unchecked};

use base64ct::{Base64, Encoding};

#[cfg(feature = "cell")]
pub mod cell_rw;
#[cfg(feature = "crypto")]
mod extract_rsa;
mod versions;

#[cfg(feature = "crypto")]
pub use extract_rsa::*;
pub use hex::fmt_hex;
pub use versions::*;

/// Relay ID/fingerprint.
pub type RelayId = [u8; 20];

/// Relay Ed25519 public key.
///
/// Used in conjunction with [`RelayId`].
pub type RelayIdEd = [u8; 32];

/// Helper function to print byte slice as hex values.
///
/// # Example
///
/// ```
/// # use onioncloud_ll::utils::print_hex;
/// println!("{}", print_hex(&[0xaa; 100]));
/// ```
#[inline]
pub const fn print_hex(s: &[u8]) -> impl '_ + Display {
    struct S<'a>(&'a [u8]);

    impl Display for S<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            let mut a = [const { MaybeUninit::<u8>::uninit() }; 256];

            for s in self.0.chunks(128) {
                let a = &mut a[..s.len() * 2];
                hex::fmt_hex(a, s);
                // SAFETY: Array is initialized.
                let s = unsafe { transmute::<&[MaybeUninit<u8>], &[u8]>(a) };
                debug_assert_matches!(from_utf8(s), Ok(_));
                // SAFETY: Hex string is ASCII.
                let s = unsafe { from_utf8_unchecked(s) };
                Display::fmt(s, f)?;
            }

            Ok(())
        }
    }

    S(s)
}

/// Helper function to print [`RelayId`].
///
/// The encoded format is uppercase hex.
///
/// # Example
///
/// ```
/// # use onioncloud_ll::utils::print_relay_id;
/// println!("Relay ID: {}", print_relay_id(&[0xaa; _]));
/// ```
#[inline]
pub const fn print_relay_id(key: &RelayId) -> impl '_ + Display {
    struct S<'a>(&'a RelayId);

    impl Display for S<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            let mut a = [const { MaybeUninit::<u8>::uninit() }; 40];
            hex::fmt_hex(&mut a, self.0);
            // SAFETY: Array is initialized.
            let s = unsafe { transmute::<&[MaybeUninit<u8>], &[u8]>(&a) };
            debug_assert_matches!(from_utf8(s), Ok(_));
            // SAFETY: Hex string is ASCII.
            let s = unsafe { from_utf8_unchecked(s) };
            Display::fmt(s, f)
        }
    }

    S(key)
}

/// Helper function to print [`RelayIdEd`].
///
/// The encoded format is base64.
///
/// # Example
///
/// ```
/// # use onioncloud_ll::utils::print_relay_id_ed;
/// println!("Relay ID: {}", print_relay_id_ed(&[0xaa; _]));
/// ```
#[inline]
pub const fn print_relay_id_ed(key: &RelayIdEd) -> impl '_ + Display {
    struct S<'a>(&'a RelayIdEd);

    impl Display for S<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            // Calculate length based on base64ct encoded_len_inner
            const LEN: usize = const {
                let q = size_of::<RelayIdEd>() * 4;
                ((q / 3) + 3) & !3
            };

            let mut a = [0; LEN];
            let s = Base64::encode(self.0, &mut a).unwrap();
            Display::fmt(s, f)
        }
    }

    S(key)
}
