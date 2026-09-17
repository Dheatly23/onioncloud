//! Utilities

use std::fmt::{Debug, Formatter, Result as FmtResult};

use base64ct::{Base64Unpadded, Encoding};
use zerocopy::byteorder::big_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::fixed::FIXED_CELL_SIZE;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Default)]
#[repr(C)]
pub(crate) struct HeaderSmall {
    pub(crate) circuit: U16,
    pub(crate) command: u8,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Default)]
#[repr(C)]
pub(crate) struct HeaderLarge {
    pub(crate) circuit: U32,
    pub(crate) command: u8,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Default)]
#[repr(C)]
pub(crate) struct HeaderSmallVariable {
    pub(crate) header: HeaderSmall,
    pub(crate) len: U16,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Default)]
#[repr(C)]
pub(crate) struct HeaderLargeVariable {
    pub(crate) header: HeaderLarge,
    pub(crate) len: U16,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct PrefixedFixedCell {
    pub(crate) v: U16,
    pub(crate) rest: [u8; const { FIXED_CELL_SIZE - 2 }],
}

pub(crate) const fn encoded_len(l: usize) -> usize {
    ((l * 4) / 3) + !(l * 4).is_multiple_of(3) as usize
}

pub(crate) const fn base64u_encode(s: &[u8]) -> impl '_ + Debug {
    struct S<'a>(&'a [u8]);

    impl Debug for S<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            const CHUNK_LEN: usize = 3 * 32;
            let mut a = [0u8; const { (CHUNK_LEN * 4) / 3 }];

            for v in self.0.chunks(CHUNK_LEN) {
                let len = v.len();
                let len = encoded_len(len);
                let out =
                    Base64Unpadded::encode(v, &mut a[..len]).expect("conversion must never fail");
                f.write_str(out)?;
            }

            Ok(())
        }
    }

    S(s)
}
