//! Utilities

use std::fmt::{Debug, Formatter, Result as FmtResult};

use base64ct::{Base64Unpadded, Encoding};

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
