#![allow(unused)]

use std::mem::{size_of, size_of_val};

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug, Clone, Copy)]
pub(crate) struct FromBytesWrapper<T>(pub(crate) T);

impl<T: Sized + FromBytes + IntoBytes> Arbitrary<'_> for FromBytesWrapper<T> {
    fn arbitrary(u: &mut Unstructured<'_>) -> ArbResult<Self> {
        let mut t = T::new_zeroed();
        let b = u.bytes(u.len().min(size_of_val(&t)))?;
        t.as_mut_bytes()[..b.len()].copy_from_slice(b);
        Ok(Self(t))
    }

    fn arbitrary_take_rest(u: Unstructured<'_>) -> ArbResult<Self> {
        let b = u.take_rest();
        let mut t = T::new_zeroed();
        let l = b.len().min(size_of_val(&t));
        t.as_mut_bytes()[..l].copy_from_slice(&b[..l]);
        Ok(Self(t))
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (size_of::<T>(), Some(size_of::<T>()))
    }
}
