use std::mem::size_of;
use std::slice::from_ref;

use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256};

use super::{Sha1Output, Sha256Output};
use crate::cell::relay::RelayLike;
use crate::errors;

/// Trait for relay rolling digest.
///
/// # Implementers Note
///
/// Implementers should **only** modify the [`recognized`](`RelayLike::recognized`) and [`digest`](`RelayLike::digest`) field.
/// All other relay fields should be left unchanged.
pub trait RelayDigest {
    /// Set digest of cell going forward.
    fn wrap_digest_forward<T: ?Sized + RelayLike>(&mut self, cell: &mut T);

    /// Set digest of cell going backward.
    fn wrap_digest_backward<T: ?Sized + RelayLike>(&mut self, cell: &mut T);

    /// Process and check digest of cell going forward.
    fn unwrap_digest_forward<T: ?Sized + RelayLike>(
        &mut self,
        cell: &mut T,
    ) -> Result<(), errors::CellDigestError>;

    /// Process and check digest of cell going backward.
    fn unwrap_digest_backward<T: ?Sized + RelayLike>(
        &mut self,
        cell: &mut T,
    ) -> Result<(), errors::CellDigestError>;
}

/// Circuit rolling digest handler.
pub struct CircuitDigest {
    forward: Context,
    backward: Context,
}

impl CircuitDigest {
    /// Create new [`CircuitDigest`].
    ///
    /// # Parameters
    ///
    /// - `forward` : Seed for forward digest. Should be obtained through circuit creation/extension.
    /// - `backward` : Seed for backward digest. Should be obtained through circuit creation/extension.
    pub fn new(forward: Sha1Output, backward: Sha1Output) -> Self {
        let mut fc = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        fc.update(&forward);
        let mut bc = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        bc.update(&backward);

        Self {
            forward: fc,
            backward: bc,
        }
    }

    /// Get current rolling digest going forward.
    pub fn digest_forward(&self) -> Sha1Output {
        self.forward.clone().finish().as_ref().try_into().unwrap()
    }

    /// Get current rolling digest going backward.
    pub fn digest_backward(&self) -> Sha1Output {
        self.backward.clone().finish().as_ref().try_into().unwrap()
    }
}

impl RelayDigest for CircuitDigest {
    fn wrap_digest_forward<T: ?Sized + RelayLike>(&mut self, cell: &mut T) {
        cell.set_recognized([0; 2]);
        cell.set_digest([0; 4]);

        self.forward.update(cell.as_ref());
        cell.set_digest(self.digest_forward()[..4].try_into().unwrap());
    }

    fn wrap_digest_backward<T: ?Sized + RelayLike>(&mut self, cell: &mut T) {
        cell.set_recognized([0; 2]);
        cell.set_digest([0; 4]);

        self.backward.update(cell.as_ref());
        cell.set_digest(self.digest_backward()[..4].try_into().unwrap());
    }

    fn unwrap_digest_forward<T: ?Sized + RelayLike>(
        &mut self,
        cell: &mut T,
    ) -> Result<(), errors::CellDigestError> {
        if !cell.is_recognized() {
            return Err(errors::CellDigestError);
        }
        let digest = cell.digest();
        cell.set_digest([0; 4]);

        self.forward.update(cell.as_ref());
        let other: [u8; 4] = self.digest_forward()[..4].try_into().unwrap();

        if digest != other {
            Err(errors::CellDigestError)
        } else {
            Ok(())
        }
    }

    fn unwrap_digest_backward<T: ?Sized + RelayLike>(
        &mut self,
        cell: &mut T,
    ) -> Result<(), errors::CellDigestError> {
        if !cell.is_recognized() {
            return Err(errors::CellDigestError);
        }
        let digest = cell.digest();
        cell.set_digest([0; 4]);

        self.backward.update(cell.as_ref());
        let other: [u8; 4] = self.digest_backward()[..4].try_into().unwrap();

        if digest != other {
            Err(errors::CellDigestError)
        } else {
            Ok(())
        }
    }
}

/// Trait for onion skin layer.
pub trait OnionLayer {
    // TODO: Interface methods
}

pub struct OnionLayerFast {}

pub fn kdf_tor(key: &[&[u8]], out: &mut [u8]) {
    let mut hasher = Context::new(&SHA256);
    for k in key {
        hasher.update(k);
    }

    let mut n = 255u8;
    for o in out.chunks_mut(size_of::<Sha256Output>()) {
        n = n.wrapping_add(1);

        let mut hasher = hasher.clone();
        hasher.update(from_ref(&n));
        let hash = hasher.finish();
        let hash = hash.as_ref();
        debug_assert!(o.len() <= hash.len());
        o.copy_from_slice(if o.len() == hash.len() {
            hash
        } else {
            &hash[..o.len()]
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_tor() {
        let mut out = [0; 255 * 32];
        kdf_tor(&[b"test123", b"test234"], &mut out);
    }
}
