use std::mem::size_of;
use std::num::NonZeroU32;
use std::slice::from_ref;

use cipher::{KeyIvInit, StreamCipher};
use rand::prelude::*;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use subtle::ConstantTimeEq;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::{Cipher128, CipherKey128, Sha1Output, Sha256Output};
use crate::cache::{Cached, CellCache};
use crate::cell::create::{CreateFast, CreatedFast};
use crate::cell::relay::RelayLike;
use crate::cell::{FIXED_CELL_SIZE, FixedCell};
use crate::errors;

/// Trait for relay rolling digest.
///
/// # User Note
///
/// Because wrap and unwrap are linked for each direction, user **should not** use both for the same value.
/// Only use [`wrap_digest_forward`] and [`unwrap_digest_backward`], or [`unwrap_digest_forward`] and [`wrap_digest_backward`].
///
/// # Implementers Note
///
/// Implementers **should only** modify the [`recognized`](`RelayLike::recognized`) and [`digest`](`RelayLike::digest`) field.
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
#[derive(Clone)]
pub struct CircuitDigest {
    forward: Context,
    backward: Context,
}

impl CircuitDigest {
    /// Create new [`CircuitDigest`].
    ///
    /// # Parameters
    ///
    /// All paraneters should be obtained through circuit creation/extension.
    ///
    /// - `forward` : Seed for forward digest.
    /// - `backward` : Seed for backward digest.
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
///
/// # User Note
///
/// Because encrypt and decrypt are linked for each direction, user **should not** use both for the same value.
/// Only use [`encrypt_forward`] and [`decrypt_backward`], or [`decrypt_forward`] and [`encrypt_backward`].
pub trait OnionLayer {
    /// Encrypts cell going forward.
    fn encrypt_forward(
        &mut self,
        data: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<(), errors::CipherError>;

    /// Encrypts cell going backward.
    fn encrypt_backward(
        &mut self,
        data: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<(), errors::CipherError>;

    /// Decrypts cell going forward.
    fn decrypt_forward(
        &mut self,
        data: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<(), errors::CipherError>;

    /// Decrypts cell going backward.
    fn decrypt_backward(
        &mut self,
        data: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<(), errors::CipherError>;
}

/// Default onion skin layer.
#[derive(Clone)]
pub struct OnionLayer128 {
    forward: Cipher128,
    backward: Cipher128,
}

impl OnionLayer128 {
    /// Create new [`OnionLayer128`].
    ///
    /// # Parameters
    ///
    /// All paraneters should be obtained through circuit creation/extension.
    ///
    /// - `forward` : Key for forward cells.
    /// - `backward` : Key for backward cells.
    pub fn new(forward: CipherKey128, backward: CipherKey128) -> Self {
        Self {
            forward: Cipher128::new((&forward).into(), &Default::default()),
            backward: Cipher128::new((&backward).into(), &Default::default()),
        }
    }
}

impl OnionLayer for OnionLayer128 {
    fn encrypt_forward(
        &mut self,
        data: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<(), errors::CipherError> {
        self.forward
            .try_apply_keystream(data)
            .map_err(errors::CipherError::from)
    }

    fn encrypt_backward(
        &mut self,
        data: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<(), errors::CipherError> {
        self.backward
            .try_apply_keystream(data)
            .map_err(errors::CipherError::from)
    }

    fn decrypt_forward(
        &mut self,
        data: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<(), errors::CipherError> {
        self.forward
            .try_apply_keystream(data)
            .map_err(errors::CipherError::from)
    }

    fn decrypt_backward(
        &mut self,
        data: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<(), errors::CipherError> {
        self.backward
            .try_apply_keystream(data)
            .map_err(errors::CipherError::from)
    }
}

/// Onion handshake output.
#[non_exhaustive]
pub struct OnionLayerData {
    /// Encryption layer used.
    pub encrypt: OnionLayer128,

    /// Digest layer used.
    ///
    /// Previous digest layer should be discarded, because it's no longer useful.
    pub digest: CircuitDigest,
}

/// CREATE_FAST/CREATED_FAST handshake.
///
/// Must only be used for one-hop directory circuit.
pub struct OnionLayerFast {
    key: Sha1Output,
}

impl OnionLayerFast {
    fn from_cell(circuit: NonZeroU32, cell: FixedCell) -> (Self, CreateFast) {
        let key = ThreadRng::default().r#gen::<Sha1Output>();
        (Self { key }, CreateFast::new(cell, circuit, key))
    }

    /// Starts handshake as client.
    ///
    /// The resulting [`CreateFast`] cell should be send to server.
    pub fn new<C: CellCache>(cache: &C, circuit: NonZeroU32) -> (Self, CreateFast) {
        Self::from_cell(circuit, cache.get_cached())
    }

    /// Same as [`new`], but wraps cell in [`Cached`].
    pub fn with_cache<C: CellCache + Clone>(
        cache: &C,
        circuit: NonZeroU32,
    ) -> (Self, Cached<CreateFast, C>) {
        let (this, cell) = Self::new(cache, circuit);
        (this, cache.cache(cell))
    }

    fn derive_server_inner(
        input: &CreateFast,
        cell: FixedCell,
    ) -> Result<(OnionLayerData, CreatedFast), errors::CircuitHandshakeError> {
        let key = ThreadRng::default().r#gen::<Sha1Output>();
        let DerivedFast { kh, keys } = derive_fast(input.key(), &key);

        Ok((
            derive_keys(keys),
            CreatedFast::new(cell, input.circuit, key, kh),
        ))
    }

    /// Starts handshake as server.
    ///
    /// The resulting [`CreatedFast`] cell should be send to client to finish handshake.
    pub fn derive_server<C: CellCache>(
        cell: &CreateFast,
        cache: &C,
    ) -> Result<(OnionLayerData, CreatedFast), errors::CircuitHandshakeError> {
        Self::derive_server_inner(cell, cache.get_cached())
    }

    /// Same as [`derive_server`], but with [`Cached`] cell instead.
    pub fn derive_server_cached<C: CellCache + Clone>(
        cell: &Cached<CreateFast, C>,
    ) -> Result<(OnionLayerData, Cached<CreatedFast, C>), errors::CircuitHandshakeError> {
        let cache = Cached::cache(cell);
        let (this, cell) = Self::derive_server(&cell, cache)?;
        Ok((this, cache.cache(cell)))
    }

    /// Finish handshake as client.
    pub fn derive_client(
        self,
        cell: &CreatedFast,
    ) -> Result<OnionLayerData, errors::CircuitHandshakeError> {
        let DerivedFast { kh, keys } = derive_fast(&self.key, cell.key());
        if kh.ct_ne(cell.derived()).into() {
            return Err(errors::CircuitHandshakeError {});
        }

        Ok(derive_keys(keys))
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct DerivedKeys {
    df: Sha1Output,
    db: Sha1Output,
    kf: CipherKey128,
    kb: CipherKey128,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct DerivedFast {
    kh: Sha1Output,
    keys: DerivedKeys,
}

fn derive_keys(keys: DerivedKeys) -> OnionLayerData {
    OnionLayerData {
        encrypt: OnionLayer128::new(keys.kf, keys.kb),
        digest: CircuitDigest::new(keys.df, keys.db),
    }
}

fn derive_fast(key_x: &Sha1Output, key_y: &Sha1Output) -> DerivedFast {
    let mut out = DerivedFast::new_zeroed();
    kdf_tor(&[&key_x[..], &key_y[..]], out.as_mut_bytes());
    out
}

fn kdf_tor(key: &[&[u8]], out: &mut [u8]) {
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

    use crate::cache::NullCellCache;
    use crate::cell::relay::Relay;

    #[test]
    fn test_kdf_tor() {
        let mut out = [0; 255 * 32];
        kdf_tor(&[b"test123", b"test234"], &mut out);
    }

    #[test]
    fn test_handshake_fast() {
        let cache = NullCellCache;
        let id = NonZeroU32::new(1).unwrap();

        // Do handshake
        let (mut client, mut server) = {
            let (client, cell) = OnionLayerFast::with_cache(&cache, id);
            let (server, cell) = OnionLayerFast::derive_server_cached(&cell).unwrap();
            let client = client.derive_client(&cell).unwrap();
            (client, server)
        };

        // Validate by simulating a cell.
        static DATA: &[u8] = b"test data";
        let mut cell = Relay::new(cache.get_cached(), id, 0, 0xdead, DATA);
        client.encrypt.encrypt_forward(cell.as_mut()).unwrap();
        server.encrypt.decrypt_forward(cell.as_mut()).unwrap();

        assert_eq!(cell.command(), 0);
        assert_eq!(cell.stream(), 0xdead);
        assert_eq!(cell.data(), DATA);
    }
}
