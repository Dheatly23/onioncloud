use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::mem::size_of;
use std::num::NonZeroU32;
use std::slice::from_ref;

use cipher::{KeyIvInit, StreamCipher};
use digest::{Digest, ExtendableOutput, Mac};
use hkdf::HkdfExtract;
use hmac::Hmac;
use rand::prelude::*;
use sha1::Sha1;
use sha2::Sha256;
use sha3::{Sha3_256, Shake256};
use subtle::ConstantTimeEq;
use tracing::field::display;
use tracing::{instrument, trace};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned};

use super::{
    Cipher128, Cipher256, CipherKey128, CipherKey256, EdPublicKey, Sha1Output, Sha256Output,
};
use crate::cache::{Cached, CellCache, CellCacheExt};
use crate::cell::create::{Create2, CreateFast, Created2, CreatedFast};
use crate::cell::relay::RelayRefWrapper;
use crate::cell::relay::v0::RelayExt;
use crate::cell::{FIXED_CELL_SIZE, FixedCell};
use crate::crypto::relay::RelayId;
use crate::errors;
use crate::util::{print_ed, print_hex};

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
    type Digest: AsRef<[u8]>;

    /// Set digest of cell going forward.
    fn wrap_digest_forward(&mut self, cell: &mut [u8; FIXED_CELL_SIZE]) -> Self::Digest;

    /// Set digest of cell going backward.
    fn wrap_digest_backward(&mut self, cell: &mut [u8; FIXED_CELL_SIZE]) -> Self::Digest;

    /// Process and check digest of cell going forward.
    fn unwrap_digest_forward(
        &mut self,
        cell: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<Self::Digest, errors::CellDigestError>;

    /// Process and check digest of cell going backward.
    fn unwrap_digest_backward(
        &mut self,
        cell: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<Self::Digest, errors::CellDigestError>;

    /// Get current forward digest.
    fn this_digest_forward(&self) -> Self::Digest;

    /// Get current backward digest.
    fn this_digest_backward(&self) -> Self::Digest;
}

/// Circuit rolling digest handler.
#[derive(Clone)]
pub struct CircuitDigest {
    forward: Sha1,
    backward: Sha1,
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
        Self {
            forward: Sha1::new_with_prefix(forward),
            backward: Sha1::new_with_prefix(backward),
        }
    }

    /// Get current rolling digest going forward.
    pub fn digest_forward(&self) -> Sha1Output {
        self.forward.clone().finalize().into()
    }

    /// Get current rolling digest going backward.
    pub fn digest_backward(&self) -> Sha1Output {
        self.backward.clone().finalize().into()
    }
}

impl RelayDigest for CircuitDigest {
    type Digest = Sha1Output;

    fn wrap_digest_forward(&mut self, cell: &mut [u8; FIXED_CELL_SIZE]) -> Self::Digest {
        let cell: &mut RelayRefWrapper = cell.into();

        cell.set_recognized([0; 2]);
        cell.set_digest([0; 4]);

        self.forward.update(cell.as_ref());
        let digest = self.digest_forward();
        cell.set_digest(digest[..4].try_into().unwrap());
        digest
    }

    fn wrap_digest_backward(&mut self, cell: &mut [u8; FIXED_CELL_SIZE]) -> Self::Digest {
        let cell: &mut RelayRefWrapper = cell.into();

        cell.set_recognized([0; 2]);
        cell.set_digest([0; 4]);

        self.backward.update(cell.as_ref());
        let digest = self.digest_backward();
        cell.set_digest(digest[..4].try_into().unwrap());
        digest
    }

    fn unwrap_digest_forward(
        &mut self,
        cell: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<Self::Digest, errors::CellDigestError> {
        let cell: &mut RelayRefWrapper = cell.into();

        if !cell.is_recognized() {
            return Err(errors::CellDigestError);
        }
        let digest = cell.digest();
        cell.set_digest([0; 4]);

        self.forward.update(cell.as_ref());
        let other = self.digest_forward();

        if digest != other[..4] {
            return Err(errors::CellDigestError);
        }
        Ok(other)
    }

    fn unwrap_digest_backward(
        &mut self,
        cell: &mut [u8; FIXED_CELL_SIZE],
    ) -> Result<Self::Digest, errors::CellDigestError> {
        let cell: &mut RelayRefWrapper = cell.into();

        if !cell.is_recognized() {
            return Err(errors::CellDigestError);
        }
        let digest = cell.digest();
        cell.set_digest([0; 4]);

        self.backward.update(cell.as_ref());
        let other = self.digest_backward();

        if digest != other[..4] {
            return Err(errors::CellDigestError);
        }
        Ok(other)
    }

    fn this_digest_forward(&self) -> Self::Digest {
        self.digest_forward()
    }

    fn this_digest_backward(&self) -> Self::Digest {
        self.digest_backward()
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
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use onioncloud_lowlevel::crypto::onion::OnionLayerFast;
/// use onioncloud_lowlevel::cache::{StandardCellCache, CellCacheExt};
///
/// let cache = Arc::<StandardCellCache>::default();
/// let id = std::num::NonZeroU32::new(1).unwrap();
///
/// // Start client
/// let client = OnionLayerFast::new();
///
/// // Send CREATE2 cell to server
/// let cell = cache.cache(client.create_cell(id, &cache));
///
/// // Start server and send CREATED2 cell to client
/// let (server, cell) = OnionLayerFast::derive_server_cached(&cell).unwrap();
///
/// // Finish client
/// let client = client.derive_client(&cell).unwrap();
/// ```
pub struct OnionLayerFast {
    key: Sha1Output,
}

impl OnionLayerFast {
    /// Starts handshake as client.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            key: ThreadRng::default().r#gen(),
        }
    }

    /// Get CREATE_FAST cell to be send to server.
    pub fn create_cell<C: CellCache>(&self, circuit: NonZeroU32, cache: &C) -> CreateFast {
        CreateFast::new(cache.get_cached(), circuit, self.key)
    }

    fn derive_server_inner(
        input: &CreateFast,
        cell: FixedCell,
    ) -> Result<(OnionLayerData, CreatedFast), errors::CircuitHandshakeError> {
        let key = ThreadRng::default().r#gen::<Sha1Output>();
        let DerivedFast { kh, keys } = derive_fast(input.key(), &key);

        trace!("server handshake successful");
        Ok((
            derive_keys(keys),
            CreatedFast::new(cell, input.circuit, key, kh),
        ))
    }

    /// Starts handshake as server.
    ///
    /// The resulting [`CreatedFast`] cell should be send to client to finish handshake.
    #[instrument(level = "debug", skip_all)]
    pub fn derive_server<C: CellCache>(
        cell: &CreateFast,
        cache: &C,
    ) -> Result<(OnionLayerData, CreatedFast), errors::CircuitHandshakeError> {
        Self::derive_server_inner(cell, cache.get_cached())
    }

    /// Same as [`derive_server`], but with [`Cached`] cell instead.
    #[instrument(level = "debug", skip_all)]
    pub fn derive_server_cached<C: CellCache + Clone>(
        cell: &Cached<CreateFast, C>,
    ) -> Result<(OnionLayerData, Cached<CreatedFast, C>), errors::CircuitHandshakeError> {
        let cache = Cached::cache(cell);
        let (this, cell) = Self::derive_server(cell, cache)?;
        Ok((this, cache.cache(cell)))
    }

    /// Finish handshake as client.
    #[instrument(level = "debug", skip_all)]
    pub fn derive_client(
        self,
        cell: &CreatedFast,
    ) -> Result<OnionLayerData, errors::CircuitHandshakeError> {
        let DerivedFast { kh, keys } = derive_fast(&self.key, cell.key());
        errors::CircuitHandshakeError::from_ct(kh.ct_eq(cell.derived()))?;

        trace!("client handshake successful");
        Ok(derive_keys(keys))
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct DerivedFast {
    kh: Sha1Output,
    keys: DerivedKeys,
}

fn derive_fast(key_x: &Sha1Output, key_y: &Sha1Output) -> DerivedFast {
    let mut out = DerivedFast::new_zeroed();

    let mut hasher = Sha1::new();
    hasher.update(key_x);
    hasher.update(key_y);

    let mut n = 255u8;
    for o in out.as_mut_bytes().chunks_mut(size_of::<Sha1Output>()) {
        n = n.wrapping_add(1);

        let mut hasher = hasher.clone();
        hasher.update(from_ref(&n));
        let hash = Sha1Output::from(hasher.finalize());
        o.copy_from_slice(&hash[..o.len()]);
    }

    out
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct NtorCreateData {
    id: RelayId,
    pk_b: EdPublicKey,
    pk_x: EdPublicKey,
}

impl AsRef<[u8]> for NtorCreateData {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct NtorCreatedData {
    pk_y: EdPublicKey,
    auth: Sha256Output,
}

impl AsRef<[u8]> for NtorCreatedData {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Ntor onion key.
///
/// Used for ntor handshake. Relays are expected to keep old onion keys (up to expiry).
pub struct NtorOnionKey {
    sk: StaticSecret,
    pk: PublicKey,
}

impl From<StaticSecret> for NtorOnionKey {
    fn from(sk: StaticSecret) -> Self {
        Self {
            pk: (&sk).into(),
            sk,
        }
    }
}

impl Display for NtorOnionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", print_ed(self.pk.as_bytes()))
    }
}

impl Debug for NtorOnionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Censor secret key
        f.debug_struct("NtorOnionKey")
            .field("pk", &print_ed(self.pk.as_bytes()))
            .finish_non_exhaustive()
    }
}

impl NtorOnionKey {
    pub fn public_key(&self) -> &EdPublicKey {
        self.pk.as_bytes()
    }
}

/// Ntor handshake.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use rand::prelude::*;
/// use x25519_dalek::StaticSecret;
/// use onioncloud_lowlevel::crypto::onion::{OnionLayerNtor, NtorOnionKey};
/// use onioncloud_lowlevel::crypto::relay::RelayId;
/// use onioncloud_lowlevel::cache::StandardCellCache;
///
/// let cache = Arc::<StandardCellCache>::default();
/// let id = std::num::NonZeroU32::new(1).unwrap();
///
/// // Server identity and keys
/// let mut rng = ThreadRng::default();
/// let server_id = rng.r#gen::<RelayId>();
/// let server_keys = [NtorOnionKey::from(StaticSecret::random_from_rng(&mut rng))];
/// let server_pk = server_keys[0].public_key();
///
/// // Start client
/// let client = OnionLayerNtor::new(&server_id, server_pk);
///
/// // Send CREATE2 cell to server
/// let cell = client.create_cell(id, &cache);
///
/// // Start server and send CREATED2 cell to client
/// let (server, cell) = OnionLayerNtor::derive_server_cached(&server_id, &server_keys, &cell).unwrap();
///
/// // Finish client
/// let client = client.derive_client(&cell).unwrap();
/// ```
pub struct OnionLayerNtor {
    sk_x: StaticSecret,
    pk_x: PublicKey,
    pk_b: PublicKey,
    id: RelayId,
}

impl OnionLayerNtor {
    /// Starts handshake as client.
    pub fn new(id: &RelayId, pk: &EdPublicKey) -> Self {
        let sk_x = StaticSecret::random_from_rng(ThreadRng::default());

        Self {
            pk_x: (&sk_x).into(),
            sk_x,
            pk_b: (*pk).into(),
            id: *id,
        }
    }

    /// Get client payload to be send to server.
    ///
    /// NOTE: It's recommended to use [`create_cell`] instead.
    /// This is only used if you want to set the protocol ID yourself.
    pub fn client_data(&self) -> impl AsRef<[u8]> {
        NtorCreateData {
            id: self.id,
            pk_b: self.pk_b.to_bytes(),
            pk_x: self.pk_x.to_bytes(),
        }
    }

    /// Get CREATE2 cell to be send to server.
    pub fn create_cell<C: CellCache + Clone>(
        &self,
        circuit: NonZeroU32,
        cache: &C,
    ) -> Cached<Create2, C> {
        cache.cache(
            Create2::new(cache.get_cached(), circuit, 2, self.client_data().as_ref()).unwrap(),
        )
    }

    /// Starts handshake as server.
    ///
    /// Returns an [`OnionLayerData`] and payload that must be send to client to finish handshake.
    ///
    /// For convenience, there is [`derive_server`] that produce ready-to-send CREATED2 cell.
    ///
    /// # Parameters
    ///
    /// - `id` : This relay ID.
    /// - `sk` : List of [`NtorOnionKey`] to be used.
    /// - `input` : Handshake payload from client.
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(id), onion_key))]
    pub fn derive_server_inner(
        id: &RelayId,
        sk: &[NtorOnionKey],
        input: &[u8],
    ) -> Result<(OnionLayerData, impl AsRef<[u8]>), errors::CircuitHandshakeError> {
        let Ok(data) = NtorCreateData::ref_from_bytes(input) else {
            return Err(errors::CircuitHandshakeErrorInner::CellFormatError.into());
        };

        let (derived, pk_y, auth) = ntor_derive_server(data, id, sk)?;
        trace!("server handshake successful");
        Ok((derived, NtorCreatedData { pk_y, auth }))
    }

    /// Inner implementation of derive server.
    fn derive_server_inner2(
        id: &RelayId,
        sk: &[NtorOnionKey],
        input: &Create2,
        cell: FixedCell,
    ) -> Result<(OnionLayerData, Created2), errors::CircuitHandshakeError> {
        let (derived, data) = Self::derive_server_inner(id, sk, input.data())?;
        Ok((
            derived,
            Created2::new(cell, input.circuit, data.as_ref()).unwrap(),
        ))
    }

    /// Starts handshake as server.
    ///
    /// The resulting [`Created2`] cell should be send to client to finish handshake.
    ///
    /// ⚠ the handshake type of [`Create2`] cell is not checked.
    /// It's the responsibility of user to dispatch handshake type.
    ///
    /// # Parameters
    ///
    /// - `id` : This relay ID.
    /// - `sk` : List of [`NtorOnionKey`] to be used.
    /// - `cell` : CREATE2 cell sent from client.
    /// - `cache` : Cell cache.
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(id)))]
    pub fn derive_server<C: CellCache>(
        id: &RelayId,
        sk: &[NtorOnionKey],
        cell: &Create2,
        cache: &C,
    ) -> Result<(OnionLayerData, Created2), errors::CircuitHandshakeError> {
        Self::derive_server_inner2(id, sk, cell, cache.get_cached())
    }

    /// Same as [`derive_server`], but with [`Cached`] cell instead.
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(id)))]
    pub fn derive_server_cached<C: CellCache + Clone>(
        id: &RelayId,
        sk: &[NtorOnionKey],
        cell: &Cached<Create2, C>,
    ) -> Result<(OnionLayerData, Cached<Created2, C>), errors::CircuitHandshakeError> {
        let cache = Cached::cache(cell);
        let (derived, cell) = Self::derive_server_inner2(id, sk, cell, cache.get_cached())?;
        Ok((derived, cache.cache(cell)))
    }

    /// Finish handshake as client.
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(&self.id), onion_key = %print_ed(self.pk_b.as_bytes())))]
    pub fn derive_client(
        self,
        cell: &Created2,
    ) -> Result<OnionLayerData, errors::CircuitHandshakeError> {
        let Ok(data) = NtorCreatedData::ref_from_bytes(cell.data()) else {
            return Err(errors::CircuitHandshakeErrorInner::CellFormatError.into());
        };

        let xy = self.sk_x.diffie_hellman(&PublicKey::from(data.pk_y));
        let xb = self.sk_x.diffie_hellman(&self.pk_b);

        let auth = ntor_auth(
            &xy,
            &xb,
            &self.id,
            self.pk_b.as_bytes(),
            self.pk_x.as_bytes(),
            &data.pk_y,
        )?;
        errors::CircuitHandshakeError::from_ct(auth.ct_eq(&data.auth))?;

        let ret = ntor_derive(
            xy,
            xb,
            &self.id,
            self.pk_b.as_bytes(),
            self.pk_x.as_bytes(),
            &data.pk_y,
        )?;
        trace!("client handshake successful");
        Ok(ret)
    }
}

fn ntor_derive_server(
    data: &NtorCreateData,
    id: &RelayId,
    sk: &[NtorOnionKey],
) -> Result<(OnionLayerData, EdPublicKey, Sha256Output), errors::CircuitHandshakeError> {
    if data.id != *id {
        return Err(errors::CircuitHandshakeErrorInner::ServerRelayIdMismatch(*id).into());
    }

    let Some(sk) = sk.iter().find(|k| *k.pk.as_bytes() == data.pk_b) else {
        return Err(errors::CircuitHandshakeErrorInner::ServerOnionKeyNotFound.into());
    };
    tracing::Span::current().record("onion_key", display(sk));

    let sk_y = StaticSecret::random_from_rng(ThreadRng::default());
    let pk_y = PublicKey::from(&sk_y).to_bytes();

    let pk_x = PublicKey::from(data.pk_x);
    let xy = sk_y.diffie_hellman(&pk_x);
    let xb = sk.sk.diffie_hellman(&pk_x);

    let auth = ntor_auth(&xy, &xb, id, sk.pk.as_bytes(), &data.pk_x, &pk_y)?;
    let keys = ntor_derive(xy, xb, id, sk.pk.as_bytes(), &data.pk_x, &pk_y)?;
    Ok((keys, pk_y, auth))
}

static PROTOID: &[u8] = b"ntor-curve25519-sha256-1";

fn ntor_auth(
    xy: &SharedSecret,
    xb: &SharedSecret,
    id: &RelayId,
    pk_b: &EdPublicKey,
    pk_x: &EdPublicKey,
    pk_y: &EdPublicKey,
) -> Result<Sha256Output, errors::CircuitHandshakeError> {
    if !xy.was_contributory() || !xb.was_contributory() {
        return Err(errors::CircuitHandshakeError::crypto());
    }

    let mut hmac = Hmac::<Sha256>::new_from_slice(PROTOID)?;
    hmac.update(b":verify");
    hmac.update(xy.as_bytes());
    hmac.update(xb.as_bytes());
    hmac.update(id);
    hmac.update(pk_b);
    hmac.update(pk_x);
    hmac.update(pk_y);
    hmac.update(PROTOID);
    let verify: Sha256Output = hmac.finalize().into_bytes().into();

    let mut hmac = Hmac::<Sha256>::new_from_slice(PROTOID)?;
    hmac.update(b":mac");
    hmac.update(&verify);
    hmac.update(id);
    hmac.update(pk_b);
    hmac.update(pk_y);
    hmac.update(pk_x);
    hmac.update(PROTOID);
    hmac.update(b"Server");
    Ok(hmac.finalize().into_bytes().into())
}

fn ntor_derive(
    xy: SharedSecret,
    xb: SharedSecret,
    id: &RelayId,
    pk_b: &EdPublicKey,
    pk_x: &EdPublicKey,
    pk_y: &EdPublicKey,
) -> Result<OnionLayerData, errors::CircuitHandshakeError> {
    let mut kdf = HkdfExtract::<Sha256>::new(Some(b"ntor-curve25519-sha256-1:key_extract"));
    kdf.input_ikm(xy.as_bytes());
    kdf.input_ikm(xb.as_bytes());
    kdf.input_ikm(id);
    kdf.input_ikm(pk_b);
    kdf.input_ikm(pk_x);
    kdf.input_ikm(pk_y);
    kdf.input_ikm(PROTOID);
    let (_, kdf) = kdf.finalize();

    let mut out = DerivedKeys::new_zeroed();
    kdf.expand_multi_info(&[PROTOID, b":key_expand"], out.as_mut_bytes())?;
    Ok(derive_keys(out))
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Ntor3CreateHeader {
    id: RelayId,
    pk_b: EdPublicKey,
    pk_x: EdPublicKey,
}

impl AsRef<[u8]> for Ntor3CreateHeader {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Ntor V3 handshake.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use rand::prelude::*;
/// use x25519_dalek::StaticSecret;
/// use onioncloud_lowlevel::crypto::onion::{OnionLayerNtor3, NtorOnionKey};
/// use onioncloud_lowlevel::crypto::relay::RelayId;
/// use onioncloud_lowlevel::cache::StandardCellCache;
///
/// let cache = Arc::<StandardCellCache>::default();
/// let id = std::num::NonZeroU32::new(1).unwrap();
///
/// // Server identity and keys
/// let mut rng = ThreadRng::default();
/// let server_id = rng.r#gen::<RelayId>();
/// let server_keys = [NtorOnionKey::from(StaticSecret::random_from_rng(&mut rng))];
/// let server_pk = server_keys[0].public_key();
///
/// // Start client and send CREATE2 cell to server
/// let mut client_msg = Vec::from(b"test_client");
/// let (client, mut cell) = OnionLayerNtor3::new_create(&server_id, server_pk, &mut client_msg, id, &cache).unwrap();
///
/// // Start server and send CREATED2 cell to client
/// let (server, mut cell) = OnionLayerNtor3::derive_server_cached(&server_id, &server_keys, &mut cell, |v| {
///     // Process client message
///     Ok::<_, onioncloud_lowlevel::errors::CircuitHandshakeError>(Vec::from(b"test_server"))
/// }).unwrap();
///
/// // Finish client
/// let (client, server_msg) = client.derive_client(&mut cell).unwrap();
/// ```
pub struct OnionLayerNtor3 {
    sk_x: StaticSecret,
    pk_x: PublicKey,
    pk_b: PublicKey,
    xb: SharedSecret,
    id: RelayId,
    mac: Sha256Output,
}

static NTOR3_CIRC_VERIFY: &[u8] = b"circuit extend";

impl OnionLayerNtor3 {
    /// Starts handshake as client (in raw).
    ///
    /// You might want [`new_create`] instead of this internal function.
    ///
    /// It's useful if you want to roll out your own ntor-v3 handshake.
    /// Afterwards, send client payload to server (see [`client_header`]).
    ///
    /// # Parameters
    ///
    /// - `id` : Peer relay ID.
    /// - `pk` : Peer relay onion key.
    /// - `client_msg` : Client message. It will be encrypted afterwards.
    /// - `verify` : Shared verification string.
    pub fn new_inner(
        id: &RelayId,
        pk: &EdPublicKey,
        client_msg: &mut [u8],
        verify: &[u8],
    ) -> Result<Self, errors::CircuitHandshakeError> {
        let sk_x = StaticSecret::random_from_rng(ThreadRng::default());
        let pk_x = PublicKey::from(&sk_x);

        let pk_b = PublicKey::from(*pk);
        let xb = sk_x.diffie_hellman(&pk_b);
        if !xb.was_contributory() {
            return Err(errors::CircuitHandshakeError::crypto());
        }

        Ok(Self {
            mac: ntor3_client_derive_client_mac(&xb, id, pk_x.as_bytes(), pk, client_msg, verify)?,
            sk_x,
            pk_x,
            pk_b,
            xb,
            id: *id,
        })
    }

    /// Get client message MAC.
    ///
    /// NOTE: `client_msg_*` methods should be used only when using [`new_inner`].
    pub fn client_msg_mac(&self) -> Sha256Output {
        self.mac
    }

    /// Get client payload header to be send to server.
    ///
    /// The entire client payload is:
    ///
    /// ```text
    /// header | ENC(client_msg) | mac
    /// ```
    ///
    /// NOTE: This method should be used only when using [`new_inner`].
    pub fn client_header(&self) -> impl AsRef<[u8]> {
        Ntor3CreateHeader {
            id: self.id,
            pk_b: self.pk_b.to_bytes(),
            pk_x: self.pk_x.to_bytes(),
        }
    }

    fn new_circuit_inner(
        id: &RelayId,
        pk: &EdPublicKey,
        client_msg: &mut [u8],
        circuit: NonZeroU32,
        cell: FixedCell,
    ) -> Result<(Self, Create2), errors::CircuitHandshakeError> {
        let ret = Self::new_inner(id, pk, client_msg, NTOR3_CIRC_VERIFY)?;
        let cell = Create2::new_multipart(
            cell,
            circuit,
            3,
            [
                ret.client_header().as_ref(),
                client_msg,
                &ret.client_msg_mac(),
            ],
        )
        .unwrap();
        Ok((ret, cell))
    }

    /// Starts circuit handshake as client.
    ///
    /// The resulting [`Create2`] cell should be send to server.
    ///
    /// # Parameters
    ///
    /// - `id` : Peer relay ID.
    /// - `pk` : Peer relay onion key.
    /// - `client_msg` : Client message. It will be encrypted afterwards.
    /// - `circuit` : Circuit ID.
    /// - `cache` : Cell cache.
    pub fn new_create<C: CellCache + Clone>(
        id: &RelayId,
        pk: &EdPublicKey,
        client_msg: &mut [u8],
        circuit: NonZeroU32,
        cache: &C,
    ) -> Result<(Self, Cached<Create2, C>), errors::CircuitHandshakeError> {
        let (ret, cell) = Self::new_circuit_inner(id, pk, client_msg, circuit, cache.get_cached())?;
        Ok((ret, cache.cache(cell)))
    }

    /// Process and decrypt client message.
    ///
    /// See [`OnionLayerNtor3Server::derive`] for more details.
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(id)))]
    pub fn derive_server_inner<'a>(
        id: &'a RelayId,
        sk: &'a [NtorOnionKey],
        input: &'a mut [u8],
    ) -> Result<(OnionLayerNtor3Server<'a>, &'a mut [u8]), errors::CircuitHandshakeError> {
        OnionLayerNtor3Server::derive(id, sk, input, NTOR3_CIRC_VERIFY)
    }

    /// Starts handshake as server.
    ///
    /// The resulting [`Created2`] cell should be send to client to finish handshake.
    ///
    /// # Parameters
    ///
    /// - `id` : Relay ID.
    /// - `sk` : Relay onion keys.
    /// - `cell` : [`Create2`] cell sent from client.
    /// - `cache` : Cell cache.
    /// - `server_fn` : Closure that process client message and returns server message.
    ///   It may reuse client message slice to reduce allocation.
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(id)))]
    pub fn derive_server<
        'a,
        E: From<errors::CircuitHandshakeError>,
        C: CellCache,
        O: 'a + AsRef<[u8]> + AsMut<[u8]>,
    >(
        id: &'a RelayId,
        sk: &'a [NtorOnionKey],
        cell: &'a mut Create2,
        cache: &C,
        server_fn: impl FnOnce(&'a mut [u8]) -> Result<O, E>,
    ) -> Result<(OnionLayerData, Created2), E> {
        let circuit = cell.circuit;
        let (server, client_msg) = Self::derive_server_inner(id, sk, cell.data_mut())?;
        let mut server_msg = server_fn(client_msg)?;
        let (derived, data) = server.finalize(server_msg.as_mut())?;
        let cell = Created2::new_multipart(
            cache.get_cached(),
            circuit,
            [data.as_ref(), server_msg.as_ref()],
        )
        .unwrap();
        Ok((derived, cell))
    }

    /// Same as [`derive_server`], but with [`Cached`].
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(id)))]
    pub fn derive_server_cached<
        'a,
        E: From<errors::CircuitHandshakeError>,
        C: CellCache + Clone,
        O: 'a + AsRef<[u8]> + AsMut<[u8]>,
    >(
        id: &'a RelayId,
        sk: &'a [NtorOnionKey],
        cell: &'a mut Cached<Create2, C>,
        server_fn: impl FnOnce(&'a mut [u8]) -> Result<O, E>,
    ) -> Result<(OnionLayerData, Cached<Created2, C>), E> {
        let (cell, cache) = Cached::split_mut(cell);
        let (derived, cell) = Self::derive_server(id, sk, cell, cache, server_fn)?;
        Ok((derived, cache.cache(cell)))
    }

    /// Raw method to derive client keys.
    ///
    /// This is only used if you want to roll out your own handshake.
    /// Use [`derive_client`] instead.
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(&self.id), onion_key = %print_ed(self.pk_b.as_bytes())))]
    pub fn derive_client_inner<'a>(
        self,
        data: &'a mut [u8],
        verify: &[u8],
    ) -> Result<(OnionLayerData, &'a mut [u8]), errors::CircuitHandshakeError> {
        let Ok((header, server_msg)) = NtorCreatedData::mut_from_prefix(data) else {
            return Err(errors::CircuitHandshakeErrorInner::CellFormatError.into());
        };

        let xy = self.sk_x.diffie_hellman(&header.pk_y.into());

        let (keys, verify) = ntor3_derive_keystream(
            &xy,
            &self.xb,
            &self.id,
            self.pk_b.as_bytes(),
            self.pk_x.as_bytes(),
            &header.pk_y,
            verify,
        )?;
        let auth = ntor3_derive_server_mac(
            &self.id,
            self.pk_b.as_bytes(),
            self.pk_x.as_bytes(),
            &header.pk_y,
            &verify,
            &self.mac,
            server_msg,
        );
        errors::CircuitHandshakeError::from_ct(auth.ct_eq(&header.auth))?;

        Cipher256::new(&keys.enc.into(), &Default::default()).try_apply_keystream(server_msg)?;

        trace!("client handshake successful");
        Ok((derive_keys(keys.keys), server_msg))
    }

    /// Finish handshake as client.
    ///
    /// Also returns decrypted server message.
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(&self.id), onion_key = %print_ed(self.pk_b.as_bytes())))]
    pub fn derive_client(
        self,
        cell: &mut Created2,
    ) -> Result<(OnionLayerData, &mut [u8]), errors::CircuitHandshakeError> {
        self.derive_client_inner(cell.data_mut(), NTOR3_CIRC_VERIFY)
    }
}

/// Ntor3 handshake (server side).
///
/// You might not want to use this. Instead use convenience functions like [`OnionLayerNtor3::derive_server`].
pub struct OnionLayerNtor3Server<'a> {
    pk_y: PublicKey,
    xb: SharedSecret,
    xy: SharedSecret,

    id: &'a RelayId,
    b: &'a NtorOnionKey,
    pk_x: &'a EdPublicKey,
    verify: &'a [u8],
    mac: &'a Sha256Output,
}

impl<'a> OnionLayerNtor3Server<'a> {
    /// Process and decrypt client message.
    ///
    /// # Parameters
    ///
    /// - `id` : Relay ID.
    /// - `sk` : Relay onion keys.
    /// - `input` : CREATE2 cell message.
    /// - `verify` : Shared verification string.
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(id), onion_key))]
    pub fn derive(
        id: &'a RelayId,
        sk: &'a [NtorOnionKey],
        input: &'a mut [u8],
        verify: &'a [u8],
    ) -> Result<(Self, &'a mut [u8]), errors::CircuitHandshakeError> {
        let Some((header, (client_msg, mac))) = Ntor3CreateHeader::mut_from_prefix(input)
            .ok()
            .and_then(|(header, rest)| Some((header, Sha256Output::mut_from_suffix(rest).ok()?)))
        else {
            return Err(errors::CircuitHandshakeErrorInner::CellFormatError.into());
        };

        if header.id != *id {
            return Err(errors::CircuitHandshakeErrorInner::ServerRelayIdMismatch(*id).into());
        }

        let Some(sk) = sk.iter().find(|k| *k.pk.as_bytes() == header.pk_b) else {
            return Err(errors::CircuitHandshakeErrorInner::ServerOnionKeyNotFound.into());
        };
        tracing::Span::current().record("onion_key", display(sk));

        let pk_x = PublicKey::from(header.pk_x);
        let xb = sk.sk.diffie_hellman(&pk_x);
        ntor3_server_decrypt_client_msg(
            &xb,
            id,
            &header.pk_x,
            sk.pk.as_bytes(),
            client_msg,
            mac,
            verify,
        )?;

        let sk_y = StaticSecret::random_from_rng(ThreadRng::default());
        let pk_y = PublicKey::from(&sk_y);
        let xy = sk_y.diffie_hellman(&pk_x);

        Ok((
            Self {
                pk_y,
                xb,
                xy,
                id,
                b: sk,
                pk_x: &header.pk_x,
                verify,
                mac,
            },
            client_msg,
        ))
    }

    /// Finish handshake as server.
    ///
    /// Returns [`OnionLayerData`] and CREATED2 cell data header.
    /// Server message will be encrypted afterwards.
    /// The full format of cell content is:
    ///
    /// ```text
    /// header | server_msg
    /// ```
    #[instrument(level = "debug", skip_all, fields(id = %print_hex(self.id), onion_key = %self.b))]
    pub fn finalize(
        self,
        server_msg: &mut [u8],
    ) -> Result<(OnionLayerData, impl use<'a> + AsRef<[u8]>), errors::CircuitHandshakeError> {
        let (keys, verify) = ntor3_derive_keystream(
            &self.xy,
            &self.xb,
            self.id,
            self.b.pk.as_bytes(),
            self.pk_x,
            self.pk_y.as_bytes(),
            self.verify,
        )?;

        Cipher256::new(&keys.enc.into(), &Default::default()).try_apply_keystream(server_msg)?;

        let auth = ntor3_derive_server_mac(
            self.id,
            self.b.pk.as_bytes(),
            self.pk_x,
            self.pk_y.as_bytes(),
            &verify,
            self.mac,
            server_msg,
        );

        trace!("server handshake successful");
        Ok((
            derive_keys(keys.keys),
            NtorCreatedData {
                pk_y: self.pk_y.to_bytes(),
                auth,
            },
        ))
    }
}

static PROTOID3: &[u8] = b"ntor3-curve25519-sha3_256-1";

fn update_encap(out: &mut impl digest::Update, data: &[&[u8]]) {
    out.update(
        &data
            .iter()
            .map(|v| v.len() as u64)
            .sum::<u64>()
            .to_be_bytes(),
    );
    for v in data {
        out.update(v);
    }
}

fn ntor3_hash(key_suffix: &[u8]) -> Sha3_256 {
    let mut hasher = Sha3_256::default();
    update_encap(&mut hasher, &[PROTOID3, key_suffix]);
    hasher
}

fn ntor3_kdf(key_suffix: &[u8]) -> Shake256 {
    let mut hasher = Shake256::default();
    update_encap(&mut hasher, &[PROTOID3, key_suffix]);
    hasher
}

fn ntor3_mac(key_suffix: &[u8], key: &[u8]) -> Sha3_256 {
    let mut hasher = Sha3_256::default();
    update_encap(&mut hasher, &[PROTOID3, key_suffix]);
    update_encap(&mut hasher, &[key]);
    hasher
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Ntor3DerivedClientMsg {
    enc: CipherKey256,
    mac: Sha256Output,
}

fn ntor3_derive_client_mac_phase1(
    xb: &SharedSecret,
    id: &RelayId,
    pk_x: &EdPublicKey,
    pk_b: &EdPublicKey,
    ver: &[u8],
) -> Ntor3DerivedClientMsg {
    use digest::Update;

    let mut kdf = ntor3_kdf(b":kdf_phase1");
    kdf.update(xb.as_bytes());
    kdf.update(id);
    kdf.update(pk_x);
    kdf.update(pk_b);
    kdf.update(PROTOID3);
    update_encap(&mut kdf, &[ver]);

    let mut out = Ntor3DerivedClientMsg::new_zeroed();
    kdf.finalize_xof_into(out.as_mut_bytes());
    out
}

fn ntor3_derive_client_mac(
    id: &RelayId,
    pk_x: &EdPublicKey,
    pk_b: &EdPublicKey,
    mac: &Sha256Output,
    client_msg: &[u8],
) -> Sha256Output {
    let mut mac = ntor3_mac(b":msg_mac", mac);
    mac.update(id);
    mac.update(pk_b);
    mac.update(pk_x);
    mac.update(client_msg);
    mac.finalize().into()
}

fn ntor3_client_derive_client_mac(
    xb: &SharedSecret,
    id: &RelayId,
    pk_x: &EdPublicKey,
    pk_b: &EdPublicKey,
    client_msg: &mut [u8],
    ver: &[u8],
) -> Result<Sha256Output, cipher::StreamCipherError> {
    let Ntor3DerivedClientMsg { enc, mac } =
        ntor3_derive_client_mac_phase1(xb, id, pk_x, pk_b, ver);

    Cipher256::new(&enc.into(), &Default::default()).try_apply_keystream(client_msg)?;
    Ok(ntor3_derive_client_mac(id, pk_x, pk_b, &mac, client_msg))
}

fn ntor3_server_decrypt_client_msg(
    xb: &SharedSecret,
    id: &RelayId,
    pk_x: &EdPublicKey,
    pk_b: &EdPublicKey,
    client_msg: &mut [u8],
    mac_value: &Sha256Output,
    ver: &[u8],
) -> Result<(), errors::CircuitHandshakeError> {
    if !xb.was_contributory() {
        return Err(errors::CircuitHandshakeError::crypto());
    }

    let Ntor3DerivedClientMsg { enc, mac } =
        ntor3_derive_client_mac_phase1(xb, id, pk_x, pk_b, ver);

    let mac = ntor3_derive_client_mac(id, pk_x, pk_b, &mac, client_msg);
    errors::CircuitHandshakeError::from_ct(mac.ct_eq(mac_value))?;

    Cipher256::new(&enc.into(), &Default::default()).try_apply_keystream(client_msg)?;
    Ok(())
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Ntor3DerivedKeystream {
    enc: CipherKey256,
    keys: DerivedKeys,
}

fn ntor3_derive_keystream(
    xy: &SharedSecret,
    xb: &SharedSecret,
    id: &RelayId,
    pk_b: &EdPublicKey,
    pk_x: &EdPublicKey,
    pk_y: &EdPublicKey,
    ver: &[u8],
) -> Result<(Ntor3DerivedKeystream, Sha256Output), errors::CircuitHandshakeError> {
    if !xy.was_contributory() {
        return Err(errors::CircuitHandshakeError::crypto());
    }

    let mut hasher = ntor3_hash(b":key_seed");
    hasher.update(xy.as_bytes());
    hasher.update(xb.as_bytes());
    hasher.update(id);
    hasher.update(pk_b);
    hasher.update(pk_x);
    hasher.update(pk_y);
    hasher.update(PROTOID3);
    update_encap(&mut hasher, &[ver]);
    let key_seed = hasher.finalize();

    let mut hasher = ntor3_hash(b":verify");
    hasher.update(xy.as_bytes());
    hasher.update(xb.as_bytes());
    hasher.update(id);
    hasher.update(pk_b);
    hasher.update(pk_x);
    hasher.update(pk_y);
    hasher.update(PROTOID3);
    update_encap(&mut hasher, &[ver]);
    let verify = hasher.finalize();

    let mut kdf = ntor3_kdf(b":kdf_final");
    digest::Update::update(&mut kdf, &key_seed);
    let mut out = Ntor3DerivedKeystream::new_zeroed();
    kdf.finalize_xof_into(out.as_mut_bytes());

    Ok((out, verify.into()))
}

fn ntor3_derive_server_mac(
    id: &RelayId,
    pk_b: &EdPublicKey,
    pk_x: &EdPublicKey,
    pk_y: &EdPublicKey,
    verify: &Sha256Output,
    mac: &Sha256Output,
    msg: &[u8],
) -> Sha256Output {
    let mut hasher = ntor3_hash(b":auth_final");
    hasher.update(verify);
    hasher.update(id);
    hasher.update(pk_b);
    hasher.update(pk_y);
    hasher.update(pk_x);
    hasher.update(mac);
    hasher.update(msg);
    hasher.update(PROTOID3);
    hasher.update(b"Server");
    hasher.finalize().into()
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct DerivedKeys {
    df: Sha1Output,
    db: Sha1Output,
    kf: CipherKey128,
    kb: CipherKey128,
}

fn derive_keys(keys: DerivedKeys) -> OnionLayerData {
    OnionLayerData {
        encrypt: OnionLayer128::new(keys.kf, keys.kb),
        digest: CircuitDigest::new(keys.df, keys.db),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::cache::NullCellCache;
    use crate::cell::relay::Relay;

    #[test]
    fn test_handshake_fast() {
        let cache = NullCellCache;
        let id = NonZeroU32::new(1).unwrap();

        // Do handshake
        let (mut client, mut server) = {
            let client = OnionLayerFast::new();
            let cell = cache.cache(client.create_cell(id, &cache));
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

    #[test]
    fn test_handshake_ntor() {
        let cache = NullCellCache;
        let id = NonZeroU32::new(1).unwrap();

        // Do handshake
        let (mut client, mut server) = {
            let mut rng = ThreadRng::default();
            let server_id = rng.r#gen::<RelayId>();
            let server_keys = [NtorOnionKey::from(StaticSecret::random_from_rng(&mut rng))];
            let server_pk = server_keys[0].public_key();

            let client = OnionLayerNtor::new(&server_id, server_pk);
            let cell = client.create_cell(id, &cache);
            let (server, cell) =
                OnionLayerNtor::derive_server_cached(&server_id, &server_keys, &cell).unwrap();
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

    #[test]
    fn test_handshake_ntor3() {
        let cache = NullCellCache;
        let id = NonZeroU32::new(1).unwrap();

        // Do handshake
        let (mut client, mut server) = {
            let mut rng = ThreadRng::default();
            let server_id = rng.r#gen::<RelayId>();
            let server_keys = [NtorOnionKey::from(StaticSecret::random_from_rng(&mut rng))];
            let server_pk = server_keys[0].public_key();

            let mut client_msg = [1, 2, 3, 4];
            let (client, mut cell) =
                OnionLayerNtor3::new_create(&server_id, server_pk, &mut client_msg, id, &cache)
                    .unwrap();
            let (server, mut cell) =
                OnionLayerNtor3::derive_server_cached(&server_id, &server_keys, &mut cell, |v| {
                    assert_eq!(v, [1, 2, 3, 4]);
                    v.reverse();
                    Ok::<_, errors::CircuitHandshakeError>(v)
                })
                .unwrap();
            let (client, server_msg) = client.derive_client(&mut cell).unwrap();
            assert_eq!(server_msg, [4, 3, 2, 1]);
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
