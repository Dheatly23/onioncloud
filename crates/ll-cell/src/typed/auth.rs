//! `AUTH_CHALLENGE` and `AUTHENTICATE` cell type.

use std::fmt::{Debug, Formatter, Result as FmtResult, from_fn};
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::ptr::{from_mut, from_ref};
use std::slice::{from_raw_parts, from_raw_parts_mut};

use base64ct::{Base64Unpadded, Encoding};
use zerocopy::byteorder::big_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::cell::{AutoReturnVariable, Cell, CellHeader, TryFromCell};
use crate::error::{CellCastError, CellFormatError, NonZeroCircID, VariableCellTooLong};
use crate::utils::{base64u_encode, encoded_len};
use crate::variable::VariableCell;

/// `AUTH_CHALLENGE` header.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct AuthChallengeHeader {
    challenge: [u8; 32],
    n_methods: U16,
}

/// `AUTH_CHALLENGE` cell format.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct AuthChallengeData {
    header: AuthChallengeHeader,
    methods: [U16],
}

/// `AUTH_CHALLENGE` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/negotiating-channels.html#AUTH-CHALLENGE-cells).
pub struct AuthChallenge {
    cell: VariableCell,
}

impl Debug for AuthChallenge {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("AuthChallenge")
            .field(
                "challenge",
                &from_fn(|f| {
                    const LEN: usize = encoded_len(32);
                    let mut a = [0u8; LEN];
                    let out = Base64Unpadded::encode(self.challenge(), &mut a)
                        .expect("conversion must never fail");
                    f.write_str(out)
                }),
            )
            .field("methods", &self.methods())
            .finish()
    }
}

impl TryFromCell for AuthChallenge {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnVariable::new(cell)?
            && cell.header().command == Self::ID
        {
            if cell.header().circuit != 0 {
                Err(NonZeroCircID.into())
            } else if Self::validate_cell(cell.data().data()) {
                Ok(Some(Self {
                    cell: cell.into_inner().1,
                }))
            } else {
                Err(CellFormatError.into())
            }
        } else {
            Ok(None)
        }
    }
}

impl From<AuthChallenge> for Cell {
    fn from(cell: AuthChallenge) -> Self {
        Self::from_variable(
            CellHeader {
                command: AuthChallenge::ID,
                circuit: 0,
            },
            cell.into_inner(),
        )
    }
}

impl From<AuthChallenge> for VariableCell {
    #[inline]
    fn from(v: AuthChallenge) -> VariableCell {
        v.into_inner()
    }
}

impl AsRef<VariableCell> for AuthChallenge {
    #[inline]
    fn as_ref(&self) -> &VariableCell {
        self.inner()
    }
}

impl AuthChallenge {
    /// Cell ID of `AUTH_CHALLENGE`.
    pub const ID: u8 = 130;

    /// Creates new [`AuthChallenge`] cell from slice of methods.
    ///
    /// # Errors
    ///
    /// Returns [`VariableCellTooLong`] if cell is too long.
    pub fn try_from_slice(
        challenge: [u8; 32],
        methods: &[u16],
    ) -> Result<Self, VariableCellTooLong> {
        let len = size_of::<AuthChallengeHeader>().saturating_add(methods.len().saturating_mul(2));
        if let Some(len) = NonZeroUsize::new(len)
            && len.get() > 65535
        {
            return Err(VariableCellTooLong { len });
        }

        let mut v = vec![0u8; len].into_boxed_slice();
        let t = AuthChallengeData::mut_from_bytes(&mut v).unwrap();
        t.header.challenge = challenge;
        t.header.n_methods.set(methods.len().try_into().unwrap());
        debug_assert_eq!(t.methods.len(), methods.len());
        for (i, &v) in methods.iter().enumerate() {
            // SAFETY: Length is already checked.
            unsafe { t.methods.get_unchecked_mut(i).set(v) };
        }

        debug_assert!(Self::validate_cell(&v), "cell format should be valid");
        v.try_into().map(|cell| Self { cell })
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &VariableCell {
        &self.cell
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> VariableCell {
        self.cell
    }

    /// Gets reference to challenge string.
    #[inline]
    #[must_use]
    pub fn challenge(&self) -> &[u8; 32] {
        // SAFETY: Cell format has been validated.
        unsafe { &(*from_ref(self.cell.data()).cast::<AuthChallengeHeader>()).challenge }
    }

    /// Gets mutable reference to challenge string.
    #[inline]
    #[must_use]
    pub fn challenge_mut(&mut self) -> &mut [u8; 32] {
        // SAFETY: Cell format has been validated.
        unsafe { &mut (*from_mut(self.cell.data_mut()).cast::<AuthChallengeHeader>()).challenge }
    }

    /// Gets reference to methods.
    #[inline]
    #[must_use]
    pub fn methods(&self) -> &[U16] {
        // SAFETY: Cell format has been validated.
        unsafe {
            let s = self.cell.data();
            let t = &*from_ref(s).cast::<AuthChallengeHeader>();
            from_raw_parts(
                from_ref(s.get_unchecked(size_of::<AuthChallengeHeader>()..)).cast::<U16>(),
                t.n_methods.get() as usize,
            )
        }
    }

    /// Gets mutable reference to methods.
    #[inline]
    #[must_use]
    pub fn methods_mut(&mut self) -> &mut [U16] {
        // SAFETY: Cell format has been validated.
        unsafe {
            let s = self.cell.data_mut();
            let t = &*from_ref(s).cast::<AuthChallengeHeader>();
            from_raw_parts_mut(
                from_mut(s.get_unchecked_mut(size_of::<AuthChallengeHeader>()..)).cast::<U16>(),
                t.n_methods.get() as usize,
            )
        }
    }

    fn validate_cell(s: &[u8]) -> bool {
        let Ok((t, _)) = AuthChallengeData::ref_from_prefix_with_elems(s, 0) else {
            return false;
        };

        AuthChallengeData::ref_from_prefix_with_elems(s, t.header.n_methods.get() as usize).is_ok()
    }
}

/// `AUTHENTICATE` header.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct AuthenticateHeader {
    ty: U16,
    len: U16,
}

/// `AUTHENTICATE` cell format.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct AuthenticateData {
    header: AuthenticateHeader,
    data: [u8],
}

/// `AUTHENTICATE` cell.
///
/// See also: [spec](https://spec.torproject.org/tor-spec/negotiating-channels.html#AUTHENTICATE-cells).
pub struct Authenticate {
    cell: VariableCell,
}

impl Debug for Authenticate {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("Authenticate")
            .field("auth_ty", &self.auth_ty())
            .field("payload", &base64u_encode(self.payload()))
            .finish()
    }
}

impl TryFromCell for Authenticate {
    type Error = CellCastError;

    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, Self::Error> {
        if let Some(cell) = AutoReturnVariable::new(cell)?
            && cell.header().command == Self::ID
        {
            if cell.header().circuit != 0 {
                Err(NonZeroCircID.into())
            } else if Self::validate_cell(cell.data().data()) {
                Ok(Some(Self {
                    cell: cell.into_inner().1,
                }))
            } else {
                Err(CellFormatError.into())
            }
        } else {
            Ok(None)
        }
    }
}

impl From<Authenticate> for Cell {
    fn from(cell: Authenticate) -> Self {
        Self::from_variable(
            CellHeader {
                command: Authenticate::ID,
                circuit: 0,
            },
            cell.into_inner(),
        )
    }
}

impl From<Authenticate> for VariableCell {
    #[inline]
    fn from(v: Authenticate) -> VariableCell {
        v.into_inner()
    }
}

impl AsRef<VariableCell> for Authenticate {
    #[inline]
    fn as_ref(&self) -> &VariableCell {
        self.inner()
    }
}

impl Authenticate {
    /// Cell ID of `AUTHENTICATE`.
    pub const ID: u8 = 131;

    /// Creates new [`Authenticate`] cell.
    ///
    /// # Errors
    ///
    /// Returns [`VariableCellTooLong`] if cell is too long.
    pub fn new(auth_ty: u16, payload: &[u8]) -> Result<Self, VariableCellTooLong> {
        let len = size_of::<AuthenticateHeader>().saturating_add(payload.len());
        if let Some(len) = NonZeroUsize::new(len)
            && len.get() > 65535
        {
            return Err(VariableCellTooLong { len });
        }

        let mut v = vec![0u8; len].into_boxed_slice();
        let t = AuthenticateData::mut_from_bytes(&mut v).unwrap();
        t.header.ty.set(auth_ty);
        t.header.len.set(payload.len().try_into().unwrap());
        t.data.copy_from_slice(payload);

        debug_assert!(Self::validate_cell(&v), "cell format should be valid");
        v.try_into().map(|cell| Self { cell })
    }

    /// Gets reference to inner.
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &VariableCell {
        &self.cell
    }

    /// Unwraps into inner.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> VariableCell {
        self.cell
    }

    /// Gets authentication method.
    #[inline]
    #[must_use]
    pub fn auth_ty(&self) -> u16 {
        // SAFETY: Cell format has been validated.
        unsafe {
            (*from_ref(self.cell.data()).cast::<AuthenticateHeader>())
                .ty
                .get()
        }
    }

    /// Sets authentication method.
    #[inline]
    #[must_use]
    pub fn set_auth_ty(&mut self, value: u16) {
        // SAFETY: Cell format has been validated.
        unsafe {
            (*from_mut(self.cell.data_mut()).cast::<AuthenticateHeader>())
                .ty
                .set(value)
        }
    }

    /// Gets reference to payload.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        // SAFETY: Cell format has been validated.
        unsafe {
            let s = self.cell.data();
            let l = (*from_ref(s).cast::<AuthenticateHeader>()).len.get() as usize;
            s.get_unchecked(size_of::<AuthenticateHeader>()..)
                .get_unchecked(..l)
        }
    }

    /// Gets mutable reference to payload.
    #[inline]
    #[must_use]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // SAFETY: Cell format has been validated.
        unsafe {
            let s = self.cell.data_mut();
            let l = (*from_ref(s).cast::<AuthenticateHeader>()).len.get() as usize;
            s.get_unchecked_mut(size_of::<AuthenticateHeader>()..)
                .get_unchecked_mut(..l)
        }
    }

    fn validate_cell(s: &[u8]) -> bool {
        let Ok(t) = AuthenticateData::ref_from_bytes(s) else {
            return false;
        };

        t.header.len.get() as usize <= t.data.len()
    }
}
