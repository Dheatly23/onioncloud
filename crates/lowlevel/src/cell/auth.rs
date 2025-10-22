use std::mem::size_of;

use zerocopy::byteorder::big_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt, Unaligned};

use super::{Cell, CellHeader, CellLike, CellRef, TryFromCell, VariableCell, to_variable_with};
use crate::errors;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct AuthChallengeHeader {
    challenge: [u8; 32],
    n_methods: U16,
}

/// Represents a AUTH_CHALLENGE cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthChallenge(VariableCell);

impl From<AuthChallenge> for Cell {
    fn from(v: AuthChallenge) -> Cell {
        Cell::from_variable(CellHeader::new(0, AuthChallenge::ID), v.into_inner())
    }
}

impl TryFromCell for AuthChallenge {
    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(
            c @ Cell {
                command: Self::ID, ..
            },
        ) = cell.as_ref()
        else {
            return Ok(None);
        };
        if c.circuit != 0 {
            return Err(errors::CellFormatError);
        }
        to_variable_with(cell, Self::check).map(|v| v.map(|v| unsafe { Self::from_cell(v) }))
    }
}

impl CellLike for AuthChallenge {
    fn circuit(&self) -> u32 {
        0
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Variable(&self.0)
    }
}

impl AuthChallenge {
    /// AUTH_CHALLENGE command ID.
    pub const ID: u8 = 130;

    /// Create new AUTH_CHALLENGE cell from a [`VariableCell`].
    ///
    /// # Safety
    ///
    /// Data must be a valid AUTH_CHALLENGE cell.
    pub unsafe fn from_cell(data: VariableCell) -> Self {
        debug_assert!(Self::check(data.data()));
        Self(data)
    }

    /// Create AUTH_CHALLENGE cell.
    ///
    /// Note that methods is not deduplicated nor checked for validity (e.g zero is not allowed).
    /// It is the responsibility of implementer to do all that.
    ///
    /// # Error
    ///
    /// Errors if data does not fit the cell (eg. methods length is > 65535).
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::auth::AuthChallenge;
    ///
    /// let cell = AuthChallenge::new(&[0; 32], &[1, 2, 3]).unwrap();
    /// ```
    pub fn new(
        challenge: &[u8; 32],
        methods: &[u16],
    ) -> Result<Self, errors::CellLengthOverflowError> {
        let n = u16::try_from(methods.len()).map_err(|_| errors::CellLengthOverflowError)?;

        let len = size_of::<AuthChallengeHeader>() + size_of::<U16>() * methods.len();
        if len > 65535 {
            return Err(errors::CellLengthOverflowError);
        }
        // TODO: Replace this with equivalent of new_box_zeroed_with_elems but with Vec<u8>
        let mut v = vec![0; len];
        let (header, rest) =
            AuthChallengeHeader::mut_from_prefix(&mut v).expect("data must be valid");
        header.challenge = *challenge;
        header.n_methods.set(n);

        let (methods_o, _) =
            <[U16]>::mut_from_prefix_with_elems(rest, methods.len()).expect("data must be valid");
        for (i, o) in methods_o.iter_mut().enumerate() {
            o.set(methods[i]);
        }

        // SAFETY: Data is valid
        unsafe { Ok(Self::from_cell(VariableCell::from(v))) }
    }

    /// Gets the challenge string.
    pub fn challenge(&self) -> &[u8; 32] {
        &AuthChallengeHeader::ref_from_prefix(self.0.data())
            .expect("data must be valid")
            .0
            .challenge
    }

    /// Gets length of methods.
    pub fn len(&self) -> usize {
        AuthChallengeHeader::ref_from_prefix(self.0.data())
            .expect("data must be valid")
            .0
            .n_methods
            .get()
            .into()
    }

    /// Returns [`true`] if there is no methods.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gets reference into methods.
    pub fn methods(&self) -> &[U16] {
        let (header, rest) =
            AuthChallengeHeader::ref_from_prefix(self.0.data()).expect("data must be valid");
        <[U16]>::ref_from_prefix_with_elems(rest, header.n_methods.get().into())
            .expect("data must be valid")
            .0
    }

    /// Unwraps into inner [`VariableCell`].
    pub fn into_inner(self) -> VariableCell {
        self.0
    }

    fn check(data: &[u8]) -> bool {
        let Ok((header, rest)) = AuthChallengeHeader::ref_from_prefix(data) else {
            return false;
        };
        <[U16]>::ref_from_prefix_with_elems(rest, header.n_methods.get().into()).is_ok()
    }
}

#[derive(FromBytes, IntoBytes, SplitAt, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct AuthenticateTy<T: ?Sized> {
    ty: U16,
    length: U16,
    data: T,
}

impl AuthenticateTy<[u8]> {
    fn ensure_length(&self) -> Option<&Self> {
        Some(self.split_at(self.length.get().into())?.via_immutable().0)
    }
}

type AuthTy = AuthenticateTy<[u8]>;

/// Represents a AUTHENTICATE cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Authenticate(VariableCell);

impl AsRef<[u8]> for Authenticate {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

impl From<Authenticate> for Cell {
    fn from(v: Authenticate) -> Cell {
        Cell::from_variable(CellHeader::new(0, Authenticate::ID), v.into_inner())
    }
}

impl TryFromCell for Authenticate {
    fn try_from_cell(cell: &mut Option<Cell>) -> Result<Option<Self>, errors::CellFormatError> {
        let Some(
            c @ Cell {
                command: Self::ID, ..
            },
        ) = cell.as_ref()
        else {
            return Ok(None);
        };
        if c.circuit != 0 {
            return Err(errors::CellFormatError);
        }
        to_variable_with(cell, Self::check).map(|v| v.map(|v| unsafe { Self::from_cell(v) }))
    }
}

impl CellLike for Authenticate {
    fn circuit(&self) -> u32 {
        0
    }

    fn command(&self) -> u8 {
        Self::ID
    }

    fn cell(&self) -> CellRef<'_> {
        CellRef::Variable(&self.0)
    }
}

impl Authenticate {
    /// AUTHENTICATE command ID.
    pub const ID: u8 = 131;

    /// Create new AUTHENTICATE cell from a [`VariableCell`].
    ///
    /// # Safety
    ///
    /// Data must be a valid AUTHENTICATE cell.
    pub unsafe fn from_cell(data: VariableCell) -> Self {
        debug_assert!(Self::check(data.data()));
        Self(data)
    }

    /// Create AUTHENTICATE cell.
    ///
    /// # Error
    ///
    /// Errors if data does not fit the cell.
    ///
    /// # Example
    ///
    /// ```
    /// use onioncloud_lowlevel::cell::auth::Authenticate;
    ///
    /// let cell = Authenticate::new(0, &[1, 2, 3]).unwrap();
    /// ```
    pub fn new(auth_type: u16, data: &[u8]) -> Result<Self, errors::CellLengthOverflowError> {
        let n = u16::try_from(data.len()).map_err(|_| errors::CellLengthOverflowError)?;

        let len = size_of::<AuthenticateTy<[u8; 0]>>() + data.len();
        if len > 65535 {
            return Err(errors::CellLengthOverflowError);
        }
        // TODO: Replace this with equivalent of new_box_zeroed_with_elems but with Vec<u8>
        let mut v = vec![0; len];
        let p = AuthTy::mut_from_bytes_with_elems(&mut v, data.len()).expect("data must be valid");
        p.ty.set(auth_type);
        p.length.set(n);
        p.data.copy_from_slice(data);

        // SAFETY: Data is valid
        unsafe { Ok(Self::from_cell(VariableCell::from(v))) }
    }

    /// Gets authentication type.
    pub fn auth_type(&self) -> u16 {
        AuthTy::ref_from_bytes(self.0.data())
            .expect("data must be valid")
            .ty
            .get()
    }

    /// Gets length of authentication data.
    pub fn len(&self) -> usize {
        AuthTy::ref_from_bytes(self.0.data())
            .expect("data must be valid")
            .length
            .get()
            .into()
    }

    /// Returns [`true`] if there is no authentication data.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gets reference into authentication data.
    pub fn data(&self) -> &[u8] {
        &AuthTy::ref_from_bytes(self.0.data())
            .expect("data must be valid")
            .ensure_length()
            .expect("data must be valid")
            .data
    }

    /// Unwraps into inner [`VariableCell`].
    pub fn into_inner(self) -> VariableCell {
        self.0
    }

    fn check(data: &[u8]) -> bool {
        AuthTy::ref_from_bytes(data)
            .ok()
            .and_then(|v| v.ensure_length())
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    fn auth_challenge_strat() -> impl Strategy<Value = ([u8; 32], Vec<u16>)> {
        (any::<[u8; 32]>(), vec(any::<u16>(), 0..(65535 - 34) / 2))
    }

    fn authenticate_strat() -> impl Strategy<Value = (u16, Vec<u8>)> {
        (any::<u16>(), vec(any::<u8>(), 0..65535 - 4))
    }

    #[test]
    fn test_auth_challenge_too_long() {
        let ret = AuthChallenge::new(&[0; 32], &[0; (65536 - 34) / 2]);
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    #[test]
    fn test_auth_challenge_nonzero_circuit() {
        let ret = AuthChallenge::try_from_cell(&mut Some(Cell::from_variable(
            CellHeader::new(1, 130),
            vec![0; 34].into(),
        )));
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    #[test]
    fn test_auth_challenge_trailing() {
        let cell = AuthChallenge::try_from_cell(&mut Some(Cell::from_variable(
            CellHeader::new(0, 130),
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 1, 0, 1,
            ]
            .into(),
        )))
        .unwrap()
        .unwrap();
        assert_eq!(cell.len(), 1);
        assert_eq!(cell.methods(), [1u16]);
    }

    #[test]
    fn test_authenticate_too_long() {
        let ret = Authenticate::new(0, &[0; 65536 - 4]);
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    #[test]
    fn test_authenticate_nonzero_circuit() {
        let ret = Authenticate::try_from_cell(&mut Some(Cell::from_variable(
            CellHeader::new(1, 131),
            vec![0, 0, 0, 2, 0, 1].into(),
        )));
        assert!(ret.is_err(), "expect error, got {ret:?}");
    }

    #[test]
    fn test_authenticate_trailing() {
        let cell = Authenticate::try_from_cell(&mut Some(Cell::from_variable(
            CellHeader::new(0, 131),
            vec![0, 0, 0, 2, 0, 1, 0, 1].into(),
        )))
        .unwrap()
        .unwrap();
        assert_eq!(cell.len(), 2);
        assert_eq!(cell.data(), [0u8, 1]);
    }

    proptest! {
        #[test]
        fn test_auth_challenge_new((challenge, methods) in auth_challenge_strat()) {
            let cell = AuthChallenge::new(&challenge, &methods).unwrap();
            assert_eq!(*cell.challenge(), challenge);
            assert_eq!(cell.methods(), methods);
            assert_eq!(
                cell.0.data(),
                challenge
                    .into_iter()
                    .chain((methods.len() as u16).to_be_bytes())
                    .chain(methods.into_iter().flat_map(|v| v.to_be_bytes()))
                    .collect::<Vec<_>>(),
                );
        }

        #[test]
        fn test_auth_challenge_from_cell((challenge, methods) in auth_challenge_strat()) {
            let mut data = Vec::with_capacity(34 + methods.len() * 2);
            data.extend(challenge);
            data.extend((methods.len() as u16).to_be_bytes());
            data.extend(methods.iter().flat_map(|v| v.to_be_bytes()));

            let cell = AuthChallenge::try_from_cell(
                &mut Some(Cell::from_variable(CellHeader::new(0, 130), data.into()))
            ).unwrap().unwrap();
            assert_eq!(*cell.challenge(), challenge);
            assert_eq!(cell.methods(), methods);
        }

        #[test]
        fn test_auth_challenge_truncated(
            (n, (challenge, methods)) in auth_challenge_strat().prop_flat_map(|(c, v)| (1..34 + v.len() * 2, Just((c, v)))),
        ) {
            let mut data = Vec::with_capacity(34 + methods.len() * 2);
            data.extend(challenge);
            data.extend((methods.len() as u16).to_be_bytes());
            data.extend(methods.iter().flat_map(|v| v.to_be_bytes()));
            data.truncate(n);

            let ret = AuthChallenge::try_from_cell(&mut Some(Cell::from_variable(
                CellHeader::new(1, 130),
                data.into(),
            )));
            assert!(ret.is_err(), "expect error, got {ret:?}");
        }

        #[test]
        fn test_authenticate_new((auth_type, data) in authenticate_strat()) {
            let cell = Authenticate::new(auth_type, &data).unwrap();
            assert_eq!(cell.auth_type(), auth_type);
            assert_eq!(cell.data(), data);
            assert_eq!(
                cell.0.data(),
                auth_type
                    .to_be_bytes()
                    .into_iter()
                    .chain((data.len() as u16).to_be_bytes())
                    .chain(data)
                    .collect::<Vec<_>>(),
            );
        }

        #[test]
        fn test_authenticate_from_cell((auth_type, data) in authenticate_strat()) {
            let mut v = Vec::with_capacity(4 + data.len());
            v.extend(auth_type.to_be_bytes());
            v.extend((data.len() as u16).to_be_bytes());
            v.extend(&data);

            let cell = Authenticate::try_from_cell(&mut Some(Cell::from_variable(
                CellHeader::new(0, 131),
                v.into(),
            ))).unwrap().unwrap();
            assert_eq!(cell.auth_type(), auth_type);
            assert_eq!(cell.data(), data);
        }

        #[test]
        fn test_authenticate_truncated(
            (n, (auth_type, data)) in authenticate_strat().prop_flat_map(|(t, v)| (1..4 + v.len(), Just((t, v)))),
        ) {
            let mut v = Vec::with_capacity(4 + data.len());
            v.extend(auth_type.to_be_bytes());
            v.extend((data.len() as u16).to_be_bytes());
            v.extend(&data);
            v.truncate(n);

            let ret = Authenticate::try_from_cell(&mut Some(Cell::from_variable(
                CellHeader::new(0, 131),
                v.into(),
            )));
            assert!(ret.is_err(), "expect error, got {ret:?}");
        }
    }
}
