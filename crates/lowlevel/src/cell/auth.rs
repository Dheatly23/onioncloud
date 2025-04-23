use std::slice::from_raw_parts;

use zerocopy::FromBytes;
use zerocopy::byteorder::big_endian::U16;

use super::{Cell, CellHeader, CellLike, CellRef, TryFromCell, VariableCell, to_variable_with};
use crate::errors;

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
    /// ```
    /// use onioncloud_lowlevel::cell::auth::AuthChallenge;
    ///
    /// let cell = AuthChallenge::new(&[0; 32], &[1, 2, 3]);
    /// ```
    pub fn new(challenge: &[u8; 32], methods: &[u16]) -> Self {
        let l = u16::try_from(methods.len()).expect("too many methods");
        let mut v = Vec::with_capacity(34 + methods.len() * 2);

        v.extend_from_slice(challenge);
        v.extend_from_slice(&l.to_be_bytes());
        v.extend(methods.iter().flat_map(|v| v.to_be_bytes()));

        // SAFETY: Data is valid
        unsafe { Self::from_cell(VariableCell::from(v)) }
    }

    /// Gets the challenge string.
    pub fn challenge(&self) -> &[u8; 32] {
        self.0.data()[..32]
            .try_into()
            .expect("slice must be 32 bytes")
    }

    /// Gets reference into methods.
    pub fn methods(&self) -> &[U16] {
        let s = &self.0.data()[32..];
        let l = u16::from_be_bytes(s[..2].try_into().unwrap());

        // SAFETY: Data has been checked
        // XXX: Use zerocopy instead?
        unsafe { from_raw_parts((&s[2..] as *const [u8]).cast::<U16>(), l.into()) }
    }

    /// Unwraps into inner [`VariableCell`].
    pub fn into_inner(self) -> VariableCell {
        self.0
    }

    fn check(data: &[u8]) -> bool {
        let Some((s, r)) = data.split_first_chunk::<34>() else {
            return false;
        };

        let l = u16::from_be_bytes(s[32..].try_into().expect("array must be 34 bytes"));
        <[U16]>::ref_from_prefix_with_elems(r, l.into()).is_ok()
    }
}

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
    pub fn new(auth_type: u16, data: &[u8]) -> Self {
        let l = u16::try_from(data.len()).expect("data is too long");
        let mut v = Vec::with_capacity(4 + data.len());

        v.extend_from_slice(&auth_type.to_be_bytes());
        v.extend_from_slice(&l.to_be_bytes());
        v.extend_from_slice(data);

        // SAFETY: Data is valid
        unsafe { Self::from_cell(VariableCell::from(v)) }
    }

    /// Gets authentication type.
    pub fn auth_type(&self) -> u16 {
        u16::from_be_bytes(self.0.data()[..2].try_into().unwrap())
    }

    /// Gets length of authentication data.
    pub fn len(&self) -> usize {
        u16::from_be_bytes(self.0.data()[2..4].try_into().unwrap()).into()
    }

    /// Returns [`true`] if there is no authentication data.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gets reference into authentication data.
    pub fn data(&self) -> &[u8] {
        let l = self.len();
        &self.0.data()[4..4 + l]
    }

    /// Unwraps into inner [`VariableCell`].
    pub fn into_inner(self) -> VariableCell {
        self.0
    }

    fn check(data: &[u8]) -> bool {
        let Some((s, r)) = data.split_first_chunk::<4>() else {
            return false;
        };

        let l = u16::from_be_bytes(s[2..4].try_into().unwrap());
        r.len() >= usize::from(l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_auth_challenge_from_list(challenge: [u8; 32], methods: Vec<u16>) {
            let cell = AuthChallenge::new(&challenge, &methods);
            assert_eq!(*cell.challenge(), challenge);
            assert_eq!(cell.methods(), methods);
        }

        #[test]
        fn test_auth_challenge_content(challenge: [u8; 32], methods: Vec<u16>) {
            let data = AuthChallenge::new(&challenge, &methods).into_inner();
            assert_eq!(
                data.data(),
                challenge
                    .into_iter()
                    .chain((methods.len() as u16).to_be_bytes())
                    .chain(methods.into_iter().flat_map(|v| v.to_be_bytes())).collect::<Vec<_>>(),
                );
        }

        #[test]
        fn test_authenticate(auth_type: u16, data in vec(any::<u8>(), 0..256)) {
            let cell = Authenticate::new(auth_type, &data);
            assert_eq!(cell.auth_type(), auth_type);
            assert_eq!(cell.data(), data);
        }
    }
}
