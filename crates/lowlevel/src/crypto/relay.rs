use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

use base64ct::{Base64Unpadded, Encoding, Error as B64Error};

use crate::errors::{ParseRelayIdInner, RelayIdParseError};
use crate::util::{print_ed, print_hex};

/// Relay ID/fingerprint, represented as 20 bytes.
pub type RelayId = super::Sha1Output;

/// Relay Ed25519 public key.
///
/// Used in conjunction with [`RelayId`].
pub type RelayIdEd = super::EdPublicKey;

/// Type that contains all relay IDs.
///
/// All IDS should correspond to the same relay.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayIds {
    /// Relay fingerprint.
    pub id: RelayId,

    /// Relay ed25519 identity key.
    pub id_ed: RelayIdEd,
}

impl Debug for RelayIds {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("RelayIds")
            .field("id", &print_hex(&self.id))
            .field("id_ed", &print_ed(&self.id_ed))
            .finish()
    }
}

impl Display for RelayIds {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", print_hex(&self.id))
    }
}

/// Parse a string into [`RelayId`].
///
/// String is in form of "$AAA..." or "AAA..." with the content is 40 hexadecimal digits.
pub fn from_str(s: &str) -> Result<RelayId, RelayIdParseError> {
    // Remove initial $
    let s = match s.as_bytes() {
        [] => return Err(RelayIdParseError(ParseRelayIdInner::Empty)),
        [b'$', r @ ..] => r,
        s => s,
    };

    // Check if byte length is valid
    let Ok(s) = <&[u8; 40]>::try_from(s) else {
        return Err(RelayIdParseError(ParseRelayIdInner::TooShort));
    };

    // Process bytes
    let mut ret = RelayId::default();
    assert_eq!(ret.len() * 2, s.len());
    for (i, o) in ret.iter_mut().enumerate() {
        let i = i * 2;
        let (Some(u), Some(l)) = (
            char::from(s[i]).to_digit(16),
            char::from(s[i + 1]).to_digit(16),
        ) else {
            return Err(RelayIdParseError(ParseRelayIdInner::InvalidDigit));
        };
        *o = l as u8 | ((u as u8) << 4);
    }

    Ok(ret)
}

/// Parse a string into [`RelayIdEd`].
///
/// String is base64 unpadded characters.
pub fn from_str_ed(s: &str) -> Result<RelayIdEd, RelayIdParseError> {
    let mut ret: RelayIdEd = [0; _];
    match Base64Unpadded::decode(s.as_bytes(), &mut ret) {
        Ok(_) => Ok(ret),
        Err(B64Error::InvalidEncoding) => Err(RelayIdParseError(ParseRelayIdInner::InvalidDigit)),
        Err(B64Error::InvalidLength) => Err(RelayIdParseError(ParseRelayIdInner::TooShort)),
    }
}
