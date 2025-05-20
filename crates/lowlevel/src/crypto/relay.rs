use crate::errors::{ParseRelayIdInner, RelayIdParseError};

/// Relay ID/fingerprint, represented as 20 bytes.
pub type RelayId = super::Sha1Output;

/// Relay Ed25519 public key.
///
/// Used in conjunction with [`RelayId`].
pub type RelayIdEd = super::EdPublicKey;

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
