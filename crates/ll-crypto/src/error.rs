//! Error types

use signature::Error as SignatureError;
use thiserror::Error;

#[derive(Error, Debug, Default)]
#[error("certificate format error")]
#[non_exhaustive]
pub struct CertFormatError;

#[derive(Error, Debug, Default)]
#[error("certificate validation error")]
#[non_exhaustive]
pub struct CertValidateError;

impl From<SignatureError> for CertValidateError {
    fn from(v: SignatureError) -> Self {
        let _ = v;
        Self
    }
}
