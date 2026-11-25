#![no_main]

mod common;

use std::mem::size_of;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_crypto::certs::rsa::RsaCert;
use onioncloud_ll_crypto::{Digest, EdPublicKey, Sha256};
use rsa::pkcs1v15::Pkcs1v15Sign;
use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use common::FromBytesWrapper;

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct CertHead {
    key: EdPublicKey,
    exp: U32,
}

type Data = FromBytesWrapper<CertHead>;

fuzz_target!(|data: Data| {
    let head = data;
    // SAFETY: We are in fuzz environment.
    let (sk, pk) = unsafe { onioncloud_ll_crypto::test_keys::test_rsa_keypair() };

    let mut buf = Vec::with_capacity(1 + size_of::<CertHead>() + 128);
    buf.extend_from_slice(head.0.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(b"Tor TLS RSA/Ed25519 cross-certificate");
    hasher.update(&buf);
    let sig = sk
        .sign(Pkcs1v15Sign::new_unprefixed(), &hasher.finalize())
        .unwrap();
    buf.push(sig.len().try_into().unwrap());
    buf.extend_from_slice(&sig);
    drop(sig);

    let cert = RsaCert::try_from(&buf[..]).unwrap();

    assert_eq!(cert.expiry(), head.0.exp.get());
    assert_eq!(*cert.key(), head.0.key);

    cert.verify(&pk).unwrap();
});
