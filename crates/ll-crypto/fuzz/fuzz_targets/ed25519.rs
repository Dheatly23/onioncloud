#![no_main]

mod common;

use std::mem::size_of;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_crypto::EdPublicKey;
use onioncloud_ll_crypto::certs::ed::EdCert;
use signature::Signer;
use zerocopy::byteorder::big_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use common::FromBytesWrapper;

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct CertHead {
    ty: u8,
    exp: U32,
    kty: u8,
    key: EdPublicKey,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct CertExt {
    ty: u8,
    flags: u8,
}

type Data = (
    FromBytesWrapper<CertHead>,
    Vec<(FromBytesWrapper<CertExt>, Vec<u8>)>,
);

fuzz_target!(|data: Data| {
    let (head, ext) = data;
    let ext = ext
        .into_iter()
        .map(|(head, mut data)| {
            data.truncate(65535);
            (head, data)
        })
        .take(255)
        .collect::<Vec<_>>();

    // SAFETY: We are in fuzz environment.
    let (sk, pk) = unsafe { onioncloud_ll_crypto::test_keys::test_ed25519_keypair() };

    let mut buf = Vec::with_capacity(
        1 + size_of::<CertHead>()
            + ext
                .iter()
                .map(|(_, b)| 2 + size_of::<CertExt>() + b.len())
                .sum::<usize>()
            + 64,
    );
    buf.push(1);
    buf.extend_from_slice(head.0.as_bytes());
    buf.push(ext.len().try_into().unwrap());
    for (head, data) in &ext {
        buf.extend_from_slice(U16::new(data.len().try_into().unwrap()).as_bytes());
        buf.extend_from_slice(head.0.as_bytes());
        buf.extend_from_slice(&data[..]);
    }
    buf.extend_from_slice(&sk.sign(&buf).to_bytes());

    let mut cert = EdCert::try_from(&buf[..]).unwrap();

    assert_eq!(cert.cert_ty().0, head.0.ty);
    assert_eq!(cert.key_ty().0, head.0.kty);
    assert_eq!(cert.expiry(), head.0.exp.get());
    assert_eq!(*cert.key(), head.0.key);

    let mut i = 0;
    for e in &mut cert {
        let e = e.unwrap();
        let exp = &ext[i];
        assert_eq!(e.ty(), exp.0.0.ty);
        assert_eq!(e.flags().0, exp.0.0.flags);
        assert_eq!(e.data(), exp.1);
        i += 1;
    }
    assert_eq!(i, ext.len());

    cert.verify(&pk).unwrap();
});
