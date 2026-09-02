#![no_main]

use std::num::Saturating;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::typed::certs::{Cert, Certs};

#[derive(Debug, Arbitrary)]
struct Data {
    ty: u8,
    data: Vec<u8>,
}

fuzz_target!(|data: Vec<Data>| {
    let len = Saturating(1usize)
        + data
            .iter()
            .map(|v| Saturating(3usize) + Saturating(v.data.len()))
            .sum::<Saturating<usize>>();
    let is_valid = data.len() < 256 && data.iter().all(|v| v.data.len() < 65536) && len.0 < 65536;

    let r = Certs::try_from_iter(data.iter().map(|v| Cert {
        ty: v.ty,
        data: &v.data[..],
    }));

    if is_valid {
        let cell = r.unwrap();
        let it = cell.iter();
        assert_eq!(it.len(), data.len());
        for (i, a) in it.enumerate() {
            let b = &data[i];
            assert_eq!(a.ty, b.ty, "mismatch at index {i}");
            assert_eq!(a.data, &b.data[..], "mismatch at index {i}");
        }
    } else {
        r.unwrap_err();
    }
});
