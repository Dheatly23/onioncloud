#![no_main]

mod common;

use std::num::NonZeroU32;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::Cell;
use onioncloud_ll_cell::fixed::{FIXED_CELL_SIZE, FixedCell};
use onioncloud_ll_cell::typed::Create2;

use crate::common::LimitedBytes;

const MAX_LEN: usize = FIXED_CELL_SIZE - 4;

#[derive(Debug, Arbitrary)]
struct Data<'a> {
    circuit: NonZeroU32,
    handshake_ty: u16,
    data: LimitedBytes<'a, MAX_LEN>,
}

fuzz_target!(|data: Data<'_>| {
    let cell = Create2::new(
        data.circuit,
        FixedCell::default(),
        data.handshake_ty,
        data.data.0,
    )
    .unwrap();

    assert_eq!(cell.circuit, data.circuit);
    assert_eq!(cell.handshake_ty(), data.handshake_ty);
    assert_eq!(cell.payload(), data.data.0);

    let cell = Cell::from(cell);

    assert_eq!(cell.header.circuit, data.circuit.into());
    assert_eq!(
        u16::from_be_bytes(cell.data()[..2].try_into().unwrap()),
        data.handshake_ty
    );
    assert_eq!(
        u16::from_be_bytes(cell.data()[2..4].try_into().unwrap()) as usize,
        data.data.0.len()
    );
    assert_eq!(
        &cell.data()[4..4 + u16::from_be_bytes(cell.data()[2..4].try_into().unwrap()) as usize],
        data.data.0
    );
});
