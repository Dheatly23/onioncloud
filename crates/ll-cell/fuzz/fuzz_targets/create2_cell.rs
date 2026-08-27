#![no_main]

mod common;

use std::assert_matches;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::{Cell, TryFromCell};
use onioncloud_ll_cell::error::CellCastError;
use onioncloud_ll_cell::fixed::FIXED_CELL_SIZE;
use onioncloud_ll_cell::typed::Create2;

use crate::common::FixedCellData;

const MAX_LEN: u16 = (FIXED_CELL_SIZE - 4) as _;

fuzz_target!(|data: FixedCellData| {
    let cell = Cell::from(data);

    if cell.header.command != Create2::ID {
        let mut cell = Some(cell);

        assert_matches!(Create2::try_from_cell(&mut cell), Ok(None));
        assert_matches!(cell, Some(_));
    } else if cell.header.circuit == 0 {
        let mut cell = Some(cell);

        assert_matches!(
            Create2::try_from_cell(&mut cell),
            Err(CellCastError::ZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else if let len @ ..=MAX_LEN = u16::from_be_bytes(cell.data()[2..4].try_into().unwrap()) {
        let mut cell = Some(cell);

        let t = Create2::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = data.0.data;
        assert_eq!(
            t.handshake_ty(),
            u16::from_be_bytes(s[..2].try_into().unwrap())
        );
        assert_eq!(t.payload(), &s[4..4 + len as usize]);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, data.0.circuit.get());
        assert_eq!(cell.header.command, Create2::ID);
        assert!(cell.is_fixed(), "cell is not fixed");
        assert_eq!(cell.data(), s);
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            Create2::try_from_cell(&mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    }
});
