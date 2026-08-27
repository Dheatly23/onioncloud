#![no_main]

mod common;

use std::assert_matches;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::{Cell, TryFromCell};
use onioncloud_ll_cell::error::CellCastError;
use onioncloud_ll_cell::typed::Padding;

use crate::common::FixedCellData;

fuzz_target!(|data: FixedCellData| {
    let cell = Cell::from(data);

    if cell.header.circuit == 0 && cell.header.command == Padding::ID {
        let mut cell = Some(cell);

        let t = Padding::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = data.0.data;
        assert_eq!(t.as_ref(), s);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, 0);
        assert_eq!(cell.header.command, Padding::ID);
        assert!(cell.is_fixed(), "cell is not fixed");
        assert_eq!(cell.data(), s);
    } else if cell.header.command == Padding::ID {
        let mut cell = Some(cell);

        assert_matches!(
            Padding::try_from_cell(&mut cell),
            Err(CellCastError::NonZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else {
        let mut cell = Some(cell);

        assert_matches!(Padding::try_from_cell(&mut cell), Ok(None));
        assert_matches!(cell, Some(_));
    }
});
