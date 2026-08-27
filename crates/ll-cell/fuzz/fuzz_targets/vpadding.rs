#![no_main]

mod common;

use std::assert_matches;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::{Cell, TryFromCell};
use onioncloud_ll_cell::error::CellCastError;
use onioncloud_ll_cell::typed::VPadding;

use crate::common::VariableCellData;

fuzz_target!(|data: VariableCellData| {
    let cell = Cell::from(data);

    if cell.header.circuit == 0 && cell.header.command == VPadding::ID {
        let mut cell = Some(cell);

        let t = VPadding::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = data.data;
        assert_eq!(&<VPadding as AsRef<[u8]>>::as_ref(&t)[..s.len()], s);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, 0);
        assert_eq!(cell.header.command, VPadding::ID);
        assert!(cell.is_variable(), "cell is not variable");
        assert_eq!(&cell.data()[..s.len()], s);
    } else if cell.header.command == VPadding::ID {
        let mut cell = Some(cell);

        assert_matches!(
            VPadding::try_from_cell(&mut cell),
            Err(CellCastError::NonZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else {
        let mut cell = Some(cell);

        assert_matches!(VPadding::try_from_cell(&mut cell), Ok(None));
        assert_matches!(cell, Some(_));
    }
});
