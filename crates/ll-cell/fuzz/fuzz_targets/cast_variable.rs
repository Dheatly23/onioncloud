#![no_main]

mod common;

use std::assert_matches;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::{Cell, TryFromCell};
use onioncloud_ll_cell::error::CellCastError;
use onioncloud_ll_cell::typed::VPadding;

use crate::common::VariableCellData;

macro_rules! dispatch {
    (($data:ident, $cell:ident) {
        $($v:ident => $f:ident),* $(,)?
    }) => {
        $(
            if ($cell.header.command != $v::ID) {
                let mut cell = Some($cell);
                assert_matches!($v::try_from_cell(&mut cell), Ok(None));
                $cell = cell.expect("cell must not be taken");
            }
        )*

        match $cell.header.command {
            $($v::ID => $f($data, $cell),)*
            _ => (),
        }
    }
}

fn cast_vpadding(data: VariableCellData, cell: Cell) {
    if cell.header.circuit == 0 {
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
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            VPadding::try_from_cell(&mut cell),
            Err(CellCastError::NonZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fuzz_target!(|data: VariableCellData| {
    let mut cell = Cell::from(data);

    dispatch! {
        (data, cell) {
            VPadding => cast_vpadding,
        }
    }
});
