#![no_main]

mod common;

use std::assert_matches;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::{Cell, TryFromCell};
use onioncloud_ll_cell::error::CellCastError;
use onioncloud_ll_cell::fixed::FIXED_CELL_SIZE;
use onioncloud_ll_cell::typed::{Create2, Created2, Padding};

use crate::common::FixedCellData;

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

fn cast_padding(data: FixedCellData, cell: Cell) {
    if cell.header.circuit == 0 {
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
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            Padding::try_from_cell(&mut cell),
            Err(CellCastError::NonZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fn cast_create2(data: FixedCellData, cell: Cell) {
    const MAX_LEN: u16 = (FIXED_CELL_SIZE - 4) as _;

    if cell.header.circuit == 0 {
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
}

fn cast_created2(data: FixedCellData, cell: Cell) {
    const MAX_LEN: u16 = (FIXED_CELL_SIZE - 2) as _;

    if cell.header.circuit == 0 {
        let mut cell = Some(cell);

        assert_matches!(
            Created2::try_from_cell(&mut cell),
            Err(CellCastError::ZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else if let len @ ..=MAX_LEN = u16::from_be_bytes(cell.data()[..2].try_into().unwrap()) {
        let mut cell = Some(cell);

        let t = Created2::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = data.0.data;
        assert_eq!(t.payload(), &s[2..2 + len as usize]);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, data.0.circuit.get());
        assert_eq!(cell.header.command, Created2::ID);
        assert!(cell.is_fixed(), "cell is not fixed");
        assert_eq!(cell.data(), s);
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            Created2::try_from_cell(&mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fuzz_target!(|data: FixedCellData| {
    let mut cell = Cell::from(data);

    dispatch! {
        (data, cell) {
            Padding => cast_padding,
            Create2 => cast_create2,
            Created2 => cast_created2,
        }
    }
});
