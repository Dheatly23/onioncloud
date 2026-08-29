#![no_main]

mod common;

use std::assert_matches;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::{Cell, TryFromCell};
use onioncloud_ll_cell::error::CellCastError;
use onioncloud_ll_cell::typed::{VPadding, Versions};

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

fn cast_versions(data: VariableCellData, cell: Cell) {
    if cell.header.circuit != 0 {
        let mut cell = Some(cell);

        assert_matches!(
            Versions::try_from_cell(&mut cell),
            Err(CellCastError::NonZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else if let len = data.header.len.get()
        && len % 2 == 0
    {
        let mut cell = Some(cell);

        let t = Versions::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = data.data;
        let d = t.data();
        assert_eq!(d.len() * 2, len as usize, "{} * 2 != {}", d.len(), len);
        for (i, a) in d.iter().enumerate() {
            let mut x = [
                s.get(i * 2).copied().unwrap_or_default(),
                s.get(i * 2 + 1).copied().unwrap_or_default(),
            ];
            assert_eq!(a.get(), u16::from_be_bytes(x), "mismatch at index {i}");
        }

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, 0);
        assert_eq!(cell.header.command, Versions::ID);
        assert!(cell.is_variable(), "cell is not variable");
        assert_eq!(&cell.data()[..s.len()], s);
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            Versions::try_from_cell(&mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fuzz_target!(|data: VariableCellData| {
    let mut cell = Cell::from(data);

    dispatch! {
        (data, cell) {
            VPadding => cast_vpadding,
            Versions => cast_versions,
        }
    }
});
