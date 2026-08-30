#![no_main]

mod common;

use std::assert_matches;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::{Cell, TryFromCell};
use onioncloud_ll_cell::error::CellCastError;
use onioncloud_ll_cell::typed::{Certs, VPadding, Versions};

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
        for (i, &t) in cell.data()[s.len()..].iter().enumerate() {
            assert_eq!(t, 0, "mismatch at index {}", i + s.len());
        }
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
            let x = u16::from_be_bytes([
                s.get(i * 2).copied().unwrap_or_default(),
                s.get(i * 2 + 1).copied().unwrap_or_default(),
            ]);
            assert_eq!(a.get(), x, "mismatch at index {i}");
        }

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, 0);
        assert_eq!(cell.header.command, Versions::ID);
        assert!(cell.is_variable(), "cell is not variable");
        assert_eq!(&cell.data()[..s.len()], s);
        for (i, &t) in cell.data()[s.len()..].iter().enumerate() {
            assert_eq!(t, 0, "mismatch at index {}", i + s.len());
        }
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            Versions::try_from_cell(&mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fn cast_certs(data: VariableCellData, cell: Cell) {
    if cell.header.circuit != 0 {
        let mut cell = Some(cell);

        assert_matches!(
            Certs::try_from_cell(&mut cell),
            Err(CellCastError::NonZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else if validate_certs(cell.data()) {
        let mut cell = Some(cell);

        let t = Certs::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = data.data;

        let mut n = 0;
        {
            let mut s = s.get(1..).unwrap_or(&[]);
            for c in &t {
                assert_eq!(c.ty, s.get(0).copied().unwrap_or_default());
                let l = u16::from_be_bytes([
                    s.get(1).copied().unwrap_or_default(),
                    s.get(2).copied().unwrap_or_default(),
                ]) as usize;
                assert_eq!(c.data.len(), l);
                s = s.get(3..).unwrap_or(&[]);
                let (a, b) = s.split_at_checked(l).unwrap_or((s, &[]));
                assert_eq!(&c.data[..a.len()], a);
                for (i, &t) in c.data[a.len()..].iter().enumerate() {
                    assert_eq!(t, 0, "mismatch at index {}", i + a.len());
                }
                s = b;
                n += 1;
            }
        }
        assert_eq!(n, s.get(0).copied().unwrap_or(0) as usize);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, 0);
        assert_eq!(cell.header.command, Certs::ID);
        assert!(cell.is_variable(), "cell is not variable");
        assert_eq!(&cell.data()[..s.len()], s);
        for (i, &t) in cell.data()[s.len()..].iter().enumerate() {
            assert_eq!(t, 0, "mismatch at index {}", i + s.len());
        }
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            Certs::try_from_cell(&mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fn validate_certs(s: &[u8]) -> bool {
    let [n, ref s @ ..] = *s else { return false };
    let mut s = s;
    for _ in 0..n {
        let [_, a, b, ref r @ ..] = *s else {
            return false;
        };
        let l = u16::from_be_bytes([a, b]) as usize;
        let Some((_, r)) = r.split_at_checked(l) else {
            return false;
        };
        s = r;
    }
    true
}

fuzz_target!(|data: VariableCellData| {
    let mut cell = Cell::from(data);

    dispatch! {
        (data, cell) {
            VPadding => cast_vpadding,
            Versions => cast_versions,
            Certs => cast_certs,
        }
    }
});
