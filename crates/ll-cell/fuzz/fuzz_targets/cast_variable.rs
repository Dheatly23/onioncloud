#![no_main]

mod common;

use std::assert_matches;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::{Cell, TryFromCell};
use onioncloud_ll_cell::error::CellCastError;
use onioncloud_ll_cell::typed::{AuthChallenge, Authenticate, Certs, VPadding, Versions};

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
        let expect_n = s.get(0).copied().unwrap_or(0) as usize;

        let mut n = 0;
        {
            let mut s = s.get(1..).unwrap_or(&[]);
            let mut it = (&t).into_iter();
            assert_eq!(it.len(), expect_n);

            for c in &mut it {
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

            assert_eq!(it.len(), 0);
        }
        assert_eq!(n, expect_n);

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

fn cast_auth_challenge(data: VariableCellData, cell: Cell) {
    if cell.header.circuit != 0 {
        let mut cell = Some(cell);

        assert_matches!(
            AuthChallenge::try_from_cell(&mut cell),
            Err(CellCastError::NonZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else if validate_auth_challenge(cell.data()) {
        let mut cell = Some(cell);

        let t = AuthChallenge::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = data.data;

        let mut challenge = [0; 32];
        let (a, b) = s.split_at_checked(32).unwrap_or((s, &[]));
        challenge[..a.len()].copy_from_slice(a);
        assert_eq!(*t.challenge(), challenge);

        let len = u16::from_be_bytes([
            b.get(0).copied().unwrap_or_default(),
            b.get(1).copied().unwrap_or_default(),
        ]) as usize;
        let u = t.methods();
        assert_eq!(u.len(), len);
        for (i, v) in u.iter().enumerate() {
            let t = u16::from_be_bytes([
                b.get(2 + i * 2).copied().unwrap_or_default(),
                b.get(3 + i * 2).copied().unwrap_or_default(),
            ]);
            assert_eq!(v.get(), t);
        }

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, 0);
        assert_eq!(cell.header.command, AuthChallenge::ID);
        assert!(cell.is_variable(), "cell is not variable");
        assert_eq!(&cell.data()[..s.len()], s);
        for (i, &t) in cell.data()[s.len()..].iter().enumerate() {
            assert_eq!(t, 0, "mismatch at index {}", i + s.len());
        }
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            AuthChallenge::try_from_cell(&mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fn validate_auth_challenge(s: &[u8]) -> bool {
    let Some(&[a, b, ref s @ ..]) = s.get(32..) else {
        return false;
    };
    u16::from_be_bytes([a, b]) as usize * 2 <= s.len()
}

fn cast_authenticate(data: VariableCellData, cell: Cell) {
    if cell.header.circuit != 0 {
        let mut cell = Some(cell);

        assert_matches!(
            Authenticate::try_from_cell(&mut cell),
            Err(CellCastError::NonZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else if validate_authenticate(cell.data()) {
        let mut cell = Some(cell);

        let t = Authenticate::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = data.data;

        let ty = u16::from_be_bytes([
            s.get(0).copied().unwrap_or_default(),
            s.get(1).copied().unwrap_or_default(),
        ]);
        assert_eq!(t.auth_ty(), ty);

        let len = u16::from_be_bytes([
            s.get(2).copied().unwrap_or_default(),
            s.get(3).copied().unwrap_or_default(),
        ]) as usize;
        let u = t.payload();
        assert_eq!(u.len(), len);
        let a = s.get(4..).unwrap_or(&[]);
        let l = u.len().min(a.len());
        assert_eq!(&u[..l], &a[..l]);
        for (i, &t) in u[l..].iter().enumerate() {
            assert_eq!(t, 0, "mismatch at index {}", i + l);
        }

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, 0);
        assert_eq!(cell.header.command, Authenticate::ID);
        assert!(cell.is_variable(), "cell is not variable");
        assert_eq!(&cell.data()[..s.len()], s);
        for (i, &t) in cell.data()[s.len()..].iter().enumerate() {
            assert_eq!(t, 0, "mismatch at index {}", i + s.len());
        }
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            Authenticate::try_from_cell(&mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fn validate_authenticate(s: &[u8]) -> bool {
    let [_, _, a, b, ref s @ ..] = *s else {
        return false;
    };
    u16::from_be_bytes([a, b]) as usize <= s.len()
}

fuzz_target!(|data: VariableCellData| {
    let mut cell = Cell::from(data);

    dispatch! {
        (data, cell) {
            VPadding => cast_vpadding,
            Versions => cast_versions,
            Certs => cast_certs,
            AuthChallenge => cast_auth_challenge,
            Authenticate => cast_authenticate,
        }
    }
});
