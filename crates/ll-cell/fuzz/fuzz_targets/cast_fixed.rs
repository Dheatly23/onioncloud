#![no_main]

mod common;

use std::assert_matches;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::{Cell, TryFromCell};
use onioncloud_ll_cell::error::CellCastError;
use onioncloud_ll_cell::fixed::FIXED_CELL_SIZE;
use onioncloud_ll_cell::typed::netinfo::MaybeAddr;
use onioncloud_ll_cell::typed::padding_negotiate::{PaddingNegotiateData, PaddingNegotiateV0};
use onioncloud_ll_cell::typed::{
    Create2, CreateFast, Created2, CreatedFast, Destroy, Netinfo, Padding, PaddingNegotiate, Relay,
    RelayEarly,
};

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

        assert_eq!(t.circuit.get(), data.0.circuit.get());
        let s = &data.0.data;
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

        assert_eq!(t.circuit.get(), data.0.circuit.get());
        let s = &data.0.data;
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

fn cast_create_fast(data: FixedCellData, cell: Cell) {
    if cell.header.circuit == 0 {
        let mut cell = Some(cell);

        assert_matches!(
            CreateFast::try_from_cell(&mut cell),
            Err(CellCastError::ZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else {
        let mut cell = Some(cell);

        let t = CreateFast::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        assert_eq!(t.circuit.get(), data.0.circuit.get());
        let s = &data.0.data;
        let mut x = [0; 20];
        let l = s.len().min(x.len());
        x[..l].copy_from_slice(&s[..l]);
        assert_eq!(*t.x(), x);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, data.0.circuit.get());
        assert_eq!(cell.header.command, CreateFast::ID);
        assert!(cell.is_fixed(), "cell is not fixed");
        assert_eq!(cell.data(), s);
    }
}

fn cast_created_fast(data: FixedCellData, cell: Cell) {
    if cell.header.circuit == 0 {
        let mut cell = Some(cell);

        assert_matches!(
            CreatedFast::try_from_cell(&mut cell),
            Err(CellCastError::ZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else {
        let mut cell = Some(cell);

        let t = CreatedFast::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        assert_eq!(t.circuit.get(), data.0.circuit.get());
        let s = &data.0.data;
        let mut x = [0; 20];
        let l = s.len().min(x.len());
        x[..l].copy_from_slice(&s[..l]);
        assert_eq!(*t.y(), x);
        let u = s.get(20..).unwrap_or(&[]);
        let l = u.len().min(x.len());
        x[..l].copy_from_slice(&u[..l]);
        assert_eq!(*t.derived(), x);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, data.0.circuit.get());
        assert_eq!(cell.header.command, CreatedFast::ID);
        assert!(cell.is_fixed(), "cell is not fixed");
        assert_eq!(cell.data(), s);
    }
}

fn cast_destroy(data: FixedCellData, cell: Cell) {
    if cell.header.circuit == 0 {
        let mut cell = Some(cell);

        assert_matches!(
            Destroy::try_from_cell(&mut cell),
            Err(CellCastError::ZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else {
        let mut cell = Some(cell);

        let t = Destroy::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        assert_eq!(t.circuit.get(), data.0.circuit.get());
        let s = &data.0.data;
        assert_eq!(t.reason(), s[0]);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, data.0.circuit.get());
        assert_eq!(cell.header.command, Destroy::ID);
        assert!(cell.is_fixed(), "cell is not fixed");
        assert_eq!(cell.data(), s);
    }
}

fn cast_netinfo(data: FixedCellData, cell: Cell) {
    if cell.header.circuit != 0 {
        let mut cell = Some(cell);

        assert_matches!(
            Netinfo::try_from_cell(&mut cell),
            Err(CellCastError::NonZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else if validate_netinfo(&data.0.data) {
        let mut cell = Some(cell);

        let t = Netinfo::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = &data.0.data;
        assert_eq!(
            t.timestamp(),
            u32::from_be_bytes(s[..4].try_into().unwrap())
        );

        let (ip, r) = match &s[4..] {
            [4, 4, r @ ..] => (
                MaybeAddr::Ip(<[u8; 4]>::try_from(&r[..4]).unwrap().into()),
                &r[4..],
            ),
            [6, 16, r @ ..] => (
                MaybeAddr::Ip(<[u8; 16]>::try_from(&r[..16]).unwrap().into()),
                &r[16..],
            ),
            [t, l, r @ ..] => (
                MaybeAddr::Unknown {
                    ty: *t,
                    payload: &r[..*l as usize],
                },
                &r[*l as usize..],
            ),
            _ => unreachable!(),
        };
        assert_eq!(t.other_addr(), ip);

        let [n, r @ ..] = r else { unreachable!() };
        let mut r = r;
        let expect_n = *n as usize;
        let mut it = t.my_addrs();
        assert_eq!(it.len(), expect_n);
        let mut n = 0;
        for a in &mut it {
            let ip;
            (ip, r) = match r {
                [4, 4, r @ ..] => (
                    MaybeAddr::Ip(<[u8; 4]>::try_from(&r[..4]).unwrap().into()),
                    &r[4..],
                ),
                [6, 16, r @ ..] => (
                    MaybeAddr::Ip(<[u8; 16]>::try_from(&r[..16]).unwrap().into()),
                    &r[16..],
                ),
                [t, l, r @ ..] => (
                    MaybeAddr::Unknown {
                        ty: *t,
                        payload: &r[..*l as usize],
                    },
                    &r[*l as usize..],
                ),
                _ => unreachable!(),
            };
            assert_eq!(a, ip, "mismatch at index {n}");
            n += 1;
        }
        assert_eq!(it.len(), 0);
        assert_eq!(n, expect_n);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, data.0.circuit.get());
        assert_eq!(cell.header.command, Netinfo::ID);
        assert!(cell.is_fixed(), "cell is not fixed");
        assert_eq!(cell.data(), s);
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            Netinfo::try_from_cell(&mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fn validate_netinfo(s: &[u8; FIXED_CELL_SIZE]) -> bool {
    let l = s[5] as usize;
    let Some([n, s @ ..]) = s.get(l + 6..) else {
        return false;
    };
    let mut s = s;

    for _ in 0..*n {
        let [_, l, r @ ..] = s else { return false };
        let Some(r) = r.get(*l as usize..) else {
            return false;
        };
        s = r;
    }

    true
}

fn cast_padding_negotiate(data: FixedCellData, cell: Cell) {
    if cell.header.circuit == 0 {
        let mut cell = Some(cell);

        assert_matches!(
            PaddingNegotiate::try_from_cell(&mut cell),
            Err(CellCastError::ZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    } else if let Some(c) = match data.0.data {
        [0, 1, ..] => Some(PaddingNegotiateData::V0(PaddingNegotiateV0::Stop)),
        [0, 2, a, b, c, d, ..] => Some(PaddingNegotiateData::V0(PaddingNegotiateV0::Start {
            low: u16::from_be_bytes([a, b]),
            high: u16::from_be_bytes([c, d]),
        })),
        _ => None,
    } {
        let mut cell = Some(cell);

        let t = PaddingNegotiate::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        assert_eq!(t.circuit.get(), data.0.circuit.get());
        assert_eq!(t.data(), c);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, data.0.circuit.get());
        assert_eq!(cell.header.command, PaddingNegotiate::ID);
        assert!(cell.is_fixed(), "cell is not fixed");
        assert_eq!(cell.data(), data.0.data);
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            PaddingNegotiate::try_from_cell(&mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fn cast_relay(data: FixedCellData, cell: Cell) {
    if cell.header.circuit != 0 {
        let mut cell = Some(cell);

        let t = Relay::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = data.0.data;
        assert_eq!(t.as_ref(), s);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, 0);
        assert_eq!(cell.header.command, Relay::ID);
        assert!(cell.is_fixed(), "cell is not fixed");
        assert_eq!(cell.data(), s);
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            Relay::try_from_cell(&mut cell),
            Err(CellCastError::ZeroCircID(_))
        );
        assert_matches!(cell, Some(_));
    }
}

fn cast_relay_early(data: FixedCellData, cell: Cell) {
    if cell.header.circuit != 0 {
        let mut cell = Some(cell);

        let t = RelayEarly::try_from_cell(&mut cell).unwrap().unwrap();
        assert_matches!(cell, None);

        let s = data.0.data;
        assert_eq!(t.as_ref(), s);

        let cell = Cell::from(t);
        assert_eq!(cell.header.circuit, 0);
        assert_eq!(cell.header.command, RelayEarly::ID);
        assert!(cell.is_fixed(), "cell is not fixed");
        assert_eq!(cell.data(), s);
    } else {
        let mut cell = Some(cell);

        assert_matches!(
            RelayEarly::try_from_cell(&mut cell),
            Err(CellCastError::ZeroCircID(_))
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
            CreateFast => cast_create_fast,
            CreatedFast => cast_created_fast,
            Destroy => cast_destroy,
            Netinfo => cast_netinfo,
            PaddingNegotiate => cast_padding_negotiate,
            Relay => cast_relay,
            RelayEarly => cast_relay_early,
        }
    }
});
