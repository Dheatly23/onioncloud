#![no_main]

use std::assert_matches;
use std::mem::size_of;
use std::num::NonZeroU16;

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::fixed::{FIXED_CELL_SIZE, FixedCell};
use onioncloud_ll_relay_cell::error::CellCastError;
use onioncloud_ll_relay_cell::typed::*;
use onioncloud_ll_relay_cell::ver::Ver;
use onioncloud_ll_relay_cell::{DynRelayVersion, TryFromRelay};
use zerocopy::{FromBytes, IntoBytes};

#[derive(Debug, Clone, Copy)]
pub(crate) struct FromBytesWrapper<T>(pub(crate) T);

impl<T: Sized + FromBytes + IntoBytes> Arbitrary<'_> for FromBytesWrapper<T> {
    fn arbitrary(u: &mut Unstructured<'_>) -> ArbResult<Self> {
        let mut t = T::new_zeroed();
        let b = u.bytes(u.len().min(size_of_val(&t)))?;
        t.as_mut_bytes()[..b.len()].copy_from_slice(b);
        Ok(Self(t))
    }

    fn arbitrary_take_rest(u: Unstructured<'_>) -> ArbResult<Self> {
        let b = u.take_rest();
        let mut t = T::new_zeroed();
        let l = b.len().min(size_of_val(&t));
        t.as_mut_bytes()[..l].copy_from_slice(&b[..l]);
        Ok(Self(t))
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (size_of::<T>(), Some(size_of::<T>()))
    }
}

pub(crate) type FixedCellData = FromBytesWrapper<[u8; FIXED_CELL_SIZE]>;

impl From<FixedCellData> for FixedCell {
    fn from(v: FixedCellData) -> FixedCell {
        v.0.into()
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum CellVersion {
    V0,
    V1,
}

impl From<CellVersion> for Ver {
    fn from(v: CellVersion) -> Ver {
        match v {
            CellVersion::V0 => Ver::V0,
            CellVersion::V1 => Ver::V1,
        }
    }
}

macro_rules! dispatch {
    (($data:ident, $cell:ident, $ver:ident) {
        $($v:ident => $f:ident),* $(,)?
    }) => {
        $(
            if ($ver.command(&$cell) != $v::<Ver>::ID) {
                let mut cell = Some($cell);
                assert_matches!($v::try_from_relay_versioned($ver, &mut cell), Ok(None));
                $cell = cell.expect("cell must not be taken");
            }
        )*

        match $ver.command(&$cell) {
            $($v::<Ver>::ID => $f($data, $cell, $ver),)*
            _ => (),
        }
    }
}

fn cast_begin_dir(data: FixedCellData, cell: FixedCell, ver: Ver) {
    let Some(stream_id) = NonZeroU16::new(ver.stream_id(&cell)) else {
        let mut cell = Some(cell);

        assert_matches!(
            BeginDir::try_from_relay_versioned(ver, &mut cell),
            Err(CellCastError::ZeroStreamID(_))
        );
        assert_matches!(cell, Some(_));
        return;
    };

    if ver.data_checked(&cell).is_none() {
        let mut cell = Some(cell);

        assert_matches!(
            BeginDir::try_from_relay_versioned(ver, &mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    } else {
        let mut cell = Some(cell);

        let t = BeginDir::try_from_relay_versioned(ver, &mut cell)
            .unwrap()
            .unwrap();
        assert_matches!(cell, None);

        assert_eq!(t.stream_id(), stream_id);

        let cell = FixedCell::from(t);
        assert_eq!(*cell.data(), data.0);
    }
}

fn cast_drop(data: FixedCellData, cell: FixedCell, ver: Ver) {
    if ver.stream_id(&cell) != 0 {
        let mut cell = Some(cell);

        assert_matches!(
            Drop::try_from_relay_versioned(ver, &mut cell),
            Err(CellCastError::NonZeroStreamID(_))
        );
        assert_matches!(cell, Some(_));
    } else if ver.data_checked(&cell).is_none() {
        let mut cell = Some(cell);

        assert_matches!(
            Drop::try_from_relay_versioned(ver, &mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
    } else {
        let mut cell = Some(cell);

        let t = Drop::try_from_relay_versioned(ver, &mut cell)
            .unwrap()
            .unwrap();
        assert_matches!(cell, None);

        let cell = FixedCell::from(t);
        assert_eq!(*cell.data(), data.0);
    }
}

fn cast_data(data: FixedCellData, cell: FixedCell, ver: Ver) {
    let Some(stream_id) = NonZeroU16::new(ver.stream_id(&cell)) else {
        let mut cell = Some(cell);

        assert_matches!(
            Data::try_from_relay_versioned(ver, &mut cell),
            Err(CellCastError::ZeroStreamID(_))
        );
        assert_matches!(cell, Some(_));
        return;
    };

    let data = FixedCell::from(data);
    let Some(s) = ver.data_checked(&data) else {
        let mut cell = Some(cell);

        assert_matches!(
            Data::try_from_relay_versioned(ver, &mut cell),
            Err(CellCastError::CellFormatError(_))
        );
        assert_matches!(cell, Some(_));
        return;
    };

    let mut cell = Some(cell);

    let t = Data::try_from_relay_versioned(ver, &mut cell)
        .unwrap()
        .unwrap();
    assert_matches!(cell, None);

    assert_eq!(t.stream_id(), stream_id);
    assert_eq!(t.data(), s);

    let cell = FixedCell::from(t);
    assert_eq!(cell, data);
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzData {
    version: CellVersion,
    data: FixedCellData,
}

fuzz_target!(|data: FuzzData| {
    let FuzzData { version, data } = data;
    let version = Ver::from(version);
    let mut cell = FixedCell::from(data);

    dispatch! {
        (data, cell, version) {
            BeginDir => cast_begin_dir,
            Drop => cast_drop,
            Data => cast_data,
        }
    }
});
