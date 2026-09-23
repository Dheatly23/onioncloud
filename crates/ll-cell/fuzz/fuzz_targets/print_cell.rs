#![no_main]

use std::hint::black_box;

use arbitrary::{Arbitrary, Result as ArbResult, Unstructured};
use base64ct::{Base64Unpadded, Encoding};
use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::cell::{Cell, CellHeader, CellTy};
use onioncloud_ll_cell::fixed::{FIXED_CELL_SIZE, FixedCell};
use onioncloud_ll_cell::variable::VariableCell;

#[derive(Debug)]
struct LimitedData<'a, const MAX: usize>(&'a [u8]);

impl<'a, const MAX: usize> Arbitrary<'a> for LimitedData<'a, MAX> {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbResult<Self> {
        let len = u.arbitrary_len::<u8>()?.min(MAX);
        Ok(Self(u.bytes(len)?))
    }

    fn arbitrary_take_rest(u: Unstructured<'a>) -> ArbResult<Self> {
        let b = u.take_rest();
        Ok(Self(&b[..b.len().min(MAX)]))
    }

    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (0, Some(MAX))
    }
}

#[derive(Debug, Arbitrary)]
enum CellInnerData<'a> {
    Fixed(LimitedData<'a, FIXED_CELL_SIZE>),
    Variable(LimitedData<'a, 65535>),
}

#[derive(Debug, Arbitrary)]
struct CellData<'a> {
    command: u8,
    circuit: u32,
    data: CellInnerData<'a>,
}

fuzz_target!(|data: CellData<'_>| {
    let CellData {
        command,
        circuit,
        data,
    } = data;

    let cell = match data {
        CellInnerData::Fixed(data) => {
            let cell = FixedCell::from_slice(data.0);

            {
                let s = format!("{cell}");
                let mut l = [0; FIXED_CELL_SIZE];
                l[..data.0.len()].copy_from_slice(data.0);
                let t = Base64Unpadded::encode_string(&l);
                assert_eq!(s, t);
            }
            let _ = black_box(format!("{cell:?}"));

            CellTy::Fixed(cell)
        }
        CellInnerData::Variable(data) => {
            let cell = VariableCell::new(data.0.into());

            {
                let s = format!("{cell}");
                let t = Base64Unpadded::encode_string(data.0);
                assert_eq!(s, t);
            }
            let _ = black_box(format!("{cell:?}"));

            CellTy::Variable(cell)
        }
    };
    let cell = Cell::new(CellHeader { command, circuit }, cell);

    let _ = black_box(format!("{cell:?}"));
});
