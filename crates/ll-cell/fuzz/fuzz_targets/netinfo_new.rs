#![no_main]

use std::net::IpAddr;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use onioncloud_ll_cell::fixed::{FIXED_CELL_SIZE, FixedCell};
use onioncloud_ll_cell::typed::Netinfo;

#[derive(Debug, Arbitrary)]
struct Data {
    timestamp: u32,
    other_addr: IpAddr,
    my_addrs: Vec<IpAddr>,
}

fn addr_len(a: &IpAddr) -> usize {
    2 + match a {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    }
}

fuzz_target!(|data: Data| {
    let len = 5 + addr_len(&data.other_addr) + data.my_addrs.iter().map(addr_len).sum::<usize>();
    let is_valid = data.my_addrs.len() < 256 && len <= FIXED_CELL_SIZE;

    let r = Netinfo::new(
        FixedCell::default(),
        data.timestamp,
        data.other_addr,
        data.my_addrs.iter().copied(),
    );

    if is_valid {
        let cell = r.unwrap();
        assert_eq!(cell.timestamp(), data.timestamp);
        assert_eq!(cell.other_addr(), data.other_addr);
        let it = cell.my_addrs();
        assert_eq!(it.len(), data.my_addrs.len());
        for (i, a) in it.enumerate() {
            assert_eq!(a, data.my_addrs[i], "mismatch at index {i}");
        }
    } else {
        r.unwrap_err();
    }
});
