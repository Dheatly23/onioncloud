#![no_main]

use std::assert_matches;
use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use onioncloud_ll_relay_cell::typed::connected::{ValidAddr, validate_addr};

fn check_addr(s: &str) -> Option<(ValidAddr<'_>, u16)> {
    let (a, p) = s.rsplit_once(':')?;

    if !matches!(p.as_bytes().get(0), Some(b'1'..=b'9')) {
        return None;
    }
    let port = p.parse::<u16>().ok()?;

    let addr = if let Ok(v) = a.parse::<IpAddr>() {
        ValidAddr::Ip(v)
    } else if a.is_empty()
        || a.ends_with(".")
        || a.starts_with(".")
        || a.bytes()
            .any(|c| !matches!(c, b'.' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'))
        || a.bytes().all(|c| c != b'.')
        || a.contains("..")
    {
        return None;
    } else {
        ValidAddr::Host(a)
    };

    Some((addr, port))
}

fuzz_target!(|data: &str| {
    if let Some((addr, port)) = check_addr(data) {
        let r = validate_addr(data).unwrap();
        assert_eq!(r.addr, addr);
        assert_eq!(r.port, port);
    } else {
        assert_matches!(validate_addr(data), None);
    }
});
