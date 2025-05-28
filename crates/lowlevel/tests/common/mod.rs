use std::env::var;
use std::net::SocketAddr;

use onioncloud_lowlevel::crypto::relay::{RelayId, from_str as relay_from_str};

pub(crate) fn get_relay_data() -> (RelayId, Vec<SocketAddr>) {
    (
        relay_from_str(&var("RELAY_ID").unwrap()).unwrap(),
        var("RELAY_ADDRS")
            .unwrap()
            .split(',')
            .map(|s| s.parse::<SocketAddr>().unwrap())
            .collect::<Vec<_>>(),
    )
}
