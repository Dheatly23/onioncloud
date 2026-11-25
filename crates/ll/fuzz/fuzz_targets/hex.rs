#![no_main]

use std::fmt::Write;

use libfuzzer_sys::fuzz_target;
#[cfg(target_arch = "aarch64")]
use onioncloud_ll::utils::hex::aarch64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use onioncloud_ll::utils::hex::x86;
use onioncloud_ll::utils::hex::{FmtHex, generic, usimd};

fn ref_impl(i: &[u8]) -> String {
    let mut ret = String::with_capacity(i.len() * 2);
    for &i in i {
        write!(ret, "{i:02X}").unwrap();
    }
    ret
}

fuzz_target!(|i: &[u8]| {
    let r = ref_impl(i).into_bytes();
    assert_eq!(r.len(), i.len() * 2);
    let mut o = vec![0u8; r.len()];

    // SAFETY: Output size is exactly twice input size.
    unsafe { usimd::I.fmt_hex(o.as_mut_ptr(), i.as_ptr(), i.len()) };

    assert_eq!(r, o);

    cfg_select! {
        any(target_arch = "x86", target_arch = "x86_64") => {
            use std::arch::is_x86_feature_detected;

            if is_x86_feature_detected!("sse2") {
                // SAFETY: SSE2 is enabled.
                unsafe { x86::sse::I.fmt_hex(o.as_mut_ptr(), i.as_ptr(), i.len()) };
                assert_eq!(r, o);
            }

            if is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 is enabled.
                unsafe { x86::avx::I.fmt_hex(o.as_mut_ptr(), i.as_ptr(), i.len()) };
                assert_eq!(r, o);
            }
        }
        target_arch = "aarch64" => {
            use std::arch::is_aarch64_feature_detected;

            if is_aarch64_feature_detected!("neon") {
                // SAFETY: NEON is enabled.
                unsafe { aarch64::neon::I.fmt_hex(o.as_mut_ptr(), i.as_ptr(), i.len()) };
                assert_eq!(r, o);
            }
        }
    }
});
