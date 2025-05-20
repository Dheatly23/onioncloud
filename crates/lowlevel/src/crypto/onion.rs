use std::slice::from_ref;

use ring::digest::{Context, SHA256};

/// Trait for onion skin layer.
pub trait OnionLayer {
    // TODO: Interface methods
}

pub fn kdf_tor(key: &[&[u8]], out: &mut [u8]) {
    let mut hasher = Context::new(&SHA256);
    for k in key {
        hasher.update(k);
    }

    let mut n = 255u8;
    for o in out.chunks_mut(32) {
        n = n.wrapping_add(1);

        let mut hasher = hasher.clone();
        hasher.update(from_ref(&n));
        let hash = hasher.finish();
        let hash = hash.as_ref();
        debug_assert!(o.len() <= hash.len());
        o.copy_from_slice(if o.len() == hash.len() {
            hash
        } else {
            &hash[..o.len()]
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_tor() {
        let mut out = [0; 255 * 32];
        kdf_tor(&[b"test123", b"test234"], &mut out);
    }
}
