//! Typed relay cells.

pub mod begin_dir;
pub mod connected;
pub mod data;
pub mod drop;
pub mod end;
pub mod padding_negotiate;
pub mod sendme;

use onioncloud_ll_cell::cache::{Cachable, CellCache};

#[doc(no_inline)]
pub use begin_dir::BeginDir;
#[doc(no_inline)]
pub use connected::Connected;
#[doc(no_inline)]
pub use data::Data;
#[doc(no_inline)]
pub use drop::Drop;
#[doc(no_inline)]
pub use end::End;
#[doc(no_inline)]
pub use padding_negotiate::{PaddingNegotiate, PaddingNegotiated};
#[doc(no_inline)]
pub use sendme::Sendme;

macro_rules! impl_cachable {
    ($($t:ty,)*) => {$(
        impl Cachable for $t {
            #[inline]
            fn cache<C: ?Sized + CellCache>(self, c: &C) {
                c.cache_cell(self.into());
            }
        }
    )*};
}

impl_cachable![
    BeginDir,
    Connected,
    Data,
    Drop,
    End,
    PaddingNegotiate,
    PaddingNegotiated,
    Sendme,
];
