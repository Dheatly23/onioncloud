pub mod cache;
pub mod cell;
pub mod channel;
pub mod circuit;
pub mod crypto;
pub mod errors;
pub mod linkver;
pub mod runtime;
pub mod util;

pub(crate) mod private {
    use std::pin::Pin;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[repr(transparent)]
    pub struct SealWrap<T: ?Sized>(pub(crate) T);

    impl<T: ?Sized> SealWrap<T> {
        pub(crate) fn project(self: Pin<&mut Self>) -> Pin<&mut T> {
            // SAFETY: Inner value is projected
            unsafe { Pin::new_unchecked(&mut Pin::into_inner_unchecked(self).0) }
        }
    }

    pub trait Sealed {}
}
