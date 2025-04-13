/// Trait for handling a value.
///
/// Useful for sans-io operations.
///
/// # Example
///
/// ```
/// use std::io::{Result, Read};
/// use onioncloud_lowlevel::util::sans_io::Handle;
/// use onioncloud_lowlevel::util::Buffer;
///
/// #[derive(Default)]
/// struct Handler {
///     buf: [u8; 4],
///     index: usize,
/// }
///
/// // Handle a stream reader.
/// impl Handle<&mut dyn Read> for Handler {
///     type Return = Result<u32>;
///
///     fn handle(&mut self, reader: &mut dyn Read) -> Self::Return {
///         // Keeps reading until we fill the buffer
///         // Non-blocking reader will return WouldBlock error,
///         // so caller can use it to detect when to yield.
///         // (read_exact will return UnexpectedEof instead, so don't use it).
///         while self.index < self.buf.len() {
///             self.index += reader.read(&mut self.buf[self.index..])?;
///         }
///
///         self.index = 0;
///         Ok(u32::from_be_bytes(self.buf))
///     }
/// }
///
/// // Use handler
/// let mut handler = Handler::default();
/// handler.handle(&mut Buffer::new(&[1, 2])).unwrap_err(); // Not enough data
/// assert_eq!(handler.handle(&mut Buffer::new(&[3, 4])).unwrap(), 0x01020304);
/// ```
pub trait Handle<Value> {
    type Return;

    fn handle(&mut self, value: Value) -> Self::Return;
}

impl<V, T: Handle<V> + ?Sized> Handle<V> for Box<T> {
    type Return = <T as Handle<V>>::Return;

    fn handle(&mut self, value: V) -> Self::Return {
        T::handle(self, value)
    }
}

/// Wrapper type to adapt function for [`Handle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FnHandle<F>(pub F);

impl<V, R, F> Handle<V> for FnHandle<F>
where
    F: FnMut(V) -> R,
{
    type Return = R;

    fn handle(&mut self, v: V) -> R {
        (self.0)(v)
    }
}
