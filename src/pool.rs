use bytes::BytesMut;
use parking_lot::Mutex;
use std::{
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering::Relaxed},
        Arc,
    },
};

type Pool = Mutex<Vec<BytesMut>>;

pub struct BufferPool {
    allocated: AtomicUsize,
    outstanding: AtomicUsize,
    pools: Vec<Pool>,
    buf_capacity: usize,
}

impl BufferPool {
    #[inline]
    pub fn new(buckets: usize, buf_capacity: usize) -> Self {
        let pools = (0..buckets).map(|_i| Mutex::new(Vec::new())).collect();

        Self {
            allocated: AtomicUsize::new(0),
            outstanding: AtomicUsize::new(0),
            buf_capacity,
            pools,
        }
    }

    #[inline]
    pub fn alloc(self: Arc<Self>) -> PoolBuffer {
        let size = self.buf_capacity;
        self.alloc_sized(size)
    }

    #[inline]
    pub fn alloc_sized(self: Arc<Self>, capacity: usize) -> PoolBuffer {
        let i = self.allocated.fetch_add(1, Relaxed);
        let index = i % self.pools.len();

        let mut inner = self.pools[index]
            .lock()
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(capacity));

        self.outstanding.fetch_add(1, Relaxed);

        if inner.capacity() < capacity {
            inner.reserve(capacity - inner.capacity());
        }

        PoolBuffer {
            inner,
            owner: self,
            index,
            prefix: None,
            suffix: None,
        }
    }

    #[inline]
    fn absorb(&self, mut buf: BytesMut, index: usize) {
        buf.clear();
        self.pools[index].lock().push(buf);
        self.outstanding.fetch_sub(1, Relaxed);
    }

    /// Creates a buffer filled with the specified data, only used for testing
    #[inline]
    pub fn alloc_slice(self: Arc<Self>, data: &[u8]) -> PoolBuffer {
        let mut buffer = self.alloc();
        buffer.inner.extend_from_slice(data);
        buffer
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(32, 64 * 1024)
    }
}

impl fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferPool")
            .field("allocated", &self.allocated.load(Relaxed))
            .field("outstanding", &self.outstanding.load(Relaxed))
            .finish_non_exhaustive()
    }
}

pub struct PoolBuffer {
    pub(crate) inner: BytesMut,
    owner: Arc<BufferPool>,
    prefix: Option<BytesMut>,
    suffix: Option<BytesMut>,
    index: usize,
}

impl PoolBuffer {
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.inner.extend_from_slice(slice);
    }

    #[inline]
    pub fn prepend_from_slice(&mut self, slice: &[u8]) {
        if self.inner.len() + slice.len() > self.inner.capacity() {
            let mut new_buffer = BytesMut::with_capacity(std::cmp::max(
                self.inner.capacity(),
                self.inner.len() + slice.len(),
            ));
            new_buffer.extend_from_slice(slice);
            new_buffer.extend_from_slice(&self.inner);
            self.inner = new_buffer;
        } else {
            self.inner.extend_from_slice(slice);
            let end = self.inner.len() - slice.len();
            self.inner.copy_within(0..end, slice.len());
            self.inner[..slice.len()].copy_from_slice(slice);
        }
    }

    #[inline]
    pub fn as_mut_slice(&mut self, range: std::ops::Range<usize>) -> &mut [u8] {
        if range.end > self.inner.len() {
            self.inner.resize(range.end, 0);
        }

        &mut self.inner[range]
    }

    #[inline]
    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    /// Splits a suffix of the specified length from the buffer and returns it
    ///
    /// The suffix will be [len - length, len) and this buffer will now be [0, len - length)
    #[inline]
    pub fn split_suffix(&mut self, length: usize) -> &[u8] {
        if let Some(current) = self.suffix.take() {
            let prev_len = current.len();
            self.inner.unsplit(current);
            self.suffix = Some(self.inner.split_off(self.inner.len() - length - prev_len));
            self.suffix.as_deref().map(|b| &b[..length]).unwrap()
        } else {
            self.suffix = Some(self.inner.split_off(self.inner.len() - length));
            self.suffix.as_deref().unwrap()
        }
    }

    /// Splits a prefix of the specified length from the buffer and returns it.
    ///
    /// The prefix will be [0, at) and this buffer will now be [at, len)
    #[inline]
    pub fn split_prefix(&mut self, at: usize) -> &[u8] {
        if let Some(mut current) = self.prefix.take() {
            let len = current.len();
            current.unsplit(std::mem::replace(&mut self.inner, BytesMut::new()));
            self.inner = current.split_off(at + len);
            self.prefix = Some(current);
            self.prefix.as_deref().map(|b| &b[..at]).unwrap()
        } else {
            self.prefix = Some(self.inner.split_to(at));
            self.prefix.as_deref().unwrap()
        }
    }

    #[inline]
    pub fn freeze(self) -> FrozenPoolBuffer {
        FrozenPoolBuffer {
            inner: Arc::new(self),
        }
    }

    /// Sets the length (number of initialized bytes) for the buffer
    #[inline]
    pub(crate) fn set_len(&mut self, len: usize) {
        unsafe { self.inner.set_len(len) }
    }
}

impl fmt::Debug for PoolBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolBuffer")
            .field("len", &self.inner.len())
            .field("prefix_len", &self.prefix.as_ref().map(|p| p.len()))
            .field("suffix_len", &self.suffix.as_ref().map(|p| p.len()))
            .finish_non_exhaustive()
    }
}

impl AsRef<[u8]> for PoolBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl std::ops::Deref for PoolBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for PoolBuffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice(0..self.inner.capacity())
    }
}

// #[cfg(target_os = "linux")]
// unsafe impl tokio_uring::buf::IoBufMut for PoolBuffer {
//     #[inline]
//     fn stable_mut_ptr(&mut self) -> *mut u8 {
//         self.inner.stable_mut_ptr()
//     }

//     #[inline]
//     unsafe fn set_init(&mut self, pos: usize) {
//         self.inner.set_init(pos)
//     }
// }

// #[cfg(target_os = "linux")]
// unsafe impl tokio_uring::buf::IoBuf for PoolBuffer {
//     #[inline]
//     fn stable_ptr(&self) -> *const u8 {
//         self.inner.stable_ptr()
//     }

//     #[inline]
//     fn bytes_init(&self) -> usize {
//         self.inner.bytes_init()
//     }

//     #[inline]
//     fn bytes_total(&self) -> usize {
//         self.inner.bytes_total()
//     }
// }

impl Drop for PoolBuffer {
    #[inline]
    fn drop(&mut self) {
        let mut inner = std::mem::replace(&mut self.inner, BytesMut::new());

        if let Some(mut prefix) = self.prefix.take() {
            prefix.unsplit(inner);
            inner = prefix;
        }

        if let Some(suffix) = self.suffix.take() {
            inner.unsplit(suffix);
        }

        self.owner.absorb(inner, self.index)
    }
}

#[derive(Clone)]
pub struct FrozenPoolBuffer {
    inner: Arc<PoolBuffer>,
}

impl FrozenPoolBuffer {
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// #[cfg(target_os = "linux")]
// unsafe impl tokio_uring::buf::IoBuf for FrozenPoolBuffer {
//     #[inline]
//     fn stable_ptr(&self) -> *const u8 {
//         self.inner.stable_ptr()
//     }

//     #[inline]
//     fn bytes_init(&self) -> usize {
//         self.inner.bytes_init()
//     }

//     #[inline]
//     fn bytes_total(&self) -> usize {
//         self.inner.bytes_total()
//     }
// }

impl std::ops::Deref for FrozenPoolBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn splits() {
        let pool = Arc::new(BufferPool::new(1, 10));

        let full_slice = &[9, 9, 9, 1, 1, 1, 1, 8, 8, 8];

        let mut buf = pool.alloc_slice(full_slice);

        assert_eq!(&[8], buf.split_suffix(1));
        assert_eq!(&full_slice[..9], buf.as_ref());
        assert_eq!(&[9, 9], buf.split_prefix(2));
        assert_eq!(&full_slice[2..9], buf.as_ref());
        assert_eq!(&[8, 8], buf.split_suffix(2));
        assert_eq!(&full_slice[2..7], buf.as_ref());
        assert_eq!(&[9], buf.split_prefix(1));
        assert_eq!(&[1, 1, 1, 1], buf.as_ref());
    }
}
