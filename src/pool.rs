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
            split: None,
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
    inner: BytesMut,
    owner: Arc<BufferPool>,
    split: Option<(BytesMut, bool)>,
    index: usize,
}

impl PoolBuffer {
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
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

    #[inline]
    pub fn split_off(&mut self, at: usize) -> &mut BytesMut {
        assert!(self.split.is_none());

        let split = self.inner.split_off(at);
        self.split = Some((split, true));

        self.split.as_mut().map(|(b, _)| b).unwrap()
    }

    #[inline]
    pub fn split_to(&mut self, at: usize) -> &mut BytesMut {
        assert!(self.split.is_none());

        let split = self.inner.split_to(at);
        self.split = Some((split, false));

        self.split.as_mut().map(|(b, _)| b).unwrap()
    }

    #[inline]
    pub fn freeze(self) -> FrozenPoolBuffer {
        FrozenPoolBuffer {
            inner: Arc::new(self),
        }
    }
}

impl fmt::Debug for PoolBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolBuffer")
            .field("len", &self.inner.len())
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

#[cfg(target_os = "linux")]
unsafe impl tokio_uring::buf::IoBufMut for PoolBuffer {
    #[inline]
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.inner.stable_mut_ptr()
    }

    #[inline]
    unsafe fn set_init(&mut self, pos: usize) {
        self.inner.set_init(pos)
    }
}

#[cfg(target_os = "linux")]
unsafe impl tokio_uring::buf::IoBuf for PoolBuffer {
    #[inline]
    fn stable_ptr(&self) -> *const u8 {
        self.inner.stable_ptr()
    }

    #[inline]
    fn bytes_init(&self) -> usize {
        self.inner.bytes_init()
    }

    #[inline]
    fn bytes_total(&self) -> usize {
        self.inner.bytes_total()
    }
}

impl Drop for PoolBuffer {
    #[inline]
    fn drop(&mut self) {
        if let Some((mut b, which)) = self.split.take() {
            if which {
                self.inner.unsplit(b);
            } else {
                b.unsplit(std::mem::replace(&mut self.inner, BytesMut::new()));
                self.inner = b;
            }
        }

        if self.inner.capacity() != 0 {
            let inner = std::mem::replace(&mut self.inner, BytesMut::new());
            self.owner.absorb(inner, self.index)
        }
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
}

#[cfg(target_os = "linux")]
unsafe impl tokio_uring::buf::IoBuf for FrozenPoolBuffer {
    #[inline]
    fn stable_ptr(&self) -> *const u8 {
        self.inner.stable_ptr()
    }

    #[inline]
    fn bytes_init(&self) -> usize {
        self.inner.bytes_init()
    }

    #[inline]
    fn bytes_total(&self) -> usize {
        self.inner.bytes_total()
    }
}
