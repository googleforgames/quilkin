#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    return ptr;
}

#[no_mangle]
#[doc(hidden)]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    let align = std::mem::align_of::<usize>();
    let layout = std::alloc::Layout::from_size_align_unchecked(size, align);
    std::alloc::dealloc(ptr, layout);
}

#[no_mangle]
pub extern "C" fn read(ptr: *mut u8, size: usize) -> bool {
    let contents = unsafe { std::str::from_utf8(std::slice::from_raw_parts(ptr, size)).unwrap() };

    contents == "hello"
}

#[no_mangle]
pub extern "C" fn write(ptr: *mut u8, size: usize) -> bool {
    let contents = unsafe { std::str::from_utf8(std::slice::from_raw_parts(ptr, size)).unwrap() };

    contents == "hello"
}
