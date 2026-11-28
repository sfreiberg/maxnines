//! Text as Windows' own functions take and give it: UTF-16, ending with a zero.

/// Text to give Windows.
pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// Reads up to a zero, as Windows' own strings end.
///
/// # Safety
/// `text` has to be null or point to a string that ends with a zero.
pub(crate) unsafe fn from_wide(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut length = 0;
    // SAFETY: the string ends with a zero, so nothing past it is read.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: those `length` characters were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) })
}
