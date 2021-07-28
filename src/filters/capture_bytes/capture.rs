/// Trait to implement different strategies for capturing packet data
pub trait Capture {
    /// Capture the packet data from the contents. If remove is true, contents will be altered to
    /// not have the retrieved set of bytes.
    /// Returns the captured bytes.
    fn capture(&self, contents: &mut Vec<u8>, size: usize, remove: bool) -> Vec<u8>;
}

/// Capture from the end of the packet.
pub struct Suffix;

impl Capture for Suffix {
    fn capture(&self, contents: &mut Vec<u8>, size: usize, remove: bool) -> Vec<u8> {
        if remove {
            return contents.split_off(contents.len() - size);
        }

        contents
            .iter()
            .skip(contents.len() - size)
            .cloned()
            .collect::<Vec<u8>>()
    }
}

/// Capture from the start of the packet.
pub struct Prefix;

impl Capture for Prefix {
    fn capture(&self, contents: &mut Vec<u8>, size: usize, remove: bool) -> Vec<u8> {
        if remove {
            return contents.drain(..size).collect();
        }

        contents.iter().cloned().take(size).collect()
    }
}
