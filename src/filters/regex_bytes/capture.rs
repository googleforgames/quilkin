/// Trait to implement different strategies for capturing packet data
pub trait Capture {
    /// Capture the packet data from the contents. If remove is true, contents will be altered to
    /// not have the retrieved set of bytes.
    /// Returns the captured bytes.
    fn capture(&self, contents: &mut Vec<u8>) -> Vec<u8>;
}

impl Capture {
    fn capture(&self, contents: &mut Vec<u8>) -> Vec<u8> {
        contents.iter().cloned().collect::<Vec<u8>>()
    }
}
