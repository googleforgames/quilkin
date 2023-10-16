use crate::net::endpoint::metadata::Value;

/// Returns whether the capture size is bigger than the packet size.
fn is_valid_size(contents: &[u8], size: u32) -> bool {
    contents.len() >= size as usize
}

/// Capture from the start of the packet.
#[derive(Debug, Eq, PartialEq, serde::Deserialize, schemars::JsonSchema, serde::Serialize)]
pub struct Prefix {
    /// Whether captured bytes are removed from the original packet.
    #[serde(default)]
    pub remove: bool,
    /// The number of bytes to capture.
    pub size: u32,
}

impl super::CaptureStrategy for Prefix {
    fn capture(&self, contents: &mut Vec<u8>) -> Option<Value> {
        is_valid_size(contents, self.size).then(|| {
            if self.remove {
                Value::Bytes(contents.drain(..self.size as usize).collect())
            } else {
                Value::Bytes(contents.iter().take(self.size as usize).copied().collect())
            }
        })
    }
}

/// Capture from the end of the packet.
#[derive(Debug, Eq, PartialEq, serde::Serialize, schemars::JsonSchema, serde::Deserialize)]
pub struct Suffix {
    /// Whether captured bytes are removed from the original packet.
    pub size: u32,
    /// The number of bytes to capture.
    #[serde(default)]
    pub remove: bool,
}

impl super::CaptureStrategy for Suffix {
    fn capture(&self, contents: &mut Vec<u8>) -> Option<Value> {
        is_valid_size(contents, self.size).then(|| {
            let index = contents.len() - self.size as usize;

            if self.remove {
                Value::Bytes(contents.split_off(index).into())
            } else {
                Value::Bytes(contents.iter().skip(index).copied().collect())
            }
        })
    }
}
