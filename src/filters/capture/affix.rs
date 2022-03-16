use crate::metadata::Value;

use super::Metrics;

fn is_valid_size(contents: &[u8], size: u32, metrics: &Metrics) -> bool {
    // if the capture size is bigger than the packet size, then we drop the packet,
    // and occasionally warn
    if contents.len() < size as usize {
        if metrics.packets_dropped_total.get() % 1000 == 0 {
            tracing::warn!(count = ?metrics.packets_dropped_total.get(), "Packets are being dropped due to their length being less than {} bytes", size);
        }
        metrics.packets_dropped_total.inc();

        false
    } else {
        true
    }
}

/// Capture from the start of the packet.
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, schemars::JsonSchema)]
pub struct Prefix {
    /// Whether captured bytes are removed from the original packet.
    #[serde(default)]
    pub remove: bool,
    /// The number of bytes to capture.
    pub size: u32,
}

impl super::CaptureStrategy for Prefix {
    fn capture(&self, contents: &mut Vec<u8>, metrics: &Metrics) -> Option<Value> {
        is_valid_size(contents, self.size, metrics).then(|| {
            if self.remove {
                Value::Bytes(contents.drain(..self.size as usize).collect())
            } else {
                Value::Bytes(contents.iter().take(self.size as usize).copied().collect())
            }
        })
    }
}

/// Capture from the end of the packet.
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, schemars::JsonSchema)]
pub struct Suffix {
    /// Whether captured bytes are removed from the original packet.
    pub size: u32,
    /// The number of bytes to capture.
    #[serde(default)]
    pub remove: bool,
}

impl super::CaptureStrategy for Suffix {
    fn capture(&self, contents: &mut Vec<u8>, metrics: &Metrics) -> Option<Value> {
        is_valid_size(contents, self.size, metrics).then(|| {
            let index = contents.len() - self.size as usize;

            if self.remove {
                Value::Bytes(contents.split_off(index).into())
            } else {
                Value::Bytes(contents.iter().skip(index).copied().collect())
            }
        })
    }
}
