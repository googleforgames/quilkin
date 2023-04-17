use crate::metadata::Value;

/// Capture from the start of the packet.
#[derive(serde::Serialize, serde::Deserialize, Debug, schemars::JsonSchema)]
pub struct Regex {
    /// The regular expression to use for capture.
    #[serde(with = "serde_regex")]
    #[schemars(with = "String")]
    pub pattern: regex::bytes::Regex,
}

impl super::CaptureStrategy for Regex {
    fn capture(&self, contents: &mut Vec<u8>) -> Option<Value> {
        let matches = self
            .pattern
            .find_iter(contents)
            .map(|mat| Value::Bytes(bytes::Bytes::copy_from_slice(mat.as_bytes())))
            .collect::<Vec<_>>();

        if matches.len() > 1 {
            Some(Value::List(matches))
        } else {
            matches.into_iter().next()
        }
    }
}

impl PartialEq for Regex {
    fn eq(&self, rhs: &Self) -> bool {
        self.pattern.as_str() == rhs.pattern.as_str()
    }
}
