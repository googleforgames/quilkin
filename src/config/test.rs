use std::{
    fmt,
    path::{Path, PathBuf},
};

use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};

use super::{error::TestSuiteDecodeError, Config};

/// The configuration of a Quilkin testsuite.
pub struct TestSuite {
    pub config: Config,
    pub options: TestConfig,
    /// Whether Quilkin should spawn an echo server for the tests or use the
    /// endpoints provided in the config.
    pub use_echo_server: bool,
}

#[derive(Deserialize)]
pub struct TestConfig {
    /// The path to the configuration file to test. If `None`, then the
    /// `TestConfig` must be included inline after a `Config` with a `---`
    /// document separator.
    pub config: Option<PathBuf>,
    /// The set of tests to be ran.
    pub tests: std::collections::HashMap<String, TestCase>,
}

impl TestSuite {
    pub fn find<P: AsRef<Path>>(
        log: &slog::Logger,
        path: Option<P>,
    ) -> Result<Self, TestSuiteDecodeError> {
        super::find_config_file(log, path)
            .map_err(From::from)
            .and_then(|s| Self::from_yaml(&s))
    }

    /// Attempts to deserialize [`Self`] from a YAML document. A valid source is
    /// either a combination of [`Config`] document followed by [`TestConfig`]
    /// document separated by a `---` (YAML document separator), or a
    /// `TestConfig` document containing a `config` key that points to a valid
    /// `Config` file.
    pub fn from_yaml(src: &str) -> Result<Self, TestSuiteDecodeError> {
        Ok(
            if let Ok(options) = serde_yaml::from_str::<TestConfig>(src) {
                let path = options
                    .config
                    .as_deref()
                    .ok_or(TestSuiteDecodeError::MissingConfigInTestOptions)?;
                let config = serde_yaml::from_reader(std::fs::File::open(path)?)?;
                Self {
                    config,
                    options,
                    use_echo_server: false,
                }
            } else {
                let mut de = serde_yaml::Deserializer::from_str(src);
                let config =
                    Config::deserialize(de.next().ok_or(TestSuiteDecodeError::MissingConfig)?)?;
                let options = TestConfig::deserialize(
                    de.next().ok_or(TestSuiteDecodeError::MissingTestOptions)?,
                )?;
                Self {
                    config,
                    options,
                    use_echo_server: false,
                }
            },
        )
    }
}

#[derive(Deserialize)]
pub struct TestCase {
    /// The data to be given to Quilkin.
    pub input: Data,
    /// What we expect Quilkin to send to the game server.
    pub output: Data,
}

/// The test data provided to quilkin. Currently can be provided as a string of
/// text, an array of bytes, or an object containing `type` and `value` fields,
/// currently valid combinations are as follows;
///
/// - type: `base64`, `value` is base64 encoded data.
pub struct Data(Vec<u8>);

impl Data {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for Data {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Data {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Serialize)]
        struct DataObject<'ty, 'value> {
            r#type: &'ty str,
            value: &'value str,
        }

        struct DataVisitor;

        impl<'de> Visitor<'de> for DataVisitor {
            type Value = Data;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter
                    .write_str("a string, an array of bytes or a map containing `type` and `value`")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(Data(value.to_owned().into_bytes()))
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(Data(value.to_owned()))
            }

            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                // `MapAccessDeserializer` is a wrapper that turns a `MapAccess`
                // into a `Deserializer`, allowing it to be used as the input to
                // DataObject's `Deserialize` implementation. DataObject then
                // deserializes itself using the entries from the map visitor.
                let object =
                    DataObject::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;

                match (&*object.r#type.to_lowercase(), object.value) {
                    ("base64", value) => base64::decode(&value).map_err(Error::custom).map(Data),
                    (key, _) => Err(Error::custom(format!("Unknown data type: `{}`", key))),
                }
            }
        }

        deserializer.deserialize_any(DataVisitor)
    }
}
