use std::{
    fmt,
    path::{Path, PathBuf},
};

use prometheus::proto::MetricType;
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};

use super::{error::TestSuiteDecodeError, Config};

/// The configuration of a Quilkin testsuite.
pub struct TestSuite {
    pub config: Config,
    pub options: TestConfig,
}

#[derive(Deserialize)]
pub struct TestConfig {
    pub config: Option<PathBuf>,
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
                Self { config, options }
            } else {
                let mut de = serde_yaml::Deserializer::from_str(src);
                let config =
                    Config::deserialize(de.next().ok_or(TestSuiteDecodeError::MissingConfig)?)?;
                let options = TestConfig::deserialize(
                    de.next().ok_or(TestSuiteDecodeError::MissingTestOptions)?,
                )?;
                Self { config, options }
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
    /// Metrics we expect to be set.
    pub metrics: Option<std::collections::HashMap<String, MetricComparison>>,
}

#[derive(Deserialize)]
pub struct MetricComparison {
    pub name: String,
    #[serde(deserialize_with = "metric_type_from_str")]
    pub r#type: MetricType,
    pub r#value: f64,
}

fn metric_type_from_str<'de, D>(deserializer: D) -> Result<MetricType, D::Error>
where
    D: Deserializer<'de>,
{
    const METRIC_TYPES: &[(&str, MetricType)] = &[
        ("counter", MetricType::COUNTER),
        ("gauge", MetricType::GAUGE),
        ("histogram", MetricType::HISTOGRAM),
        ("summary", MetricType::SUMMARY),
        ("untyped", MetricType::UNTYPED),
    ];

    let input = <&str>::deserialize(deserializer)?.to_lowercase();

    METRIC_TYPES
        .iter()
        .find(|(key, _)| *key == input)
        .map(|(_, value)| *value)
        .ok_or_else(|| {
            Error::custom(format!(
                "Invalid Prometheus metric type. Expected: {}",
                itertools::Itertools::intersperse(
                    METRIC_TYPES.iter().map(|(key, _)| format!("`{}`", key)),
                    String::from(", ")
                )
                .collect::<String>(),
            ))
        })
}

pub enum Data {
    String(String),
    Binary(Vec<u8>),
    Base64(Vec<u8>),
}

impl Data {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::String(string) => string.as_bytes(),
            Self::Binary(bytes) => bytes,
            Self::Base64(bytes) => bytes,
        }
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
                Ok(Data::String(value.to_owned()))
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(Data::Binary(value.to_owned()))
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
                    ("base64", value) => base64::decode(&value)
                        .map_err(Error::custom)
                        .map(Data::Base64),
                    (key, _) => Err(Error::custom(format!("Unknown data type: `{}`", key))),
                }
            }
        }

        deserializer.deserialize_any(DataVisitor)
    }
}
