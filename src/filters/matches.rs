crate::include_proto!("quilkin.extensions.filters.matches.v1alpha1");

use self::quilkin::extensions::filters::matches::v1alpha1 as proto;
use crate::{
    config::ConfigType,
    filters::{prelude::*, registry::FilterRegistry},
    metadata::Value,
};

pub const NAME: &str = "quilkin.extensions.filters.matches.v1alpha1.Matches";

/// Creates a new factory for generating match filters.
pub fn factory() -> DynFilterFactory {
    Box::from(MatchesFactory::new())
}

pub struct FilterConfig {
    metadata_key: String,
    branches: Vec<(Value, FilterInstance)>,
    fallthrough: FallthroughInstance,
}

impl FilterConfig {
    fn new(
        config: DirectionalConfig,
        filter_registry: FilterRegistry,
        metrics_registry: prometheus::Registry,
    ) -> Result<Self, Error> {
        let map_to_instance = |filter: &String, config_type: Option<ConfigType>| {
            let args = CreateFilterArgs::new(
                filter_registry.clone(),
                metrics_registry.clone(),
                config_type,
            )
            .with_metrics_registry(metrics_registry.clone());

            filter_registry.get(filter, args)
        };

        let branches = config
            .branches
            .iter()
            .map(|branch| {
                map_to_instance(&branch.filter, branch.config.clone())
                    .map(|instance| (branch.value.clone(), instance))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            metadata_key: config.metadata_key,
            branches,
            fallthrough: match config.fallthrough {
                Fallthrough::Pass => FallthroughInstance::Pass,
                Fallthrough::Drop => FallthroughInstance::Drop,
                Fallthrough::Filter { filter, config } => {
                    map_to_instance(&filter, config).map(FallthroughInstance::Filter)?
                }
            },
        })
    }
}

pub enum FallthroughInstance {
    Pass,
    Drop,
    Filter(FilterInstance),
}

struct Matches {
    on_read_filters: Option<FilterConfig>,
    on_write_filters: Option<FilterConfig>,
}

impl Matches {
    fn new(
        config: Config,
        filter_registry: FilterRegistry,
        metrics_registry: prometheus::Registry,
    ) -> Result<Self, Error> {
        let on_read_filters = config
            .on_read
            .map(|config| {
                FilterConfig::new(config, filter_registry.clone(), metrics_registry.clone())
            })
            .transpose()?;

        let on_write_filters = config
            .on_write
            .map(|config| {
                FilterConfig::new(config, filter_registry.clone(), metrics_registry.clone())
            })
            .transpose()?;

        if on_read_filters.is_none() && on_write_filters.is_none() {
            return Err(Error::MissingConfig(NAME));
        }

        Ok(Self {
            on_read_filters,
            on_write_filters,
        })
    }
}

fn match_filter<'config, Ctx, R>(
    config: &'config Option<FilterConfig>,
    ctx: Ctx,
    get_metadata: impl for<'ctx> Fn(&'ctx Ctx, &'config String) -> Option<&'ctx Value>,
    and_then: impl Fn(Ctx, &'config FilterInstance) -> Option<R>,
) -> Option<R>
where
    Ctx: Into<R>,
{
    match config {
        Some(config) => {
            let value = (get_metadata)(&ctx, &config.metadata_key)?;

            match config.branches.iter().find(|(key, _)| key == value) {
                Some((_, instance)) => (and_then)(ctx, instance),
                None => match &config.fallthrough {
                    FallthroughInstance::Pass => Some(ctx.into()),
                    FallthroughInstance::Drop => None,
                    FallthroughInstance::Filter(instance) => (and_then)(ctx, instance),
                },
            }
        }
        None => Some(ctx.into()),
    }
}

impl Filter for Matches {
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        match_filter(
            &self.on_read_filters,
            ctx,
            |ctx, metadata_key| ctx.metadata.get(metadata_key),
            |ctx, instance| instance.filter.read(ctx),
        )
    }

    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        match_filter(
            &self.on_write_filters,
            ctx,
            |ctx, metadata_key| ctx.metadata.get(metadata_key),
            |ctx, instance| instance.filter.write(ctx),
        )
    }
}

struct MatchesFactory;

impl MatchesFactory {
    pub fn new() -> Self {
        MatchesFactory
    }
}

impl FilterFactory for MatchesFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<FilterInstance, Error> {
        let (config_json, config) = self
            .require_config(args.config)?
            .deserialize::<Config, proto::Matches>(self.name())?;

        let filter = Matches::new(config, args.filter_registry, args.metrics_registry)?;
        Ok(FilterInstance::new(
            config_json,
            Box::new(filter) as Box<dyn Filter>,
        ))
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub on_read: Option<DirectionalConfig>,
    pub on_write: Option<DirectionalConfig>,
}

impl TryFrom<proto::Matches> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(value: proto::Matches) -> Result<Self, Self::Error> {
        Ok(Self {
            on_read: value
                .on_read
                .map(proto::matches::DirectionalConfig::try_into)
                .transpose()
                .map_err(|error: eyre::Report| {
                    ConvertProtoConfigError::new(error, Some("on_read".into()))
                })?,
            on_write: value
                .on_write
                .map(proto::matches::DirectionalConfig::try_into)
                .transpose()
                .map_err(|error: eyre::Report| {
                    ConvertProtoConfigError::new(error, Some("on_write".into()))
                })?,
        })
    }
}

impl TryFrom<proto::matches::DirectionalConfig> for DirectionalConfig {
    type Error = eyre::Report;

    fn try_from(value: proto::matches::DirectionalConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            metadata_key: value.metadata_key.ok_or_else(|| {
                ConvertProtoConfigError::new("Missing", Some("metadata_key".into()))
            })?,
            branches: value
                .branches
                .into_iter()
                .map(proto::matches::Branch::try_into)
                .collect::<Result<_, _>>()?,
            fallthrough: value
                .fallthrough
                .ok_or_else(|| ConvertProtoConfigError::new("Missing", Some("fallthrough".into())))?
                .try_into()?,
        })
    }
}

/// Configuration for a specific direction
#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct DirectionalConfig {
    #[serde(rename = "metadataKey")]
    pub metadata_key: String,
    pub branches: Vec<Branch>,
    #[serde(default)]
    pub fallthrough: Fallthrough,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct Branch {
    pub value: crate::metadata::Value,
    pub filter: String,
    pub config: Option<ConfigType>,
}

impl TryFrom<proto::matches::Branch> for Branch {
    type Error = eyre::Report;

    fn try_from(branch: proto::matches::Branch) -> Result<Self, Self::Error> {
        Ok(Self {
            value: branch
                .value
                .ok_or_else(|| ConvertProtoConfigError::new("Missing", Some("value".into())))?
                .try_into()?,
            filter: branch
                .filter
                .ok_or_else(|| ConvertProtoConfigError::new("Missing", Some("filter".into())))?,
            config: branch.config.map(ConfigType::Dynamic),
        })
    }
}

///  How the [`Matches`] filter should handle no branch being matched.
#[derive(Debug, PartialEq)]
pub enum Fallthrough {
    /// The packet will be passed onto the next filter.
    Pass,
    /// The packet will be dropped. **Default behaviour**
    Drop,
    /// The filter specified in `filter` will be called.
    Filter {
        filter: String,
        config: Option<ConfigType>,
    },
}

impl Default for Fallthrough {
    fn default() -> Self {
        Self::Drop
    }
}

impl TryFrom<proto::matches::directional_config::Fallthrough> for Fallthrough {
    type Error = eyre::Report;

    fn try_from(
        branch: proto::matches::directional_config::Fallthrough,
    ) -> Result<Self, Self::Error> {
        use proto::matches::directional_config::Fallthrough as ProtoFallthrough;

        Ok(match branch {
            ProtoFallthrough::Pass(_) => Self::Pass,
            ProtoFallthrough::Drop(_) => Self::Drop,
            ProtoFallthrough::Filter(filter) => Self::Filter {
                filter: filter
                    .filter
                    .ok_or_else(|| eyre::eyre!("missing `filter` field in Fallthrough configuration"))?,
                config: filter.config.map(ConfigType::Dynamic),
            },
        })
    }
}

impl serde::Serialize for Fallthrough {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Pass => ser.serialize_str("PASS"),
            Self::Drop => ser.serialize_str("DROP"),
            Self::Filter { filter, config } => {
                use serde::ser::SerializeMap;

                let mut map = ser.serialize_map(Some(2))?;

                map.serialize_entry("filter", filter)?;
                map.serialize_entry("config", config)?;

                map.end()
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for Fallthrough {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FallthroughVisitor;

        impl<'de> serde::de::Visitor<'de> for FallthroughVisitor {
            type Value = Fallthrough;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
                f.write_str("`pass`, `drop`, or an object containing a `filter` field and optionally `config` field")
            }

            fn visit_borrowed_str<E>(self, string: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(string)
            }

            fn visit_string<E>(self, string: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&string)
            }

            fn visit_str<E>(self, string: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match &*string.to_lowercase() {
                    "pass" => Ok(Fallthrough::Pass),
                    "drop" => Ok(Fallthrough::Drop),
                    _ => Err(serde::de::Error::custom("invalid fallthrough type.")),
                }
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                const CONFIG_FIELD: &str = "config";
                const FILTER_FIELD: &str = "filter";
                let mut config = None;
                let mut filter = None;
                loop {
                    match map.next_key::<String>()?.as_deref() {
                        Some(CONFIG_FIELD) => {
                            if config.replace(map.next_value()?).is_some() {
                                return Err(serde::de::Error::duplicate_field(CONFIG_FIELD));
                            }
                        }
                        Some(FILTER_FIELD) => {
                            if filter.replace(map.next_value()?).is_some() {
                                return Err(serde::de::Error::duplicate_field(FILTER_FIELD));
                            }
                        }
                        Some(field) => {
                            return Err(serde::de::Error::unknown_field(
                                field,
                                &[CONFIG_FIELD, FILTER_FIELD],
                            ))
                        }
                        None => break,
                    }
                }

                Ok(Fallthrough::Filter {
                    filter: filter.ok_or_else(|| serde::de::Error::missing_field("filter"))?,
                    config,
                })
            }
        }

        de.deserialize_any(FallthroughVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde() {
        let matches_yaml = "
on_read:
    metadataKey: quilkin.dev/captured_bytes
    branches:
        - value: abc
          filter: quilkin.extensions.filters.debug.v1alpha1.Debug
        ";

        let config = serde_yaml::from_str::<Config>(matches_yaml).unwrap();

        assert_eq!(
            config,
            Config {
                on_read: Some(DirectionalConfig {
                    metadata_key: "quilkin.dev/captured_bytes".into(),
                    branches: vec![Branch {
                        value: String::from("abc").into(),
                        filter: "quilkin.extensions.filters.debug.v1alpha1.Debug".into(),
                        config: None,
                    }],
                    fallthrough: Fallthrough::Drop,
                }),
                on_write: None,
            }
        )
    }
}
