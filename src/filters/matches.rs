crate::include_proto!("quilkin.extensions.filters.matches.v1alpha1");

use self::quilkin::extensions::filters::matches::v1alpha1::Matches as ProtoConfig;
use crate::filters::{prelude::*, registry::FilterRegistry};

pub const NAME: &str = "quilkin.extensions.filters.matches.v1alpha1.Matches";

/// Creates a new factory for generating capture filters.
pub fn factory() -> DynFilterFactory {
    Box::from(MatchesFactory::new())
}

struct Matches {
    config: Config,
    metrics_registry: prometheus::Registry,
    filter_registry: FilterRegistry,
}

impl Matches {
    fn new(
        config: Config,
        filter_registry: FilterRegistry,
        metrics_registry: prometheus::Registry,
    ) -> Self {
        Self {
            config,
            filter_registry,
            metrics_registry,
        }
    }
}

/// The actual behaviour of the matches filter, the only thing that changes
/// between read and write is which config and direction is called.
macro_rules! matches_filter {
    ($this:ident, $context:ident, $direction:ident, $config:ident) => {{
        let ctx = $context;
        let config = match $this.config.$config.as_ref() {
            Some(value) => value,
            None => return Some(ctx.into()),
        };

        for branch in &config.branches {
            if ctx.metadata.get(&config.metadata_key) == Some(&branch.value) {
                let args = CreateFilterArgs::fixed(
                    $this.filter_registry.clone(),
                    $this.metrics_registry.clone(),
                    branch.config.as_ref(),
                )
                .with_metrics_registry($this.metrics_registry.clone());

                let instance = $this.filter_registry.get(&branch.filter, args).ok()?;

                return instance.filter.$direction(ctx);
            }
        }

        None
    }};
}

impl Filter for Matches {
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        matches_filter!(self, ctx, read, on_read)
    }

    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        matches_filter!(self, ctx, write, on_write)
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
            .deserialize::<Config, ProtoConfig>(self.name())?;

        let filter = Matches::new(config, args.filter_registry.clone(), args.metrics_registry);
        Ok(FilterInstance::new(
            config_json,
            Box::new(filter) as Box<dyn Filter>,
        ))
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Config {
    on_read: Option<DirectionalConfig>,
    on_write: Option<DirectionalConfig>,
}

impl TryFrom<ProtoConfig> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(_value: ProtoConfig) -> Result<Self, Self::Error> {
        todo!()
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq)]
struct DirectionalConfig {
    metadata_key: String,
    branches: Vec<Branch>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq)]
struct Branch {
    value: crate::metadata::Value,
    filter: String,
    config: Option<serde_yaml::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde() {
        let matches_yaml = "
on_read:
    metadata_key: quilkin.dev/captured_bytes
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
                    }]
                }),
                on_write: None,
            }
        )
    }
}
