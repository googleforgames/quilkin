/*
 * Copyright 2020 Google LLC All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use std::convert::TryFrom;
use std::io;

use serde::{Deserialize, Serialize};
use slog::{o, warn, Logger};
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;

use proto::quilkin::extensions::filters::compress::v1alpha1::{
    compress::Action as ProtoAction, compress::Mode as ProtoMode, Compress as ProtoConfig,
};

use crate::config::LOG_SAMPLING_RATE;
use crate::extensions::filters::compress::metrics::Metrics;
use crate::extensions::filters::ConvertProtoConfigError;
use crate::extensions::{
    CreateFilterArgs, Error as RegistryError, Filter, FilterFactory, ReadContext, ReadResponse,
    WriteContext, WriteResponse,
};
use crate::map_proto_enum;

mod metrics;
mod proto;

/// The library to use when compressing
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Mode {
    // we only support one mode for now, but adding in the config option to provide the
    // option to expand for later.
    #[serde(rename = "SNAPPY")]
    Snappy,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Snappy
    }
}

/// Whether to do nothing, compress or decompress the packet.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum Action {
    #[serde(rename = "DO_NOTHING")]
    DoNothing,
    #[serde(rename = "COMPRESS")]
    Compress,
    #[serde(rename = "DECOMPRESS")]
    Decompress,
}

impl Default for Action {
    fn default() -> Self {
        Action::DoNothing
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Config {
    #[serde(default)]
    mode: Mode,
    on_read: Action,
    on_write: Action,
}

impl TryFrom<ProtoConfig> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoConfig) -> std::result::Result<Self, Self::Error> {
        let mode = p
            .mode
            .map(|mode| {
                map_proto_enum!(
                    value = mode.value,
                    field = "mode",
                    proto_enum_type = ProtoMode,
                    target_enum_type = Mode,
                    variants = [Snappy]
                )
            })
            .transpose()?
            .unwrap_or_else(Mode::default);

        let on_read = p
            .on_read
            .map(|on_read| {
                map_proto_enum!(
                    value = on_read.value,
                    field = "on_read",
                    proto_enum_type = ProtoAction,
                    target_enum_type = Action,
                    variants = [DoNothing, Compress, Decompress]
                )
            })
            .transpose()?
            .unwrap_or_else(Action::default);

        let on_write = p
            .on_write
            .map(|on_write| {
                map_proto_enum!(
                    value = on_write.value,
                    field = "on_write",
                    proto_enum_type = ProtoAction,
                    target_enum_type = Action,
                    variants = [DoNothing, Compress, Decompress]
                )
            })
            .transpose()?
            .unwrap_or_else(Action::default);

        Ok(Self {
            mode,
            on_read,
            on_write,
        })
    }
}

pub struct CompressFactory {
    log: Logger,
}

impl CompressFactory {
    pub fn new(base: &Logger) -> Self {
        CompressFactory { log: base.clone() }
    }
}

impl FilterFactory for CompressFactory {
    fn name(&self) -> String {
        "quilkin.extensions.filters.compress.v1alpha1.Compress".into()
    }

    fn create_filter(
        &self,
        args: CreateFilterArgs,
    ) -> std::result::Result<Box<dyn Filter>, RegistryError> {
        Ok(Box::new(Compress::new(
            &self.log,
            self.require_config(args.config)?
                .deserialize::<Config, ProtoConfig>(self.name().as_str())?,
            Metrics::new(&args.metrics_registry)?,
        )))
    }
}

/// Filter for compressing and decompressing packet data
struct Compress {
    log: Logger,
    metrics: Metrics,
    compression_mode: Mode,
    on_read: Action,
    on_write: Action,
    compressor: Box<dyn Compressor + Sync + Send>,
}

impl Compress {
    pub fn new(base: &Logger, config: Config, metrics: Metrics) -> Self {
        let compressor = match config.mode {
            Mode::Snappy => Box::new(Snappy {}),
        };
        Compress {
            log: base.new(o!("source" => "extensions::Compress")),
            metrics,
            compression_mode: config.mode,
            on_read: config.on_read,
            on_write: config.on_write,
            compressor,
        }
    }

    /// Track a failed attempt at compression
    fn failed_compression<T>(&self, err: Box<dyn std::error::Error>) -> Option<T> {
        if self.metrics.packets_dropped_compress.get() % LOG_SAMPLING_RATE == 0 {
            warn!(self.log, "Packets are being dropped as they could not be compressed";
                            "mode" => #?self.compression_mode, "error" => %err,
                            "count" => self.metrics.packets_dropped_compress.get());
        }
        self.metrics.packets_dropped_compress.inc();
        None
    }

    /// Track a failed attempt at decompression
    fn failed_decompression<T>(&self, err: Box<dyn std::error::Error>) -> Option<T> {
        if self.metrics.packets_dropped_decompress.get() % LOG_SAMPLING_RATE == 0 {
            warn!(self.log, "Packets are being dropped as they could not be decompressed";
                            "mode" => #?self.compression_mode, "error" => %err,
                            "count" => self.metrics.packets_dropped_decompress.get());
        }
        self.metrics.packets_dropped_decompress.inc();
        None
    }
}

impl Filter for Compress {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        let original_size = ctx.contents.len();

        match self.on_read {
            Action::Compress => match self.compressor.encode(&mut ctx.contents) {
                Ok(()) => {
                    self.metrics
                        .decompressed_bytes_total
                        .inc_by(original_size as u64);
                    self.metrics
                        .compressed_bytes_total
                        .inc_by(ctx.contents.len() as u64);
                    Some(ctx.into())
                }
                Err(err) => self.failed_compression(err),
            },
            Action::Decompress => match self.compressor.decode(&mut ctx.contents) {
                Ok(()) => {
                    self.metrics
                        .compressed_bytes_total
                        .inc_by(original_size as u64);
                    self.metrics
                        .decompressed_bytes_total
                        .inc_by(ctx.contents.len() as u64);
                    Some(ctx.into())
                }
                Err(err) => self.failed_decompression(err),
            },
            Action::DoNothing => Some(ctx.into()),
        }
    }

    fn write(&self, mut ctx: WriteContext) -> Option<WriteResponse> {
        let original_size = ctx.contents.len();
        match self.on_write {
            Action::Compress => match self.compressor.encode(&mut ctx.contents) {
                Ok(()) => {
                    self.metrics
                        .decompressed_bytes_total
                        .inc_by(original_size as u64);
                    self.metrics
                        .compressed_bytes_total
                        .inc_by(ctx.contents.len() as u64);
                    Some(ctx.into())
                }
                Err(err) => self.failed_compression(err),
            },
            Action::Decompress => match self.compressor.decode(&mut ctx.contents) {
                Ok(()) => {
                    self.metrics
                        .compressed_bytes_total
                        .inc_by(original_size as u64);
                    self.metrics
                        .decompressed_bytes_total
                        .inc_by(ctx.contents.len() as u64);
                    Some(ctx.into())
                }

                Err(err) => self.failed_decompression(err),
            },
            Action::DoNothing => Some(ctx.into()),
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A trait that provides a compression and decompression strategy for this filter.
/// Conversion takes place on a mutable Vec, to ensure the most performant compression or
/// decompression operation can occur.
trait Compressor {
    /// Compress the contents of the Vec - overwriting the original content.
    fn encode(&self, contents: &mut Vec<u8>) -> Result<()>;
    /// Decompress the contents of the Vec - overwriting the original content.
    fn decode(&self, contents: &mut Vec<u8>) -> Result<()>;
}

struct Snappy {}

impl Compressor for Snappy {
    fn encode(&self, contents: &mut Vec<u8>) -> Result<()> {
        let input = std::mem::replace(contents, Vec::new());
        let mut wtr = FrameEncoder::new(contents);
        io::copy(&mut input.as_slice(), &mut wtr)?;
        Ok(())
    }

    fn decode(&self, contents: &mut Vec<u8>) -> Result<()> {
        let input = std::mem::replace(contents, Vec::new());
        let mut rdr = FrameDecoder::new(input.as_slice());
        io::copy(&mut rdr, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use prometheus::Registry;
    use serde_yaml::{Mapping, Value};

    use crate::cluster::Endpoint;
    use crate::config::{Endpoints, UpstreamEndpoints};
    use crate::extensions::filters::compress::Compressor;
    use crate::extensions::{CreateFilterArgs, Filter, FilterFactory, ReadContext, WriteContext};
    use crate::test_utils::logger;

    use super::proto::quilkin::extensions::filters::compress::v1alpha1::{
        compress::{Action as ProtoAction, ActionValue, Mode as ProtoMode, ModeValue},
        Compress as ProtoConfig,
    };
    use super::{Action, Compress, CompressFactory, Config, Metrics, Mode, Snappy};

    #[test]
    fn convert_proto_config() {
        let test_cases = vec![
            (
                "should succeed when all valid values are provided",
                ProtoConfig {
                    mode: Some(ModeValue {
                        value: ProtoMode::Snappy as i32,
                    }),
                    on_read: Some(ActionValue {
                        value: ProtoAction::Compress as i32,
                    }),
                    on_write: Some(ActionValue {
                        value: ProtoAction::Decompress as i32,
                    }),
                },
                Some(Config {
                    mode: Mode::Snappy,
                    on_read: Action::Compress,
                    on_write: Action::Decompress,
                }),
            ),
            (
                "should fail when invalid mode is provided",
                ProtoConfig {
                    mode: Some(ModeValue { value: 42 }),
                    on_read: Some(ActionValue {
                        value: ProtoAction::Compress as i32,
                    }),
                    on_write: Some(ActionValue {
                        value: ProtoAction::Decompress as i32,
                    }),
                },
                None,
            ),
            (
                "should fail when invalid on_read is provided",
                ProtoConfig {
                    mode: Some(ModeValue {
                        value: ProtoMode::Snappy as i32,
                    }),
                    on_read: Some(ActionValue { value: 73 }),
                    on_write: Some(ActionValue {
                        value: ProtoAction::Decompress as i32,
                    }),
                },
                None,
            ),
            (
                "should fail when invalid on_write is provided",
                ProtoConfig {
                    mode: Some(ModeValue {
                        value: ProtoMode::Snappy as i32,
                    }),
                    on_read: Some(ActionValue {
                        value: ProtoAction::Decompress as i32,
                    }),
                    on_write: Some(ActionValue { value: 73 }),
                },
                None,
            ),
            (
                "should use correct default values",
                ProtoConfig {
                    mode: None,
                    on_read: None,
                    on_write: None,
                },
                Some(Config {
                    mode: Mode::default(),
                    on_read: Action::default(),
                    on_write: Action::default(),
                }),
            ),
        ];
        for (name, proto_config, expected) in test_cases {
            let result = Config::try_from(proto_config);
            assert_eq!(
                result.is_err(),
                expected.is_none(),
                "{}: error expectation does not match",
                name
            );
            if let Some(expected) = expected {
                assert_eq!(expected, result.unwrap(), "{}", name);
            }
        }
    }

    #[test]
    fn default_mode_factory() {
        let log = logger();
        let factory = CompressFactory::new(&log);
        let mut map = Mapping::new();
        map.insert(
            Value::String("on_read".into()),
            Value::String("DECOMPRESS".into()),
        );
        map.insert(
            Value::String("on_write".into()),
            Value::String("COMPRESS".into()),
        );
        let filter = factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map)),
            ))
            .expect("should create a filter");
        assert_downstream(filter.as_ref());
    }

    #[test]
    fn config_factory() {
        let log = logger();
        let factory = CompressFactory::new(&log);
        let mut map = Mapping::new();
        map.insert(Value::String("mode".into()), Value::String("SNAPPY".into()));
        map.insert(
            Value::String("on_read".into()),
            Value::String("DECOMPRESS".into()),
        );
        map.insert(
            Value::String("on_write".into()),
            Value::String("COMPRESS".into()),
        );
        let config = Value::Mapping(map);
        let args = CreateFilterArgs::fixed(Registry::default(), Some(&config));

        let filter = factory.create_filter(args).expect("should create a filter");
        assert_downstream(filter.as_ref());
    }

    #[test]
    fn upstream() {
        let log = logger();
        let compress = Compress::new(
            &log,
            Config {
                mode: Default::default(),
                on_read: Action::Compress,
                on_write: Action::Decompress,
            },
            Metrics::new(&Registry::default()).unwrap(),
        );
        let expected = contents_fixture();

        // read compress
        let read_response = compress
            .read(ReadContext::new(
                UpstreamEndpoints::from(
                    Endpoints::new(vec![Endpoint::from_address(
                        "127.0.0.1:80".parse().unwrap(),
                    )])
                    .unwrap(),
                ),
                "127.0.0.1:8080".parse().unwrap(),
                expected.clone(),
            ))
            .expect("should compress");

        assert_ne!(expected, read_response.contents);
        assert!(
            expected.len() > read_response.contents.len(),
            "Original: {}. Compressed: {}",
            expected.len(),
            read_response.contents.len()
        );
        assert_eq!(
            expected.len() as u64,
            compress.metrics.decompressed_bytes_total.get()
        );
        assert_eq!(
            read_response.contents.len() as u64,
            compress.metrics.compressed_bytes_total.get()
        );

        // write decompress
        let write_response = compress
            .write(WriteContext::new(
                &Endpoint::from_address("127.0.0.1:80".parse().unwrap()),
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:8081".parse().unwrap(),
                read_response.contents.clone(),
            ))
            .expect("should decompress");

        assert_eq!(expected, write_response.contents);

        assert_eq!(0, compress.metrics.packets_dropped_decompress.get());
        assert_eq!(0, compress.metrics.packets_dropped_compress.get());
        // multiply by two, because data was sent both upstream and downstream
        assert_eq!(
            (read_response.contents.len() * 2) as u64,
            compress.metrics.compressed_bytes_total.get()
        );
        assert_eq!(
            (expected.len() * 2) as u64,
            compress.metrics.decompressed_bytes_total.get()
        );
    }

    #[test]
    fn downstream() {
        let log = logger();
        let compress = Compress::new(
            &log,
            Config {
                mode: Default::default(),
                on_read: Action::Decompress,
                on_write: Action::Compress,
            },
            Metrics::new(&Registry::default()).unwrap(),
        );

        let (expected, compressed) = assert_downstream(&compress);

        // multiply by two, because data was sent both downstream and upstream
        assert_eq!(
            (compressed.len() * 2) as u64,
            compress.metrics.compressed_bytes_total.get()
        );
        assert_eq!(
            (expected.len() * 2) as u64,
            compress.metrics.decompressed_bytes_total.get()
        );

        assert_eq!(0, compress.metrics.packets_dropped_decompress.get());
        assert_eq!(0, compress.metrics.packets_dropped_compress.get());
    }

    #[test]
    fn failed_decompress() {
        let log = logger();
        let compression = Compress::new(
            &log,
            Config {
                mode: Default::default(),
                on_read: Action::Compress,
                on_write: Action::Decompress,
            },
            Metrics::new(&Registry::default()).unwrap(),
        );

        let write_response = compression.write(WriteContext::new(
            &Endpoint::from_address("127.0.0.1:80".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
            b"hello".to_vec(),
        ));

        assert!(write_response.is_none());
        assert_eq!(1, compression.metrics.packets_dropped_decompress.get());
        assert_eq!(0, compression.metrics.packets_dropped_compress.get());

        let compression = Compress::new(
            &log,
            Config {
                mode: Default::default(),
                on_read: Action::Decompress,
                on_write: Action::Compress,
            },
            Metrics::new(&Registry::default()).unwrap(),
        );

        let read_response = compression.read(ReadContext::new(
            UpstreamEndpoints::from(
                Endpoints::new(vec![Endpoint::from_address(
                    "127.0.0.1:80".parse().unwrap(),
                )])
                .unwrap(),
            ),
            "127.0.0.1:8080".parse().unwrap(),
            b"hello".to_vec(),
        ));

        assert!(read_response.is_none());
        assert_eq!(1, compression.metrics.packets_dropped_decompress.get());
        assert_eq!(0, compression.metrics.packets_dropped_compress.get());
        assert_eq!(0, compression.metrics.compressed_bytes_total.get());
        assert_eq!(0, compression.metrics.decompressed_bytes_total.get());
    }

    #[test]
    fn do_nothing() {
        let log = logger();
        let compression = Compress::new(
            &log,
            Config {
                mode: Default::default(),
                on_read: Action::default(),
                on_write: Action::default(),
            },
            Metrics::new(&Registry::default()).unwrap(),
        );

        let read_response = compression.read(ReadContext::new(
            UpstreamEndpoints::from(
                Endpoints::new(vec![Endpoint::from_address(
                    "127.0.0.1:80".parse().unwrap(),
                )])
                .unwrap(),
            ),
            "127.0.0.1:8080".parse().unwrap(),
            b"hello".to_vec(),
        ));
        assert_eq!(b"hello".to_vec(), read_response.unwrap().contents);

        let write_response = compression.write(WriteContext::new(
            &Endpoint::from_address("127.0.0.1:80".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
            b"hello".to_vec(),
        ));

        assert_eq!(b"hello".to_vec(), write_response.unwrap().contents)
    }

    #[test]
    fn snappy() {
        let expected = contents_fixture();
        let mut contents = expected.clone();
        let snappy = Snappy {};

        let ok = snappy.encode(&mut contents);
        assert!(ok.is_ok());
        assert!(
            !contents.is_empty(),
            "compressed array should be greater than 0"
        );
        assert_ne!(
            expected, contents,
            "should not be equal, as one should be compressed"
        );
        assert!(
            expected.len() > contents.len(),
            "Original: {}. Compressed: {}",
            expected.len(),
            contents.len()
        ); // 45000 bytes uncompressed, 276 bytes compressed

        let ok = snappy.decode(&mut contents);
        assert!(ok.is_ok());
        assert_eq!(
            expected, contents,
            "should be equal, as decompressed state should go back to normal"
        );
    }

    /// At small data packets, compression will add data, so let's give a bigger data packet!
    fn contents_fixture() -> Vec<u8> {
        String::from("hello my name is mark and I like to do things")
            .repeat(100)
            .as_bytes()
            .to_vec()
    }

    /// assert compression work with decompress on read and compress on write
    /// Returns the original data packet, and the compressed version
    fn assert_downstream<F>(filter: &F) -> (Vec<u8>, Vec<u8>)
    where
        F: Filter + ?Sized,
    {
        let expected = contents_fixture();
        // write compress
        let write_response = filter
            .write(WriteContext::new(
                &Endpoint::from_address("127.0.0.1:80".parse().unwrap()),
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:8081".parse().unwrap(),
                expected.clone(),
            ))
            .expect("should compress");

        assert_ne!(expected, write_response.contents);
        assert!(
            expected.len() > write_response.contents.len(),
            "Original: {}. Compressed: {}",
            expected.len(),
            write_response.contents.len()
        );

        // read decompress
        let read_response = filter
            .read(ReadContext::new(
                UpstreamEndpoints::from(
                    Endpoints::new(vec![Endpoint::from_address(
                        "127.0.0.1:80".parse().unwrap(),
                    )])
                    .unwrap(),
                ),
                "127.0.0.1:8080".parse().unwrap(),
                write_response.contents.clone(),
            ))
            .expect("should decompress");

        assert_eq!(expected, read_response.contents);
        (expected, write_response.contents)
    }
}
