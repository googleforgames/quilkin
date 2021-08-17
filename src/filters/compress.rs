/*
 * Copyright 2020 Google LLC
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

mod compressor;
mod config;
mod metrics;

crate::include_proto!("quilkin.extensions.filters.compress.v1alpha1");

use slog::{o, warn, Logger};

use crate::{config::LOG_SAMPLING_RATE, filters::prelude::*};

use self::quilkin::extensions::filters::compress::v1alpha1::Compress as ProtoConfig;
use compressor::Compressor;
use metrics::Metrics;

pub use config::{Action, Config, Mode};

pub const NAME: &str = "quilkin.extensions.filters.compress.v1alpha1.Compress";

/// Returns a factory for creating compression filters.
pub fn factory(base: &Logger) -> DynFilterFactory {
    Box::from(CompressFactory::new(base))
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
    fn new(base: &Logger, config: Config, metrics: Metrics) -> Self {
        Self {
            log: base.new(o!("source" => "extensions::Compress")),
            metrics,
            compressor: config.mode.as_compressor(),
            compression_mode: config.mode,
            on_read: config.on_read,
            on_write: config.on_write,
        }
    }

    /// Track a failed attempt at compression
    fn failed_compression<T>(&self, err: &dyn std::error::Error) -> Option<T> {
        if self.metrics.packets_dropped_compress.get() % LOG_SAMPLING_RATE == 0 {
            warn!(self.log, "Packets are being dropped as they could not be compressed";
                            "mode" => #?self.compression_mode, "error" => %err,
                            "count" => self.metrics.packets_dropped_compress.get());
        }
        self.metrics.packets_dropped_compress.inc();
        None
    }

    /// Track a failed attempt at decompression
    fn failed_decompression<T>(&self, err: &dyn std::error::Error) -> Option<T> {
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
                Err(err) => self.failed_compression(&err),
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
                Err(err) => self.failed_decompression(&err),
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
                Err(err) => self.failed_compression(&err),
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

                Err(err) => self.failed_decompression(&err),
            },
            Action::DoNothing => Some(ctx.into()),
        }
    }
}

struct CompressFactory {
    log: Logger,
}

impl CompressFactory {
    pub fn new(base: &Logger) -> Self {
        CompressFactory { log: base.clone() }
    }
}

impl FilterFactory for CompressFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(Compress::new(
            &self.log,
            self.require_config(args.config)?
                .deserialize::<Config, ProtoConfig>(self.name())?,
            Metrics::new(&args.metrics_registry)?,
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use prometheus::Registry;
    use serde_yaml::{Mapping, Value};

    use crate::endpoint::{Endpoint, Endpoints, UpstreamEndpoints};
    use crate::filters::{
        compress::{compressor::Snappy, Compressor},
        CreateFilterArgs, Filter, FilterFactory, ReadContext, WriteContext,
    };
    use crate::test_utils::logger;

    use super::quilkin::extensions::filters::compress::v1alpha1::{
        compress::{Action as ProtoAction, ActionValue, Mode as ProtoMode, ModeValue},
        Compress as ProtoConfig,
    };
    use super::{Action, Compress, CompressFactory, Config, Metrics, Mode};

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
                    Endpoints::new(vec![Endpoint::new("127.0.0.1:80".parse().unwrap())]).unwrap(),
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
                &Endpoint::new("127.0.0.1:80".parse().unwrap()),
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
            &Endpoint::new("127.0.0.1:80".parse().unwrap()),
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
                Endpoints::new(vec![Endpoint::new("127.0.0.1:80".parse().unwrap())]).unwrap(),
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
                Endpoints::new(vec![Endpoint::new("127.0.0.1:80".parse().unwrap())]).unwrap(),
            ),
            "127.0.0.1:8080".parse().unwrap(),
            b"hello".to_vec(),
        ));
        assert_eq!(b"hello".to_vec(), read_response.unwrap().contents);

        let write_response = compression.write(WriteContext::new(
            &Endpoint::new("127.0.0.1:80".parse().unwrap()),
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
                &Endpoint::new("127.0.0.1:80".parse().unwrap()),
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
                    Endpoints::new(vec![Endpoint::new("127.0.0.1:80".parse().unwrap())]).unwrap(),
                ),
                "127.0.0.1:8080".parse().unwrap(),
                write_response.contents.clone(),
            ))
            .expect("should decompress");

        assert_eq!(expected, read_response.contents);
        (expected, write_response.contents)
    }
}
