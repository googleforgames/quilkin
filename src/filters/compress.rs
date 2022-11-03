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

crate::include_proto!("quilkin.filters.compress.v1alpha1");

use crate::{config::LOG_SAMPLING_RATE, filters::prelude::*};
use tracing::warn;

use self::quilkin::filters::compress::v1alpha1 as proto;
use compressor::Compressor;
use metrics::Metrics;

pub use config::{Action, Config, Mode};

/// Filter for compressing and decompressing packet data
pub struct Compress {
    metrics: Metrics,
    compression_mode: Mode,
    on_read: Action,
    on_write: Action,
    compressor: Box<dyn Compressor + Sync + Send>,
}

impl Compress {
    fn new(config: Config, metrics: Metrics) -> Self {
        Self {
            metrics,
            compressor: config.mode.as_compressor(),
            compression_mode: config.mode,
            on_read: config.on_read,
            on_write: config.on_write,
        }
    }

    /// Track a failed attempt at compression
    fn failed_compression<T>(&self, err: &dyn std::error::Error) -> Option<T> {
        if self.metrics.packets_dropped_total_compress.get() % LOG_SAMPLING_RATE == 0 {
            warn!(mode = ?self.compression_mode, error = %err, count = self.metrics.packets_dropped_total_compress.get(),
            "Packets are being dropped as they could not be compressed");
        }
        self.metrics.packets_dropped_total_compress.inc();
        None
    }

    /// Track a failed attempt at decompression
    fn failed_decompression<T>(&self, err: &dyn std::error::Error) -> Option<T> {
        if self.metrics.packets_dropped_total_decompress.get() % LOG_SAMPLING_RATE == 0 {
            warn!(mode = ?self.compression_mode, error = %err, count = ?self.metrics.packets_dropped_total_decompress.get(),
            "Packets are being dropped as they could not be decompressed");
        }
        self.metrics.packets_dropped_total_decompress.inc();
        None
    }
}

impl Filter for Compress {
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn read(&self, ctx: &mut ReadContext) -> Option<()> {
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
                    Some(())
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
                    Some(())
                }
                Err(err) => self.failed_decompression(&err),
            },
            Action::DoNothing => Some(()),
        }
    }

    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn write(&self, ctx: &mut WriteContext) -> Option<()> {
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
                    Some(())
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
                    Some(())
                }

                Err(err) => self.failed_decompression(&err),
            },
            Action::DoNothing => Some(()),
        }
    }
}

impl StaticFilter for Compress {
    const NAME: &'static str = "quilkin.filters.compress.v1alpha1.Compress";
    type Configuration = Config;
    type BinaryConfiguration = proto::Compress;

    fn try_from_config(config: Option<Self::Configuration>) -> Result<Self, Error> {
        Ok(Compress::new(
            Self::ensure_config_exists(config)?,
            Metrics::new()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use crate::{endpoint::Endpoint, filters::compress::compressor::Snappy};

    use super::*;
    use proto::compress::{Action as ProtoAction, ActionValue, Mode as ProtoMode, ModeValue};

    #[test]
    fn convert_proto_config() {
        let test_cases = vec![
            (
                "should succeed when all valid values are provided",
                proto::Compress {
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
                proto::Compress {
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
                proto::Compress {
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
                proto::Compress {
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
                proto::Compress {
                    mode: None,
                    on_read: None,
                    on_write: None,
                },
                Some(Config::default()),
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
        let config = serde_json::json!({
            "on_read": "DECOMPRESS".to_string(),
            "on_write": "COMPRESS".to_string(),

        });
        let filter = Compress::from_config(Some(serde_json::from_value(config).unwrap()));
        assert_downstream(&filter);
    }

    #[test]
    fn config_factory() {
        let config = serde_json::json!({
            "mode": "SNAPPY".to_string(),
            "on_read": "DECOMPRESS".to_string(),
            "on_write": "COMPRESS".to_string(),

        });
        let filter = Compress::from_config(Some(serde_json::from_value(config).unwrap()));
        assert_downstream(&filter);
    }

    #[test]
    fn upstream() {
        let compress = Compress::new(
            Config {
                mode: Default::default(),
                on_read: Action::Compress,
                on_write: Action::Decompress,
            },
            Metrics::new().unwrap(),
        );
        let expected = contents_fixture();

        // read compress
        let mut read_context = ReadContext::new(
            vec![Endpoint::new("127.0.0.1:80".parse().unwrap())],
            "127.0.0.1:8080".parse().unwrap(),
            expected.clone(),
        );
        compress.read(&mut read_context).expect("should compress");

        assert_ne!(expected, &*read_context.contents);
        assert!(
            expected.len() > read_context.contents.len(),
            "Original: {}. Compressed: {}",
            expected.len(),
            read_context.contents.len()
        );
        assert_eq!(
            expected.len() as u64,
            compress.metrics.decompressed_bytes_total.get()
        );
        assert_eq!(
            read_context.contents.len() as u64,
            compress.metrics.compressed_bytes_total.get()
        );

        // write decompress
        let mut write_context = WriteContext::new(
            Endpoint::new("127.0.0.1:80".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
            read_context.contents.clone(),
        );

        compress
            .write(&mut write_context)
            .expect("should decompress");

        assert_eq!(expected, &*write_context.contents);

        assert_eq!(0, compress.metrics.packets_dropped_total_decompress.get());
        assert_eq!(0, compress.metrics.packets_dropped_total_compress.get());
        // multiply by two, because data was sent both upstream and downstream
        assert_eq!(
            (read_context.contents.len() * 2) as u64,
            compress.metrics.compressed_bytes_total.get()
        );
        assert_eq!(
            (expected.len() * 2) as u64,
            compress.metrics.decompressed_bytes_total.get()
        );
    }

    #[test]
    fn downstream() {
        let compress = Compress::new(
            Config {
                mode: Default::default(),
                on_read: Action::Decompress,
                on_write: Action::Compress,
            },
            Metrics::new().unwrap(),
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

        assert_eq!(0, compress.metrics.packets_dropped_total_decompress.get());
        assert_eq!(0, compress.metrics.packets_dropped_total_compress.get());
    }

    #[traced_test]
    #[test]
    fn failed_decompress() {
        let compression = Compress::new(
            Config {
                mode: Default::default(),
                on_read: Action::Compress,
                on_write: Action::Decompress,
            },
            Metrics::new().unwrap(),
        );

        assert!(compression
            .write(&mut WriteContext::new(
                Endpoint::new("127.0.0.1:80".parse().unwrap()),
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:8081".parse().unwrap(),
                b"hello".to_vec(),
            ))
            .is_none());

        assert_eq!(
            1,
            compression.metrics.packets_dropped_total_decompress.get()
        );
        assert_eq!(0, compression.metrics.packets_dropped_total_compress.get());

        let compression = Compress::new(
            Config {
                mode: Default::default(),
                on_read: Action::Decompress,
                on_write: Action::Compress,
            },
            Metrics::new().unwrap(),
        );

        assert!(compression
            .read(&mut ReadContext::new(
                vec![Endpoint::new("127.0.0.1:80".parse().unwrap())],
                "127.0.0.1:8080".parse().unwrap(),
                b"hello".to_vec(),
            ))
            .is_none());

        assert!(logs_contain(
            "Packets are being dropped as they could not be decompressed"
        ));
        assert!(logs_contain("quilkin::filters::compress")); // the given name to the the logger by tracing

        assert_eq!(
            1,
            compression.metrics.packets_dropped_total_decompress.get()
        );
        assert_eq!(0, compression.metrics.packets_dropped_total_compress.get());
        assert_eq!(0, compression.metrics.compressed_bytes_total.get());
        assert_eq!(0, compression.metrics.decompressed_bytes_total.get());
    }

    #[test]
    fn do_nothing() {
        let compression = Compress::new(
            Config {
                mode: Default::default(),
                on_read: Action::default(),
                on_write: Action::default(),
            },
            Metrics::new().unwrap(),
        );

        let mut read_context = ReadContext::new(
            vec![Endpoint::new("127.0.0.1:80".parse().unwrap())],
            "127.0.0.1:8080".parse().unwrap(),
            b"hello".to_vec(),
        );
        compression.read(&mut read_context).unwrap();
        assert_eq!(b"hello", &*read_context.contents);

        let mut write_context = WriteContext::new(
            Endpoint::new("127.0.0.1:80".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
            b"hello".to_vec(),
        );

        compression.write(&mut write_context).unwrap();

        assert_eq!(b"hello".to_vec(), &*write_context.contents)
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
        let mut write_context = WriteContext::new(
            Endpoint::new("127.0.0.1:80".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
            expected.clone(),
        );

        filter.write(&mut write_context).expect("should compress");

        assert_ne!(expected, &*write_context.contents);
        assert!(
            expected.len() > write_context.contents.len(),
            "Original: {}. Compressed: {}",
            expected.len(),
            write_context.contents.len()
        );

        // read decompress
        let mut read_context = ReadContext::new(
            vec![Endpoint::new("127.0.0.1:80".parse().unwrap())],
            "127.0.0.1:8080".parse().unwrap(),
            write_context.contents.clone(),
        );

        filter.read(&mut read_context).expect("should decompress");

        assert_eq!(expected, &*read_context.contents);
        (expected, write_context.contents.to_vec())
    }
}
