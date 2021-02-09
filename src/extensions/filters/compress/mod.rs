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

use std::io;

use serde::{Deserialize, Serialize};
use slog::{o, warn, Logger};
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;

use crate::extensions::filters::compress::metrics::Metrics;
use crate::extensions::{
    CreateFilterArgs, DownstreamContext, DownstreamResponse, Error as RegistryError, Filter,
    FilterFactory, UpstreamContext, UpstreamResponse,
};

mod metrics;

/// The library to use when compressing
#[derive(Serialize, Deserialize, Debug)]
pub enum Mode {
    // we only support one mode for now, but adding in the config option to provide the
    // option to expand for later.
    #[serde(rename = "SNAPPY")]
    Snappy,
}

/// Compression direction (and decompression goes the other way)
#[derive(Serialize, Deserialize, Debug)]
pub enum Direction {
    /// Compress traffic flowing upstream (received by the proxy listening port, and sent to endpoint(s))
    #[serde(rename = "UPSTREAM")]
    Upstream,
    /// Compress traffic flowing downstream (received by an endpoint, and sent to the proxy listening port)
    #[serde(rename = "DOWNSTREAM")]
    Downstream,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Snappy
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    #[serde(default)]
    mode: Mode,
    direction: Direction,
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
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct TODO;
        impl From<TODO> for Config {
            fn from(_: TODO) -> Self {
                unimplemented!()
            }
        }
        Ok(Box::new(Compress::new(
            &self.log,
            self.require_config(args.config)?
                .deserialize::<Config, TODO>(self.name().as_str())?,
            Metrics::new(&args.metrics_registry)?,
        )))
    }
}

/// Filter for compressing and decompressing packet data
struct Compress {
    log: Logger,
    metrics: Metrics,
    compression_mode: Mode,
    direction: Direction,
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
            direction: config.direction,
            compressor,
        }
    }

    /// Track a failed attempt at compression
    fn failed_compression<T>(&self, err: Box<dyn std::error::Error>) -> Option<T> {
        if self.metrics.packets_dropped_compress.get() % 1000 == 0 {
            warn!(self.log, "Packets are being dropped as they could not be compressed"; 
                            "mode" => format!("{:?}", self.compression_mode), "error" => format!("{}", err), 
                            "count" => self.metrics.packets_dropped_compress.get());
        }
        self.metrics.packets_dropped_compress.inc();
        None
    }

    /// Track a failed attempt at decompression
    fn failed_decompression<T>(&self, err: Box<dyn std::error::Error>) -> Option<T> {
        if self.metrics.packets_dropped_decompress.get() % 1000 == 0 {
            warn!(self.log, "Packets are being dropped as they could not be decompressed"; 
                            "mode" => format!("{:?}", self.compression_mode), "error" => format!("{}", err), 
                            "count" => self.metrics.packets_dropped_decompress.get());
        }
        self.metrics.packets_dropped_decompress.inc();
        None
    }
}

impl Filter for Compress {
    fn on_upstream(&self, mut ctx: UpstreamContext) -> Option<UpstreamResponse> {
        let original_size = ctx.contents.len();
        match self.direction {
            Direction::Upstream => match self.compressor.encode(&mut ctx.contents) {
                Ok(()) => {
                    self.metrics
                        .decompressed_bytes_total
                        .inc_by(original_size as i64);
                    self.metrics
                        .compressed_bytes_total
                        .inc_by(ctx.contents.len() as i64);
                    Some(ctx.into())
                }
                Err(err) => self.failed_compression(err),
            },
            Direction::Downstream => match self.compressor.decode(&mut ctx.contents) {
                Ok(()) => {
                    self.metrics
                        .compressed_bytes_total
                        .inc_by(original_size as i64);
                    self.metrics
                        .decompressed_bytes_total
                        .inc_by(ctx.contents.len() as i64);
                    Some(ctx.into())
                }
                Err(err) => self.failed_decompression(err),
            },
        }
    }

    fn on_downstream(&self, mut ctx: DownstreamContext) -> Option<DownstreamResponse> {
        let original_size = ctx.contents.len();
        match self.direction {
            Direction::Upstream => match self.compressor.decode(&mut ctx.contents) {
                Ok(()) => {
                    self.metrics
                        .compressed_bytes_total
                        .inc_by(original_size as i64);
                    self.metrics
                        .decompressed_bytes_total
                        .inc_by(ctx.contents.len() as i64);
                    Some(ctx.into())
                }

                Err(err) => self.failed_decompression(err),
            },
            Direction::Downstream => match self.compressor.encode(&mut ctx.contents) {
                Ok(()) => {
                    self.metrics
                        .decompressed_bytes_total
                        .inc_by(original_size as i64);
                    self.metrics
                        .compressed_bytes_total
                        .inc_by(ctx.contents.len() as i64);
                    Some(ctx.into())
                }
                Err(err) => self.failed_compression(err),
            },
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
    use prometheus::Registry;
    use serde_yaml::{Mapping, Value};

    use crate::config::{Endpoints, UpstreamEndpoints};
    use crate::test_utils::logger;

    use super::*;
    use crate::cluster::Endpoint;

    #[test]
    fn default_mode_factory() {
        let log = logger();
        let factory = CompressFactory::new(&log);
        let mut map = Mapping::new();
        map.insert(
            Value::String("direction".into()),
            Value::String("DOWNSTREAM".into()),
        );
        let filter = factory
            .create_filter(CreateFilterArgs::fixed(Some(&Value::Mapping(map))))
            .expect("should create a filter");
        assert_downstream_direction(filter.as_ref());
    }

    #[test]
    fn config_factory() {
        let log = logger();
        let factory = CompressFactory::new(&log);
        let mut map = Mapping::new();
        map.insert(Value::String("mode".into()), Value::String("SNAPPY".into()));
        map.insert(
            Value::String("direction".into()),
            Value::String("DOWNSTREAM".into()),
        );
        let config = Value::Mapping(map);
        let args = CreateFilterArgs::fixed(Some(&config));

        let filter = factory.create_filter(args).expect("should create a filter");
        assert_downstream_direction(filter.as_ref());
    }

    #[test]
    fn upstream_direction() {
        let log = logger();
        let compress = Compress::new(
            &log,
            Config {
                mode: Default::default(),
                direction: Direction::Upstream,
            },
            Metrics::new(&Registry::default()).unwrap(),
        );
        let expected = contents_fixture();

        // on_upstream compress
        let downstream_response = compress
            .on_upstream(UpstreamContext::new(
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

        assert_ne!(expected, downstream_response.contents);
        assert!(
            expected.len() > downstream_response.contents.len(),
            "Original: {}. Compressed: {}",
            expected.len(),
            downstream_response.contents.len()
        );
        assert_eq!(
            expected.len() as i64,
            compress.metrics.decompressed_bytes_total.get()
        );
        assert_eq!(
            downstream_response.contents.len() as i64,
            compress.metrics.compressed_bytes_total.get()
        );

        // on_downstream decompress
        let upstream_response = compress
            .on_downstream(DownstreamContext::new(
                &Endpoint::from_address("127.0.0.1:80".parse().unwrap()),
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:8081".parse().unwrap(),
                downstream_response.contents.clone(),
            ))
            .expect("should decompress");

        assert_eq!(expected, upstream_response.contents);

        assert_eq!(0, compress.metrics.packets_dropped_decompress.get());
        assert_eq!(0, compress.metrics.packets_dropped_compress.get());
        // multiply by two, because data was sent both upstream and downstream
        assert_eq!(
            (downstream_response.contents.len() * 2) as i64,
            compress.metrics.compressed_bytes_total.get()
        );
        assert_eq!(
            (expected.len() * 2) as i64,
            compress.metrics.decompressed_bytes_total.get()
        );
    }

    #[test]
    fn downstream_direction() {
        let log = logger();
        let compress = Compress::new(
            &log,
            Config {
                mode: Default::default(),
                direction: Direction::Downstream,
            },
            Metrics::new(&Registry::default()).unwrap(),
        );

        let (expected, upstream_response) = assert_downstream_direction(&compress);

        // multiply by two, because data was sent both downstream and upstream
        assert_eq!(
            (upstream_response.len() * 2) as i64,
            compress.metrics.compressed_bytes_total.get()
        );
        assert_eq!(
            (expected.len() * 2) as i64,
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
                direction: Direction::Upstream,
            },
            Metrics::new(&Registry::default()).unwrap(),
        );

        let upstream_response = compression.on_downstream(DownstreamContext::new(
            &Endpoint::from_address("127.0.0.1:80".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
            b"hello".to_vec(),
        ));

        assert!(upstream_response.is_none());
        assert_eq!(1, compression.metrics.packets_dropped_decompress.get());
        assert_eq!(0, compression.metrics.packets_dropped_compress.get());

        let compression = Compress::new(
            &log,
            Config {
                mode: Default::default(),
                direction: Direction::Downstream,
            },
            Metrics::new(&Registry::default()).unwrap(),
        );

        let downstream_response = compression.on_upstream(UpstreamContext::new(
            UpstreamEndpoints::from(
                Endpoints::new(vec![Endpoint::from_address(
                    "127.0.0.1:80".parse().unwrap(),
                )])
                .unwrap(),
            ),
            "127.0.0.1:8080".parse().unwrap(),
            b"hello".to_vec(),
        ));

        assert!(downstream_response.is_none());
        assert_eq!(1, compression.metrics.packets_dropped_decompress.get());
        assert_eq!(0, compression.metrics.packets_dropped_compress.get());
        assert_eq!(0, compression.metrics.compressed_bytes_total.get());
        assert_eq!(0, compression.metrics.decompressed_bytes_total.get());
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

    /// assert compression work in a Downstream direction.
    /// Returns the original data packet, and the compressed version
    fn assert_downstream_direction<F>(filter: &F) -> (Vec<u8>, Vec<u8>)
    where
        F: Filter + ?Sized,
    {
        let expected = contents_fixture();
        // on_downstream compress
        let upstream_response = filter
            .on_downstream(DownstreamContext::new(
                &Endpoint::from_address("127.0.0.1:80".parse().unwrap()),
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:8081".parse().unwrap(),
                expected.clone(),
            ))
            .expect("should compress");

        assert_ne!(expected, upstream_response.contents);
        assert!(
            expected.len() > upstream_response.contents.len(),
            "Original: {}. Compressed: {}",
            expected.len(),
            upstream_response.contents.len()
        );

        // on_upstream decompress
        let downstream_response = filter
            .on_upstream(UpstreamContext::new(
                UpstreamEndpoints::from(
                    Endpoints::new(vec![Endpoint::from_address(
                        "127.0.0.1:80".parse().unwrap(),
                    )])
                    .unwrap(),
                ),
                "127.0.0.1:8080".parse().unwrap(),
                upstream_response.contents.clone(),
            ))
            .expect("should decompress");

        assert_eq!(expected, downstream_response.contents);
        (expected, upstream_response.contents)
    }
}
