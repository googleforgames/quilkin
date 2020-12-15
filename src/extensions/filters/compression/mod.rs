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

use core::fmt;
use std::fmt::Display;
use std::io;

use serde::export::Formatter;
use serde::{Deserialize, Serialize};
use slog::{o, warn, Logger};
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;

use crate::config::ProxyMode;
use crate::extensions::filters::compression::metrics::Metrics;
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

impl Default for Mode {
    fn default() -> Self {
        Mode::Snappy
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
struct Config {
    mode: Mode,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
        }
    }
}

pub struct CompressionFactory {
    log: Logger,
}

impl CompressionFactory {
    pub fn new(base: &Logger) -> Self {
        CompressionFactory { log: base.clone() }
    }
}

impl FilterFactory for CompressionFactory {
    fn name(&self) -> String {
        "quilkin.extensions.filters.compression.v1alpha1.Compression".into()
    }

    fn create_filter(
        &self,
        args: CreateFilterArgs,
    ) -> std::result::Result<Box<dyn Filter>, RegistryError> {
        let config: Option<Config> = serde_yaml::to_string(&args.config)
            .and_then(|raw_config| serde_yaml::from_str(raw_config.as_str()))
            .map_err(|err| RegistryError::DeserializeFailed(err.to_string()))?;

        Ok(Box::new(Compression::new(
            &self.log,
            config.unwrap_or_default(),
            args.proxy_mode,
            Metrics::new(&args.metrics_registry)?,
        )))
    }
}

/// Filter for compressing and decompressing packet data
struct Compression {
    log: Logger,
    metrics: Metrics,
    compression_mode: Mode,
    proxy_mode: ProxyMode,
    compressor: Box<dyn Compressor + Sync + Send>,
}

impl Compression {
    pub fn new(base: &Logger, config: Config, proxy_mode: ProxyMode, metrics: Metrics) -> Self {
        let compressor = match config.mode {
            Mode::Snappy => Box::new(Snappy {}),
        };
        Compression {
            log: base.new(o!("source" => "extensions::Compression")),
            metrics,
            compression_mode: config.mode,
            proxy_mode,
            compressor,
        }
    }

    /// track a failed attempt at compression
    fn failed_compression<T>(&self, err: Error) -> Option<T> {
        if self.metrics.packets_dropped_compression.get() % 1000 == 0 {
            warn!(self.log, "Could not compress packet, dropping"; 
                            "mode" => format!("{:?}", self.compression_mode), "error" => format!("{}", err), 
                            "count" => self.metrics.packets_dropped_compression.get());
        }
        self.metrics.packets_dropped_compression.inc();
        None
    }

    /// track a failed attempt at decompression
    fn failed_decompression<T>(&self, err: Error) -> Option<T> {
        if self.metrics.packets_dropped_decompression.get() % 1000 == 0 {
            warn!(self.log, "Could not decompress packet, dropping"; 
                            "mode" => format!("{:?}", self.compression_mode), "error" => format!("{}", err), 
                            "count" => self.metrics.packets_dropped_decompression.get());
        }
        self.metrics.packets_dropped_decompression.inc();
        None
    }
}

impl Filter for Compression {
    fn on_downstream_receive(&self, mut ctx: DownstreamContext) -> Option<DownstreamResponse> {
        let original_size = ctx.contents.len();
        match self.proxy_mode {
            ProxyMode::Client => match self.compressor.encode(&mut ctx.contents) {
                Ok(_) => {
                    // Important to convert to i64. Depending on compression algorithm, compressed
                    // values can be larger than the original, and we don't want a panic.
                    self.metrics
                        .bytes_diff_compression
                        .add(original_size as i64 - ctx.contents.len() as i64);
                    Some(ctx.into())
                }
                Err(err) => self.failed_compression(err),
            },
            ProxyMode::Server => match self.compressor.decode(&mut ctx.contents) {
                Ok(_) => {
                    self.metrics
                        .bytes_diff_decompression
                        .add(ctx.contents.len() as i64 - original_size as i64);
                    Some(ctx.into())
                }
                Err(err) => self.failed_decompression(err),
            },
        }
    }

    fn on_upstream_receive(&self, mut ctx: UpstreamContext) -> Option<UpstreamResponse> {
        let original_size = ctx.contents.len();
        match self.proxy_mode {
            ProxyMode::Client => match self.compressor.decode(&mut ctx.contents) {
                Ok(_) => {
                    self.metrics
                        .bytes_diff_decompression
                        .add(ctx.contents.len() as i64 - original_size as i64);
                    Some(ctx.into())
                }

                Err(err) => self.failed_decompression(err),
            },
            ProxyMode::Server => match self.compressor.encode(&mut ctx.contents) {
                Ok(_) => {
                    self.metrics
                        .bytes_diff_compression
                        .add(original_size as i64 - ctx.contents.len() as i64);
                    Some(ctx.into())
                }
                Err(err) => self.failed_compression(err),
            },
        }
    }
}

pub enum Error {
    IO(io::Error),
}

impl std::convert::From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::IO(inner) => write!(f, "io error: {}", inner),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// Trait provides a compression and decompression strategy for this filter.
/// Conversion takes place on a mutable Vec, to ensure the most performant compression or
/// decompression operation can occur.
trait Compressor {
    /// Take the contents of the Vec, and compress it - overwriting the original `contents` Vec
    fn encode(&self, contents: &mut Vec<u8>) -> Result<()>;
    /// Take the contents of the Vec, and decompress it - overwriting the original `contents` Vec
    fn decode(&self, contents: &mut Vec<u8>) -> Result<()>;
}

struct Snappy {}

impl Compressor for Snappy {
    fn encode(&self, contents: &mut Vec<u8>) -> Result<()> {
        let input = contents.clone();
        let mut slice = input.as_slice();
        contents.clear();
        let mut wtr = FrameEncoder::new(contents);
        io::copy(&mut slice, &mut wtr)?;
        Ok(())
    }

    fn decode(&self, contents: &mut Vec<u8>) -> Result<()> {
        let input = contents.clone();
        let mut rdr = FrameDecoder::new(input.as_slice());
        contents.clear();
        io::copy(&mut rdr, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_yaml::{Mapping, Value};

    use crate::config::{Endpoints, UpstreamEndpoints};
    use crate::test_utils::{ep, logger};

    use super::*;
    use prometheus::Registry;

    #[test]
    fn default_factory() {
        let log = logger();
        let factory = CompressionFactory::new(&log);
        let args = CreateFilterArgs::new(None);
        let filter = factory.create_filter(args).expect("should create a filter");
        assert_server_mode(filter.as_ref());
    }

    #[test]
    fn config_factory() {
        let log = logger();
        let factory = CompressionFactory::new(&log);
        let mut map = Mapping::new();
        map.insert(Value::String("mode".into()), Value::String("SNAPPY".into()));
        let config = Value::Mapping(map);
        let args = CreateFilterArgs::new(Some(&config));

        let filter = factory.create_filter(args).expect("should create a filter");
        assert_server_mode(filter.as_ref());
    }

    #[test]
    fn client_proxy_mode() {
        let log = logger();
        let compression = Compression::new(
            &log,
            Config::default(),
            ProxyMode::Client,
            Metrics::new(&Registry::default()).unwrap(),
        );
        let expected = contents_fixture();

        // on_downstream_receive compress
        let downstream_response = compression
            .on_downstream_receive(DownstreamContext::new(
                UpstreamEndpoints::from(Endpoints::new(vec![ep(1)]).unwrap()),
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

        // on_upstream_receive decompress
        let upstream_response = compression
            .on_upstream_receive(UpstreamContext::new(
                &ep(1),
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:8081".parse().unwrap(),
                downstream_response.contents.clone(),
            ))
            .expect("should decompress");

        assert_eq!(expected, upstream_response.contents);

        assert_eq!(0, compression.metrics.packets_dropped_decompression.get());
        assert_eq!(0, compression.metrics.packets_dropped_compression.get());

        let diff = expected.len() - downstream_response.contents.len();
        assert_eq!(
            diff as i64,
            compression.metrics.bytes_diff_compression.get()
        );
        assert_eq!(
            diff as i64,
            compression.metrics.bytes_diff_decompression.get()
        );
    }

    #[test]
    fn server_proxy_mode() {
        let log = logger();
        let compression = Compression::new(
            &log,
            Config::default(),
            ProxyMode::Server,
            Metrics::new(&Registry::default()).unwrap(),
        );
        let (original, compressed_content) = assert_server_mode(&compression);

        assert_eq!(0, compression.metrics.packets_dropped_decompression.get());
        assert_eq!(0, compression.metrics.packets_dropped_compression.get());
        let diff = original.len() - compressed_content.len();
        assert_eq!(
            diff as i64,
            compression.metrics.bytes_diff_compression.get()
        );
        assert_eq!(
            diff as i64,
            compression.metrics.bytes_diff_decompression.get()
        );
    }

    #[test]
    fn failed_decompress() {
        let log = logger();
        let compression = Compression::new(
            &log,
            Config::default(),
            ProxyMode::Client,
            Metrics::new(&Registry::default()).unwrap(),
        );

        let upstream_response = compression.on_upstream_receive(UpstreamContext::new(
            &ep(1),
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
            b"hello".to_vec(),
        ));

        assert!(upstream_response.is_none());
        assert_eq!(1, compression.metrics.packets_dropped_decompression.get());
        assert_eq!(0, compression.metrics.packets_dropped_compression.get());

        let compression = Compression::new(
            &log,
            Config::default(),
            ProxyMode::Server,
            Metrics::new(&Registry::default()).unwrap(),
        );

        let downstream_response = compression.on_downstream_receive(DownstreamContext::new(
            UpstreamEndpoints::from(Endpoints::new(vec![ep(1)]).unwrap()),
            "127.0.0.1:8080".parse().unwrap(),
            b"hello".to_vec(),
        ));

        assert!(downstream_response.is_none());
        assert_eq!(1, compression.metrics.packets_dropped_decompression.get());
        assert_eq!(0, compression.metrics.packets_dropped_compression.get());
        assert_eq!(0, compression.metrics.bytes_diff_decompression.get());
        assert_eq!(0, compression.metrics.bytes_diff_compression.get());
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

    /// assert the server mode works.
    /// Returns the original data packet, and the compressed version
    fn assert_server_mode<F>(filter: &F) -> (Vec<u8>, Vec<u8>)
    where
        F: Filter + ?Sized,
    {
        let expected = contents_fixture();
        // on_upstream_receive compress
        let upstream_response = filter
            .on_upstream_receive(UpstreamContext::new(
                &ep(1),
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

        // on_downstream_receive decompress
        let downstream_response = filter
            .on_downstream_receive(DownstreamContext::new(
                UpstreamEndpoints::from(Endpoints::new(vec![ep(1)]).unwrap()),
                "127.0.0.1:8080".parse().unwrap(),
                upstream_response.contents.clone(),
            ))
            .expect("should decompress");

        assert_eq!(expected, downstream_response.contents);
        (expected, upstream_response.contents)
    }
}
