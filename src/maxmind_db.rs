use std::sync::Arc;

use bytes::Bytes;
use maxminddb::Reader;
use once_cell::sync::Lazy;

type Result<T, E = Error> = std::result::Result<T, E>;

static HTTP: Lazy<
    hyper::Client<
        hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>,
        hyper::body::Body,
    >,
> = Lazy::new(|| {
    hyper::Client::builder().build(
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build(),
    )
});
pub static CLIENT: Lazy<arc_swap::ArcSwapOption<MaxmindDb>> = Lazy::new(<_>::default);

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(tag = "kind")]
pub enum Source {
    File { path: std::path::PathBuf },
    Url { url: url::Url },
}

impl std::str::FromStr for Source {
    type Err = eyre::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Ok(url) = input.parse() {
            Ok(Self::Url { url })
        } else if let Ok(path) = input.parse() {
            Ok(Self::File { path })
        } else {
            Err(eyre::eyre!("'{}' is not a valid URL or path", input))
        }
    }
}

#[derive(Debug)]
pub struct MaxmindDb {
    reader: Reader<Bytes>,
}

impl MaxmindDb {
    fn new(reader: Reader<Bytes>) -> Self {
        Self { reader }
    }

    pub fn instance() -> arc_swap::Guard<Option<Arc<MaxmindDb>>> {
        CLIENT.load()
    }

    pub fn lookup(ip: std::net::IpAddr) -> Option<IpNetEntry> {
        let mmdb = match crate::MaxmindDb::instance().clone() {
            Some(mmdb) => mmdb,
            None => {
                tracing::debug!("skipping mmdb telemetry, no maxmind database available");
                return None;
            }
        };

        match mmdb.lookup::<IpNetEntry>(ip) {
            Ok(asn) => Some(asn),
            Err(error) => {
                tracing::warn!(%ip, %error, "ip not found in maxmind database");
                None
            }
        }
    }

    #[tracing::instrument(skip_all)]
    pub async fn update(source: Source) -> Result<()> {
        let db = Self::from_source(source).await?;
        CLIENT.store(Some(Arc::new(db)));
        tracing::info!("maxmind database updated");
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn from_source(source: Source) -> Result<Self> {
        match source {
            Source::File { path } => Self::open(path).await,
            Source::Url { url } => Self::open_url(&url).await,
        }
    }

    #[tracing::instrument(skip_all, fields(path = %path.as_ref().display()))]
    pub async fn open<A: AsRef<std::path::Path>>(path: A) -> Result<Self> {
        let path = path.as_ref();
        tracing::info!(path=%path.display(), "trying to read local maxmind database");
        let bytes = Bytes::from(tokio::fs::read(path).await?);
        Reader::from_source(bytes)
            .map(Self::new)
            .map_err(From::from)
    }

    /// Reads a Maxmind DB from `url`, and if `cache` is `true`, then will use
    /// the cached result, retreiving a fresh copy otherwise.
    #[tracing::instrument(skip_all, fields(url = %url))]
    pub async fn open_url(url: &url::Url) -> Result<Self> {
        tracing::info!("requesting maxmind database from network");
        let data = hyper::body::to_bytes(
            HTTP.get(url.as_str().try_into().unwrap())
                .await?
                .into_body(),
        )
        .await?;

        tracing::debug!("finished download");
        let reader = Reader::from_source(data)?;

        Ok(Self { reader })
    }
}

impl std::ops::Deref for MaxmindDb {
    type Target = Reader<Bytes>;

    fn deref(&self) -> &Self::Target {
        &self.reader
    }
}

impl std::ops::DerefMut for MaxmindDb {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.reader
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct IpNetEntry {
    #[serde(default)]
    pub allocation: String,
    #[serde(default)]
    pub allocation_cc: String,
    #[serde(default)]
    pub allocation_registry: String,
    #[serde(default)]
    pub allocation_status: String,
    #[serde(default)]
    pub r#as: u64,
    #[serde(default)]
    pub as_cc: String,
    #[serde(default)]
    pub as_entity: String,
    #[serde(default)]
    pub as_name: String,
    #[serde(default)]
    pub as_private: bool,
    #[serde(default)]
    pub as_registry: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub prefix_asset: Vec<String>,
    #[serde(default)]
    pub prefix_assignment: String,
    #[serde(default)]
    pub prefix_bogon: bool,
    #[serde(default)]
    pub prefix_entity: String,
    #[serde(default)]
    pub prefix_name: String,
    #[serde(default)]
    pub prefix_origins: Vec<u64>,
    #[serde(default)]
    pub prefix_registry: String,
    #[serde(default)]
    pub rpki_status: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    MaxmindDb(#[from] maxminddb::MaxMindDBError),
    #[error(transparent)]
    Http(#[from] hyper::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
