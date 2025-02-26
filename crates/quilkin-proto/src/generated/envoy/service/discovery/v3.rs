#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DiscoveryRequest {
    #[prost(string, tag = "1")]
    pub version_info: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub node: ::core::option::Option<super::super::super::config::core::v3::Node>,
    #[prost(string, repeated, tag = "3")]
    pub resource_names: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "4")]
    pub type_url: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub response_nonce: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "6")]
    pub error_detail: ::core::option::Option<super::super::super::super::google::rpc::Status>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DiscoveryResponse {
    #[prost(string, tag = "1")]
    pub version_info: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "2")]
    pub resources: ::prost::alloc::vec::Vec<::prost_types::Any>,
    #[prost(bool, tag = "3")]
    pub canary: bool,
    #[prost(string, tag = "4")]
    pub type_url: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub nonce: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "6")]
    pub control_plane: ::core::option::Option<super::super::super::config::core::v3::ControlPlane>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeltaDiscoveryRequest {
    #[prost(message, optional, tag = "1")]
    pub node: ::core::option::Option<super::super::super::config::core::v3::Node>,
    #[prost(string, tag = "2")]
    pub type_url: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "3")]
    pub resource_names_subscribe: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag = "4")]
    pub resource_names_unsubscribe: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(map = "string, string", tag = "5")]
    pub initial_resource_versions:
        ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
    #[prost(string, tag = "6")]
    pub response_nonce: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "7")]
    pub error_detail: ::core::option::Option<super::super::super::super::google::rpc::Status>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeltaDiscoveryResponse {
    #[prost(string, tag = "1")]
    pub system_version_info: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "2")]
    pub resources: ::prost::alloc::vec::Vec<Resource>,
    #[prost(string, tag = "4")]
    pub type_url: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "6")]
    pub removed_resources: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "5")]
    pub nonce: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "7")]
    pub control_plane: ::core::option::Option<super::super::super::config::core::v3::ControlPlane>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Resource {
    #[prost(string, tag = "3")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "4")]
    pub aliases: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub resource: ::core::option::Option<::prost_types::Any>,
    #[prost(message, optional, tag = "6")]
    pub ttl: ::core::option::Option<::prost_types::Duration>,
    #[prost(message, optional, tag = "7")]
    pub cache_control: ::core::option::Option<resource::CacheControl>,
}
/// Nested message and enum types in `Resource`.
pub mod resource {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CacheControl {
        #[prost(bool, tag = "1")]
        pub do_not_cache: bool,
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AdsDummy {}
/// Generated client implementations.
pub mod aggregated_discovery_service_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::http::Uri;
    use tonic::codegen::*;
    /// See https://github.com/envoyproxy/envoy-api#apis for a description of the
    /// role of ADS and how it is intended to be used by a management server. ADS
    /// requests have the same structure as their singleton xDS counterparts, but can
    /// multiplex many resource types on a single stream. The type_url in the
    /// DiscoveryRequest/DiscoveryResponse provides sufficient information to recover
    /// the multiplexed singleton APIs at the Envoy instance and management server.
    #[derive(Debug, Clone)]
    pub struct AggregatedDiscoveryServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl AggregatedDiscoveryServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> AggregatedDiscoveryServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> AggregatedDiscoveryServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                    http::Request<tonic::body::BoxBody>,
                    Response = http::Response<
                        <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                    >,
                >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            AggregatedDiscoveryServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// This is a gRPC-only API.
        pub async fn stream_aggregated_resources(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::DiscoveryRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::DiscoveryResponse>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "envoy.service.discovery.v3.AggregatedDiscoveryService",
                "StreamAggregatedResources",
            ));
            self.inner.streaming(req, path, codec).await
        }
        pub async fn delta_aggregated_resources(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::DeltaDiscoveryRequest>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::DeltaDiscoveryResponse>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/envoy.service.discovery.v3.AggregatedDiscoveryService/DeltaAggregatedResources",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "envoy.service.discovery.v3.AggregatedDiscoveryService",
                "DeltaAggregatedResources",
            ));
            self.inner.streaming(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod aggregated_discovery_service_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with AggregatedDiscoveryServiceServer.
    #[async_trait]
    pub trait AggregatedDiscoveryService: Send + Sync + 'static {
        /// Server streaming response type for the StreamAggregatedResources method.
        type StreamAggregatedResourcesStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::DiscoveryResponse, tonic::Status>,
            > + Send
            + 'static;
        /// This is a gRPC-only API.
        async fn stream_aggregated_resources(
            &self,
            request: tonic::Request<tonic::Streaming<super::DiscoveryRequest>>,
        ) -> std::result::Result<
            tonic::Response<Self::StreamAggregatedResourcesStream>,
            tonic::Status,
        >;
        /// Server streaming response type for the DeltaAggregatedResources method.
        type DeltaAggregatedResourcesStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::DeltaDiscoveryResponse, tonic::Status>,
            > + Send
            + 'static;
        async fn delta_aggregated_resources(
            &self,
            request: tonic::Request<tonic::Streaming<super::DeltaDiscoveryRequest>>,
        ) -> std::result::Result<tonic::Response<Self::DeltaAggregatedResourcesStream>, tonic::Status>;
    }
    /// See https://github.com/envoyproxy/envoy-api#apis for a description of the
    /// role of ADS and how it is intended to be used by a management server. ADS
    /// requests have the same structure as their singleton xDS counterparts, but can
    /// multiplex many resource types on a single stream. The type_url in the
    /// DiscoveryRequest/DiscoveryResponse provides sufficient information to recover
    /// the multiplexed singleton APIs at the Envoy instance and management server.
    #[derive(Debug)]
    pub struct AggregatedDiscoveryServiceServer<T: AggregatedDiscoveryService> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: AggregatedDiscoveryService> AggregatedDiscoveryServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for AggregatedDiscoveryServiceServer<T>
    where
        T: AggregatedDiscoveryService,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources" =>
                {
                    #[allow(non_camel_case_types)]
                    struct StreamAggregatedResourcesSvc<T: AggregatedDiscoveryService>(pub Arc<T>);
                    impl<T: AggregatedDiscoveryService>
                        tonic::server::StreamingService<super::DiscoveryRequest>
                        for StreamAggregatedResourcesSvc<T>
                    {
                        type Response = super::DiscoveryResponse;
                        type ResponseStream = T::StreamAggregatedResourcesStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<tonic::Streaming<super::DiscoveryRequest>>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as AggregatedDiscoveryService>::stream_aggregated_resources(
                                    &inner, request,
                                )
                                .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = StreamAggregatedResourcesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/envoy.service.discovery.v3.AggregatedDiscoveryService/DeltaAggregatedResources" =>
                {
                    #[allow(non_camel_case_types)]
                    struct DeltaAggregatedResourcesSvc<T: AggregatedDiscoveryService>(pub Arc<T>);
                    impl<T: AggregatedDiscoveryService>
                        tonic::server::StreamingService<super::DeltaDiscoveryRequest>
                        for DeltaAggregatedResourcesSvc<T>
                    {
                        type Response = super::DeltaDiscoveryResponse;
                        type ResponseStream = T::DeltaAggregatedResourcesStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<tonic::Streaming<super::DeltaDiscoveryRequest>>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as AggregatedDiscoveryService>::delta_aggregated_resources(
                                    &inner, request,
                                )
                                .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DeltaAggregatedResourcesSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: AggregatedDiscoveryService> Clone for AggregatedDiscoveryServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    impl<T: AggregatedDiscoveryService> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: AggregatedDiscoveryService> tonic::server::NamedService
        for AggregatedDiscoveryServiceServer<T>
    {
        const NAME: &'static str = "envoy.service.discovery.v3.AggregatedDiscoveryService";
    }
}
