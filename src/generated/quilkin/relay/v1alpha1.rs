/// Generated client implementations.
pub mod aggregated_control_plane_discovery_service_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::http::Uri;
    use tonic::codegen::*;
    /// The Manager Discovery Service provides an RPC for a management
    /// service to upstream its configuration to a relay service.
    /// This RPC works essentially the same as xDS, except instead of the
    /// client connecting to the server to receive configuration, the
    /// client is connecting to the server send its configuration.
    ///
    /// This service enables the relay to merge the configuration of all
    /// currently live management servers as a single aggregated
    /// xDS server without the relay needing to maintain a list
    /// of xDS servers to connect to in the relay itself.
    #[derive(Debug, Clone)]
    pub struct AggregatedControlPlaneDiscoveryServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl AggregatedControlPlaneDiscoveryServiceClient<tonic::transport::Channel> {
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
    impl<T> AggregatedControlPlaneDiscoveryServiceClient<T>
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
        ) -> AggregatedControlPlaneDiscoveryServiceClient<InterceptedService<T, F>>
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
            AggregatedControlPlaneDiscoveryServiceClient::new(InterceptedService::new(
                inner,
                interceptor,
            ))
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
        /// The RPC protocol begins with a single empty DiscoveryResponse
        /// initiated by the management server, after that this behaves
        /// the same as the management server xDS protocol, except with
        /// DiscoveryRequests initiated by the server rather than the client.
        pub async fn stream_aggregated_resources(
            &mut self,
            request: impl tonic::IntoStreamingRequest<
                Message = super::super::super::super::envoy::service::discovery::v3::DiscoveryResponse,
            >,
        ) -> std::result::Result<
            tonic::Response<
                tonic::codec::Streaming<
                    super::super::super::super::envoy::service::discovery::v3::DiscoveryRequest,
                >,
            >,
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
                "/quilkin.relay.v1alpha1.AggregatedControlPlaneDiscoveryService/StreamAggregatedResources",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "quilkin.relay.v1alpha1.AggregatedControlPlaneDiscoveryService",
                "StreamAggregatedResources",
            ));
            self.inner.streaming(req, path, codec).await
        }
        pub async fn delta_aggregated_resources(
            &mut self,
            request: impl tonic::IntoStreamingRequest<
                Message = super::super::super::super::envoy::service::discovery::v3::DeltaDiscoveryResponse,
            >,
        ) -> std::result::Result<
            tonic::Response<
                tonic::codec::Streaming<
                    super::super::super::super::envoy::service::discovery::v3::DeltaDiscoveryRequest,
                >,
            >,
            tonic::Status,
        >{
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/quilkin.relay.v1alpha1.AggregatedControlPlaneDiscoveryService/DeltaAggregatedResources",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "quilkin.relay.v1alpha1.AggregatedControlPlaneDiscoveryService",
                "DeltaAggregatedResources",
            ));
            self.inner.streaming(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod aggregated_control_plane_discovery_service_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with AggregatedControlPlaneDiscoveryServiceServer.
    #[async_trait]
    pub trait AggregatedControlPlaneDiscoveryService: Send + Sync + 'static {
        /// Server streaming response type for the StreamAggregatedResources method.
        type StreamAggregatedResourcesStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<
                    super::super::super::super::envoy::service::discovery::v3::DiscoveryRequest,
                    tonic::Status,
                >,
            > + Send
            + 'static;
        /// The RPC protocol begins with a single empty DiscoveryResponse
        /// initiated by the management server, after that this behaves
        /// the same as the management server xDS protocol, except with
        /// DiscoveryRequests initiated by the server rather than the client.
        async fn stream_aggregated_resources(
            &self,
            request: tonic::Request<
                tonic::Streaming<
                    super::super::super::super::envoy::service::discovery::v3::DiscoveryResponse,
                >,
            >,
        ) -> std::result::Result<
            tonic::Response<Self::StreamAggregatedResourcesStream>,
            tonic::Status,
        >;
        /// Server streaming response type for the DeltaAggregatedResources method.
        type DeltaAggregatedResourcesStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<
                    super::super::super::super::envoy::service::discovery::v3::DeltaDiscoveryRequest,
                    tonic::Status,
                >,
            >
            + Send
            + 'static;
        async fn delta_aggregated_resources(
            &self,
            request: tonic::Request<
                tonic::Streaming<
                    super::super::super::super::envoy::service::discovery::v3::DeltaDiscoveryResponse,
                >,
            >,
        ) -> std::result::Result<tonic::Response<Self::DeltaAggregatedResourcesStream>, tonic::Status>;
    }
    /// The Manager Discovery Service provides an RPC for a management
    /// service to upstream its configuration to a relay service.
    /// This RPC works essentially the same as xDS, except instead of the
    /// client connecting to the server to receive configuration, the
    /// client is connecting to the server send its configuration.
    ///
    /// This service enables the relay to merge the configuration of all
    /// currently live management servers as a single aggregated
    /// xDS server without the relay needing to maintain a list
    /// of xDS servers to connect to in the relay itself.
    #[derive(Debug)]
    pub struct AggregatedControlPlaneDiscoveryServiceServer<
        T: AggregatedControlPlaneDiscoveryService,
    > {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: AggregatedControlPlaneDiscoveryService> AggregatedControlPlaneDiscoveryServiceServer<T> {
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
    impl<T, B> tonic::codegen::Service<http::Request<B>>
        for AggregatedControlPlaneDiscoveryServiceServer<T>
    where
        T: AggregatedControlPlaneDiscoveryService,
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
                "/quilkin.relay.v1alpha1.AggregatedControlPlaneDiscoveryService/StreamAggregatedResources" => {
                    #[allow(non_camel_case_types)]
                    struct StreamAggregatedResourcesSvc<
                        T: AggregatedControlPlaneDiscoveryService,
                    >(
                        pub Arc<T>,
                    );
                    impl<
                        T: AggregatedControlPlaneDiscoveryService,
                    > tonic::server::StreamingService<
                        super::super::super::super::envoy::service::discovery::v3::DiscoveryResponse,
                    > for StreamAggregatedResourcesSvc<T> {
                        type Response = super::super::super::super::envoy::service::discovery::v3::DiscoveryRequest;
                        type ResponseStream = T::StreamAggregatedResourcesStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                tonic::Streaming<
                                    super::super::super::super::envoy::service::discovery::v3::DiscoveryResponse,
                                >,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as AggregatedControlPlaneDiscoveryService>::stream_aggregated_resources(
                                        &inner,
                                        request,
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
                "/quilkin.relay.v1alpha1.AggregatedControlPlaneDiscoveryService/DeltaAggregatedResources" => {
                    #[allow(non_camel_case_types)]
                    struct DeltaAggregatedResourcesSvc<
                        T: AggregatedControlPlaneDiscoveryService,
                    >(
                        pub Arc<T>,
                    );
                    impl<
                        T: AggregatedControlPlaneDiscoveryService,
                    > tonic::server::StreamingService<
                        super::super::super::super::envoy::service::discovery::v3::DeltaDiscoveryResponse,
                    > for DeltaAggregatedResourcesSvc<T> {
                        type Response = super::super::super::super::envoy::service::discovery::v3::DeltaDiscoveryRequest;
                        type ResponseStream = T::DeltaAggregatedResourcesStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                tonic::Streaming<
                                    super::super::super::super::envoy::service::discovery::v3::DeltaDiscoveryResponse,
                                >,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as AggregatedControlPlaneDiscoveryService>::delta_aggregated_resources(
                                        &inner,
                                        request,
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
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: AggregatedControlPlaneDiscoveryService> Clone
        for AggregatedControlPlaneDiscoveryServiceServer<T>
    {
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
    impl<T: AggregatedControlPlaneDiscoveryService> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: AggregatedControlPlaneDiscoveryService> tonic::server::NamedService
        for AggregatedControlPlaneDiscoveryServiceServer<T>
    {
        const NAME: &'static str = "quilkin.relay.v1alpha1.AggregatedControlPlaneDiscoveryService";
    }
}
