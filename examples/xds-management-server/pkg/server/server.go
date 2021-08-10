package server

import (
	"context"
	"fmt"
	"net"

	discoveryservice "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const (
	grpcMaxConcurrentStreams = 1000000
)

// Run starts a go-control-plane, xds grpc server in a background goroutine.
// The server is bounded by the provided context.
func Run(
	ctx context.Context,
	logger *log.Logger,
	port int16,
	snapshotCache cache.SnapshotCache,
	nodeIDCh chan<- string,
) error {
	logger = logger.WithFields(log.Fields{
		"component": "server",
	}).Logger

	cbs := &callbacks{log: logger, nodeIDCh: nodeIDCh}

	srv := server.NewServer(ctx, snapshotCache, cbs)

	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions, grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams))
	grpcServer := grpc.NewServer(grpcOptions...)

	discoveryservice.RegisterAggregatedDiscoveryServiceServer(grpcServer, srv)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, srv)

	go func() {
		<-ctx.Done()
		grpcServer.Stop()
		close(nodeIDCh)
	}()

	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	log.Infof("management server listening on %d\n", port)

	go func() {
		if err = grpcServer.Serve(listen); err != nil {
			log.WithError(err).Warn("gRPC server returned an error")
		}
	}()

	return nil
}
