/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

// Server is a wrapper around go-control-plane's xds server.
type Server struct {
	logger *log.Logger
	// port is the port the server runs on.
	port int16
	// snapshotCache is passed updated by us and read by go-control-plane
	// to provided proxies with config from.
	snapshotCache cache.SnapshotCache
	// nodeIDCh is nilable. It is used as a callback mechanism from go-control-plane's server to
	// let us know when a new proxy has connected. The proxy's ID is passed on the channel.
	nodeIDCh chan<- string
}

// NewServer returns a new Server
func New(
	logger *log.Logger,
	port int16,
	snapshotCache cache.SnapshotCache,
	nodeIDCh chan<- string,
) *Server {
	return &Server{
		logger: logger.WithFields(log.Fields{
			"component": "server",
		}).Logger,
		port:          port,
		snapshotCache: snapshotCache,
		nodeIDCh:      nodeIDCh,
	}
}

// Run starts a go-control-plane, xds server in a background goroutine.
// The server is bounded by the provided context.
func (s *Server) Run(ctx context.Context) error {

	cbs := &callbacks{log: s.logger, nodeIDCh: s.nodeIDCh}

	srv := server.NewServer(ctx, s.snapshotCache, cbs)

	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions, grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams))
	grpcServer := grpc.NewServer(grpcOptions...)

	discoveryservice.RegisterAggregatedDiscoveryServiceServer(grpcServer, srv)
	endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, srv)

	go func() {
		<-ctx.Done()
		grpcServer.Stop()
		close(s.nodeIDCh)
	}()

	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	log.Infof("management server listening on %d\n", s.port)

	go func() {
		if err = grpcServer.Serve(listen); err != nil {
			log.WithError(err).Warn("gRPC server returned an error")
		}
	}()

	return nil
}
