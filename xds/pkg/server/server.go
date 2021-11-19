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
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"

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

// HealthCheck implements the health check logic exposed by the server.
// It is implemented by internal components of the server and returns
// an error if the component is unhealthy.
type HealthCheck func(ctx context.Context) error

// Server is a wrapper around go-control-plane's xds server.
type Server struct {
	logger *log.Logger
	// xdsPort is the port the XDS server runs on.
	xdsPort int16
	// snapshotCache is passed updated by us and read by go-control-plane
	// to provided proxies with config from.
	snapshotCache cache.SnapshotCache
	// nodeIDCh is nilable. It is used as a callback mechanism from go-control-plane's server to
	// let us know when a new proxy has connected. The proxy's ID is passed on the channel.
	nodeIDCh chan<- string
	// healthChecks contains the server's health check implementations.
	healthChecks []HealthCheck
	// adminPort is the port the admin server runs on.
	adminPort int16
}

// New returns a new Server
func New(
	logger *log.Logger,
	xdsPort int16,
	snapshotCache cache.SnapshotCache,
	nodeIDCh chan<- string,
	healthChecks []HealthCheck,
	adminPort int16,
) *Server {
	return &Server{
		logger: logger.WithFields(log.Fields{
			"component": "server",
		}).Logger,
		xdsPort:       xdsPort,
		snapshotCache: snapshotCache,
		nodeIDCh:      nodeIDCh,
		healthChecks:  healthChecks,
		adminPort:     adminPort,
	}
}

func (s *Server) startAdminServer(ctx context.Context) {
	address := fmt.Sprintf(":%d", s.adminPort)

	srv := &http.Server{Addr: address}

	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		statusMessage := "OK"
		statusCode := http.StatusOK

		checksErrorGroup, ctx := errgroup.WithContext(r.Context())
		for i := range s.healthChecks {
			check := s.healthChecks[i]
			checksErrorGroup.Go(func() error {
				return check(ctx)
			})
		}

		if err := checksErrorGroup.Wait(); err != nil {
			statusCode = http.StatusInternalServerError
			statusMessage = err.Error()
		}

		w.WriteHeader(statusCode)
		_, writeErr := w.Write([]byte(statusMessage))
		if writeErr != nil {
			s.logger.WithError(writeErr).Warn("Failed to write /healthz response")
		}
	})

	go func() {
		s.logger.Infof("starting admin server on %s", address)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			s.logger.WithError(err).Warn("Admin server shutdown prematurely")
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			s.logger.WithError(err).Warn("Admin server did not shut down properly")
		}
	}()
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

	s.startAdminServer(ctx)

	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", s.xdsPort))
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	log.Infof("management server listening on %d\n", s.xdsPort)

	go func() {
		if err = grpcServer.Serve(listen); err != nil {
			log.WithError(err).Warn("gRPC server returned an error")
		}
	}()

	return nil
}
