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

package main

import (
	"context"
	"os"
	"os/signal"
	"time"

	"k8s.io/apimachinery/pkg/util/clock"

	"quilkin.dev/xds-management-server/pkg/providers"

	"github.com/alecthomas/kong"
	log "github.com/sirupsen/logrus"

	"quilkin.dev/xds-management-server/pkg/server"
	"quilkin.dev/xds-management-server/pkg/snapshot"
)

type flags struct {
	Config string `name:"config" help:"Resource config file path." type:"path" default:"config.yaml"`
	Port   int16  `name:"port" help:"Server listening port." default:"18000"`
}

func main() {
	var flags flags
	kong.Parse(&flags)

	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.DebugLevel)
	logger.SetFormatter(&log.JSONFormatter{})

	ctx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	proxyIDCh := make(chan string, 10)

	provider := providers.NewFileProvider(flags.Config, proxyIDCh)
	clusterCh, filterChainCh, providerErrorCh := provider.Run(ctx, logger)

	snapshotUpdater := snapshot.NewUpdater(
		logger,
		clusterCh,
		filterChainCh,
		100*time.Millisecond,
		clock.RealClock{})
	snapshotCache := snapshotUpdater.GetSnapshotCache()
	go snapshotUpdater.Run(ctx)

	srv := server.New(logger, flags.Port, snapshotCache, proxyIDCh)
	if err := srv.Run(ctx); err != nil {
		logger.WithError(err).Fatal("failed to start server")
	}

	go func() {
		defer shutdown()

		if err := <-providerErrorCh; err != nil {
			logger.WithError(err).Error("provider encountered an error")
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	select {
	case <-c:
		logger.Info("Received shutdown signal. Shutting down.")
		shutdown()
	case <-ctx.Done():
		logger.Info("Shutdown.")
	}

}
