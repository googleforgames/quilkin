package main

import (
	"context"
	"os"
	"os/signal"
	"quilkin.dev/xds-management-server/pkg/providers"
	"time"

	"github.com/alecthomas/kong"
	log "github.com/sirupsen/logrus"

	"quilkin.dev/xds-management-server/pkg/server"
	"quilkin.dev/xds-management-server/pkg/snapshot"
)

type flags struct {
	Config string `name:"config" help:"Resource config file path." type:"path" default:"config.yaml"`
	Port   int16  `name:"int16" help:"Server listening port." default:"18000"`
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

	snapshotCache := snapshot.RunSnapshotUpdater(
		ctx,
		logger,
		clusterCh,
		filterChainCh,
		100*time.Millisecond)

	if err := server.Run(ctx, logger, flags.Port, snapshotCache, proxyIDCh); err != nil {
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
