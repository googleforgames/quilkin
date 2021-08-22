package main

import (
	"context"
	"os"
	"os/signal"
	"time"

	"github.com/alecthomas/kong"
	log "github.com/sirupsen/logrus"

	"quilkin.dev/xds-management-server/pkg/providers"
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

	provider := providers.NewFileProvider(flags.Config)
	resourcesCh, providerErrorCh := provider.Run(ctx, logger)

	nodeIDCh := make(chan string, 1000)
	snapshotCache := snapshot.RunSnapshotUpdater(
		ctx,
		logger,
		nodeIDCh,
		resourcesCh,
		100*time.Millisecond)

	if err := server.Run(ctx, logger, flags.Port, snapshotCache, nodeIDCh); err != nil {
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
