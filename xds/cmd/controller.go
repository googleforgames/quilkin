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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"quilkin.dev/xds-management-server/pkg/cluster"
	"quilkin.dev/xds-management-server/pkg/filterchain"

	agones "agones.dev/agones/pkg/client/clientset/versioned"

	"k8s.io/apimachinery/pkg/util/clock"

	"agones.dev/agones/pkg/client/informers/externalversions"
	agonescluster "quilkin.dev/xds-management-server/pkg/cluster/agones"
	k8sfilterchain "quilkin.dev/xds-management-server/pkg/filterchain/k8s"
	"quilkin.dev/xds-management-server/pkg/k8s"

	"github.com/alecthomas/kong"
	log "github.com/sirupsen/logrus"

	"quilkin.dev/xds-management-server/pkg/server"
	"quilkin.dev/xds-management-server/pkg/snapshot"
)

type flags struct {
	Port                    int16         `name:"port" help:"Server listening port." default:"18000"`
	ProxyNamespace          string        `name:"proxy-namespace" help:"Namespace under which the proxies run." default:"quilkin"`
	GameServersNamespace    string        `name:"game-server-namespace" help:"Namespace under which the game-servers run." default:"gameservers"`
	GameServersPollInterval time.Duration `name:"game-server-poll-interval" help:"How long to wait in-between checking for game-server updates." default:"1s"`
	ProxyPollInterval       time.Duration `name:"proxy-interval" help:"How long to wait in-between checking for proxy updates." default:"1s"`
}

func createAgonesClusterProvider(
	ctx context.Context,
	logger *log.Logger,
	k8sConfig *rest.Config,
	flags *flags,
) cluster.Provider {
	agonesClient, err := agones.NewForConfig(k8sConfig)
	if err != nil {
		log.WithError(err).Fatal("failed to create Agones clientset")
	}

	informerFactory := externalversions.NewSharedInformerFactoryWithOptions(
		agonesClient,
		0,
		externalversions.WithNamespace(flags.GameServersNamespace))

	gameServerLister := informerFactory.Agones().V1().GameServers().Lister()

	informerFactory.Start(ctx.Done())

	return agonescluster.NewProvider(logger, gameServerLister, agonescluster.Config{
		GameServersNamespace:    flags.GameServersNamespace,
		GameServersPollInterval: flags.GameServersPollInterval,
	})
}

func createFilterChainProvider(
	ctx context.Context,
	logger *log.Logger,
	k8sClient *kubernetes.Clientset,
	flags *flags,
) filterchain.Provider {

	informerFactory := informers.NewSharedInformerFactoryWithOptions(
		k8sClient,
		0,
		informers.WithNamespace(flags.ProxyNamespace),
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = k8sfilterchain.LabelSelectorProxyRole
		}),
	)

	podLister := informerFactory.Core().V1().Pods().Lister()

	informerFactory.Start(ctx.Done())

	return k8sfilterchain.NewProvider(
		logger,
		clock.RealClock{},
		podLister,
		flags.ProxyPollInterval)
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

	k8sConfig, err := k8s.GetK8sConfig()
	if err != nil {
		log.WithError(err).Fatal("failed to get kube config")
	}

	k8sClient, err := k8s.CreateClient(k8sConfig)
	if err != nil {
		log.WithError(err).Fatal("failed to create k8s client")
	}
	clusterProvider := createAgonesClusterProvider(ctx, logger, k8sConfig, &flags)
	clusterCh, err := clusterProvider.Run(ctx)
	if err != nil {
		log.WithError(err).Fatal("failed to create start cluster provider")
	}

	filterChainProvider := createFilterChainProvider(ctx, logger, k8sClient, &flags)
	filterChainCh := filterChainProvider.Run(ctx)

	snapshotUpdater := snapshot.NewUpdater(
		logger,
		clusterCh,
		filterChainCh,
		100*time.Millisecond,
		clock.RealClock{})
	snapshotCache := snapshotUpdater.GetSnapshotCache()
	go snapshotUpdater.Run(ctx)

	srv := server.New(logger, flags.Port, snapshotCache, nil)
	if err := srv.Run(ctx); err != nil {
		logger.WithError(err).Fatal("failed to start server")
	}

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
