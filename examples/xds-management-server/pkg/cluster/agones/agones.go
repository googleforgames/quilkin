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

package agones

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	agonesv1 "agones.dev/agones/pkg/apis/agones/v1"
	"agones.dev/agones/pkg/client/informers/externalversions"

	agones "agones.dev/agones/pkg/client/clientset/versioned"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"quilkin.dev/xds-management-server/pkg/cluster"
)

// Provider implements the Provider interface, exposing Agones GameServers as endpoints.
type Provider struct {
	config       Config
	logger       *log.Logger
	agonesClient agones.Interface
}

// Config contains the Agones provider's configuration.
type Config struct {
	K8sConfig               *rest.Config
	GameServersNamespace    string
	GameServersPollInterval time.Duration
}

// NewProvider returns a new Provider instance.
func NewProvider(logger *log.Logger, config Config) (*Provider, error) {
	agonesClient, err := agones.NewForConfig(config.K8sConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Agones clientset")
	}

	return &Provider{
		agonesClient: agonesClient,
		logger:       logger,
		config:       config,
	}, nil
}

// Run spawns a goroutine in the background that watches Agones GameServers
// and exposes them as endpoints via the returned Cluster channel.
func (p *Provider) Run(ctx context.Context) (<-chan []cluster.Cluster, error) {
	informerFactory := externalversions.NewSharedInformerFactoryWithOptions(
		p.agonesClient,
		0,
		externalversions.WithNamespace(p.config.GameServersNamespace))
	gameServerInformer := informerFactory.Agones().V1().GameServers().Informer()
	gameServerStore := gameServerInformer.GetStore()
	go gameServerInformer.Run(ctx.Done())

	clusterCh := make(chan []cluster.Cluster)

	go runClusterWatch(
		ctx,
		p.logger,
		p.config.GameServersPollInterval,
		gameServerStore,
		clusterCh)

	return clusterCh, nil
}

func runClusterWatch(
	ctx context.Context,
	logger *log.Logger,
	gameServersPollInterval time.Duration,
	gameServerStore cache.Store,
	clusterCh chan<- []cluster.Cluster,
) {
	defer close(clusterCh)

	ticker := time.NewTicker(gameServersPollInterval)
	defer ticker.Stop()

	var prevEndpoints []cluster.Endpoint
	for {
		select {
		case <-ticker.C:
			currEndpoints := getEndpointsFromStore(logger, gameServerStore)
			if reflect.DeepEqual(currEndpoints, prevEndpoints) {
				continue
			}
			prevEndpoints = currEndpoints

			clusterCh <- []cluster.Cluster{{
				Name:      "default-quilkin-cluster",
				Endpoints: currEndpoints,
			}}
		case <-ctx.Done():
			logger.Debug("Exiting cluster watch loop: context cancelled")

		}
	}
}

func getEndpointsFromStore(
	logger *log.Logger,
	gameServerStore cache.Store,
) []cluster.Endpoint {
	gameServers := gameServerStore.List()

	var endpoints []cluster.Endpoint
	for i := range gameServers {
		gs := gameServers[i].(*agonesv1.GameServer)

		gsLogger := logger.WithFields(log.Fields{
			"gameserver": gs.Name,
		})

		if gs.Status.State != agonesv1.GameServerStateAllocated {
			continue
		}

		if gs.Status.Address == "" {
			continue
		}

		numPorts := len(gs.Status.Ports)
		if numPorts == 0 {
			continue
		}

		var metadata map[string]interface{}
		tokenStr, found := gs.Annotations["quilkin.dev/tokens"]
		if found {
			metadata = map[string]interface{}{
				"quilkin.dev": map[string]interface{}{
					"tokens": strings.Split(tokenStr, ","),
				},
			}
		}

		endpoints = append(endpoints, cluster.Endpoint{
			IP:       gs.Status.Address,
			Port:     int(getGameServerPort(gsLogger, gs.Status.Ports)),
			Metadata: metadata,
		})
	}

	return endpoints
}

func getGameServerPort(logger *log.Entry, ports []agonesv1.GameServerStatusPort) int32 {
	if len(ports) == 0 {
		return 0
	}

	if len(ports) == 1 {
		return ports[0].Port
	}

	for _, port := range ports {
		if port.Name == "default" {
			return port.Port
		}
	}

	logger.Warnf("found %d ports: will pick the first one %v", len(ports), ports[0])
	return ports[0].Port
}
