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

	"k8s.io/apimachinery/pkg/labels"

	agonesv1 "agones.dev/agones/pkg/apis/agones/v1"
	v1 "agones.dev/agones/pkg/client/listers/agones/v1"
	log "github.com/sirupsen/logrus"
	"quilkin.dev/xds-management-server/pkg/cluster"
)

// Provider implements the Provider interface, exposing Agones GameServers as endpoints.
type Provider struct {
	config   Config
	logger   *log.Logger
	gsLister v1.GameServerLister
}

// Config contains the Agones provider's configuration.
type Config struct {
	GameServersNamespace    string
	GameServersPollInterval time.Duration
}

// NewProvider returns a new Provider instance.
func NewProvider(logger *log.Logger, gsLister v1.GameServerLister, config Config) *Provider {
	return &Provider{
		logger:   logger,
		config:   config,
		gsLister: gsLister,
	}
}

// Run spawns a goroutine in the background that watches Agones GameServers
// and exposes them as endpoints via the returned Cluster channel.
func (p *Provider) Run(ctx context.Context) (<-chan []cluster.Cluster, error) {
	clusterCh := make(chan []cluster.Cluster)

	go runClusterWatch(
		ctx,
		p.logger,
		p.config.GameServersPollInterval,
		p.gsLister,
		clusterCh)

	return clusterCh, nil
}

func runClusterWatch(
	ctx context.Context,
	logger *log.Logger,
	gameServersPollInterval time.Duration,
	gsLister v1.GameServerLister,
	clusterCh chan<- []cluster.Cluster,
) {
	defer close(clusterCh)

	ticker := time.NewTicker(gameServersPollInterval)
	defer ticker.Stop()

	prevEndpoints := map[string]cluster.Endpoint{}
	for {
		select {
		case <-ticker.C:
			currEndpoints := getEndpointsFromStore(logger, gsLister)
			if reflect.DeepEqual(currEndpoints, prevEndpoints) {
				continue
			}
			prevEndpoints = currEndpoints

			endpoints := make([]cluster.Endpoint, 0, len(currEndpoints))
			for _, ep := range currEndpoints {
				endpoints = append(endpoints, ep)
			}
			clusterCh <- []cluster.Cluster{{
				Name:      "default-quilkin-cluster",
				Endpoints: endpoints,
			}}
		case <-ctx.Done():
			logger.Debug("Exiting cluster watch loop: context cancelled")
		}
	}
}

func getEndpointsFromStore(
	logger *log.Logger,
	gsLister v1.GameServerLister,
) map[string]cluster.Endpoint {
	endpoints := make(map[string]cluster.Endpoint)

	gameServers, err := gsLister.List(labels.Everything())
	if err != nil {
		log.WithError(err).Warn("failed to list game servers")
		return endpoints
	}

	for _, gs := range gameServers {
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

		gsPort := int(getGameServerPort(gsLogger, gs.Status.Ports))
		endpoints[fmt.Sprintf("%s:%d", gs.Status.Address, gsPort)] = cluster.Endpoint{
			IP:       gs.Status.Address,
			Port:     gsPort,
			Metadata: metadata,
		}
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
