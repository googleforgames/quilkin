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

package cluster

import (
	"context"
)

// Endpoint represents an upstream endpoint (e.g a game-server)
type Endpoint struct {
	// IP is the endpoint's IP address
	IP string
	// Port is the endpoint's port
	Port int
	// Metadata contains any endpoint metadata
	Metadata map[string]interface{}
}

// Cluster represents a cluster of endpoints. It maps to an xds Cluster.
type Cluster struct {
	// Name is the cluster's name
	Name string
	// Endpoints contains the endpoints belonging to the cluster
	Endpoints []Endpoint
}

// Provider is an abstraction over the source of clusters like
// Agones, Kubernetes or other compute providers.
type Provider interface {
	// Run returns a channel that the server reads cluster updates from.
	Run(ctx context.Context) (<-chan []Cluster, error)
}
