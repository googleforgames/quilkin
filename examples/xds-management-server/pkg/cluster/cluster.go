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
