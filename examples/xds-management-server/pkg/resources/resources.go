package resources

import (
	"bytes"
	"encoding/json"
	"fmt"
	gogojsonpb "github.com/gogo/protobuf/jsonpb"
	"strconv"

	envoycluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyendpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	prototypes "github.com/gogo/protobuf/types"
	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"
)

// Endpoint represents an xds endpoint
type Endpoint struct {
	IP       string
	Port     int
	Metadata map[string]interface{}
}

// Cluster represents an xds cluster
type Cluster struct {
	Endpoints []Endpoint
}

// FilterConfig represents a filter's config.
type FilterConfig interface {}

// Resources represents an xds resource.
type Resources struct {
	Clusters map[string]Cluster
	FilterChain []FilterConfig
}

func GenerateSnapshot(version int64, resources Resources) (cache.Snapshot, error) {
	var clusterResources []types.Resource
	for clusterName, cluster := range resources.Clusters {
		clusterResource, err := makeCluster(clusterName, cluster)
		if err != nil {
			return cache.Snapshot{}, fmt.Errorf("failed to generate cluster resources: %w", err)
		}
		clusterResources = append(clusterResources, clusterResource)
	}

	listener, err  := makeListener(resources.FilterChain)
	if err != nil {
		return cache.Snapshot{}, fmt.Errorf("failed to generate filterchain resource: %w", err)
	}

	return cache.NewSnapshot(
		strconv.FormatInt(version, 10),
		[]types.Resource{}, // endpoints
		clusterResources,
		[]types.Resource{}, // routes
		[]types.Resource{listener}, // listeners
		[]types.Resource{}, // runtimes
		[]types.Resource{}, // secrets
	), nil
}

func makeCluster(clusterName string, cluster Cluster) (*envoycluster.Cluster, error) {
	loadAssignment, err := makeEndpoint(clusterName, cluster.Endpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster resource: %w", err)
	}

	return &envoycluster.Cluster{
		Name: clusterName,
		ClusterDiscoveryType: &envoycluster.Cluster_Type{
			Type: envoycluster.Cluster_STATIC,
		},
		LoadAssignment: loadAssignment,
	}, nil
}

func parseMetadata(input map[string]interface{}) (map[string]*structpb.Struct, error) {
	output := make(map[string]*structpb.Struct)
	for key, value := range input {
		metadataBytes, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse metadata: %w", err)
		}

		protoValue := structpb.Struct{}
		if err := jsonpb.Unmarshal(bytes.NewReader(metadataBytes), &protoValue); err != nil {
			return nil, err
		}
		output[key] = &protoValue
	}
	return output, nil
}

func makeEndpoint(
	clusterName string,
	endpoints []Endpoint,
) (*envoyendpoint.ClusterLoadAssignment, error) {
	var endpointConfigs []*envoyendpoint.LocalityLbEndpoints
	for _, ep := range endpoints {
		metadata, err := parseMetadata(ep.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to create Endpoint resource: %w", err)
		}
		endpointConfigs = append(endpointConfigs, &envoyendpoint.LocalityLbEndpoints{
			LbEndpoints: []*envoyendpoint.LbEndpoint{{
				Metadata: &envoycore.Metadata{
					FilterMetadata: metadata,
				},
				HostIdentifier: &envoyendpoint.LbEndpoint_Endpoint{
					Endpoint: &envoyendpoint.Endpoint{
						Address: &envoycore.Address{
							Address: &envoycore.Address_SocketAddress{
								SocketAddress: &envoycore.SocketAddress{
									Protocol: envoycore.SocketAddress_UDP,
									Address:  ep.IP,
									PortSpecifier: &envoycore.SocketAddress_PortValue{
										PortValue: uint32(ep.Port),
									},
								},
							},
						},
					},
				},
			}},
		})
	}

	return &envoyendpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints:   endpointConfigs,
	}, nil
}

func makeListener(
	filterChainResource []FilterConfig,
) (*envoylistener.Listener, error) {
	filterChain, err := makeFilterChain(filterChainResource)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener resource: %w", err)
	}

	return &envoylistener.Listener{
		FilterChains: []*envoylistener.FilterChain{ filterChain },
	}, nil
}

func makeFilterChain(
	filterChainResource []FilterConfig,
) (*envoylistener.FilterChain, error) {
	var filters []*envoylistener.Filter

	for _, config := range filterChainResource {
		configBytes, err := json.Marshal(config)
		if err != nil {
			return nil, fmt.Errorf("failed to JSON marshal filter config: %w", err)
		}

		pbs := &prototypes.Struct{}
		if err := gogojsonpb.Unmarshal(bytes.NewReader(configBytes), pbs); err != nil {
			return nil, fmt.Errorf("failed to Unmarshal filter config into protobuf Struct: %w", err)
		}

		buf := &bytes.Buffer{}
		if err := (&gogojsonpb.Marshaler{OrigName: true}).Marshal(buf, pbs); err != nil {
			return nil, fmt.Errorf("failed to marshal filter config protobuf into json: %w", err)
		}

		filter := &envoylistener.Filter{}
		if err := (&jsonpb.Unmarshaler{AllowUnknownFields: false}).Unmarshal(buf, filter); err != nil {
			return nil, fmt.Errorf("failed to unmarshal filter config jsonpb into envoy filter proto: %w", err)
		}

		filters = append(filters, filter)
	}

	return &envoylistener.FilterChain{
		Filters: filters,
	}, nil
}
