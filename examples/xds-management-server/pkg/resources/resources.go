package resources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"strconv"

	envoycluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyendpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/golang/protobuf/jsonpb"
	structpb "github.com/golang/protobuf/ptypes/struct"

	quilkinfilter "quilkin.dev/xds-management-server/filters/debug/v1alpha1"
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

// FilterConfig represents a filter's config
type FilterConfig struct {
	Name string
	Config interface{}
}

// Resources represents an xds resource.
type Resources struct {
	Clusters map[string]Cluster
	FilterChain []FilterConfig
}

type debugFilterConfig struct {
	Id string
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

	for _, resource := range filterChainResource {
		switch resource.Name {
		case "quilkin.extensions.filters.debug.v1alpha1.Debug":
			configBytes, err := json.Marshal(resource.Config)
			if err != nil {
				return nil, fmt.Errorf("failed to JSON marshal filter config: %w", err)
			}
			var filterConfig debugFilterConfig
			if err := json.Unmarshal(configBytes, &filterConfig); err != nil {
				return nil, fmt.Errorf("failed to JSON unmarshal filter config: %w", err)
			}
			protoConfig, err := ptypes.MarshalAny(&quilkinfilter.Debug{
				Id: &wrapperspb.StringValue{Value: filterConfig.Id},
			})
			if err != nil {
				return nil, fmt.Errorf("failed to proto marshal filter config: %w", err)
			}
			filter := &envoylistener.Filter{
				Name: resource.Name,
				ConfigType:&envoylistener.Filter_TypedConfig{
					TypedConfig: protoConfig,
				},
			}
			filters = append(filters, filter)
		default:
			return nil, fmt.Errorf("invalid or unsupported filter: %s", resource.Name)
		}
	}

	return &envoylistener.FilterChain{
		Filters: filters,
	}, nil
}
