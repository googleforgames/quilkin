package resources

import (
	"encoding/json"
	"fmt"
	"quilkin.dev/xds-management-server/pkg/cluster"
	"quilkin.dev/xds-management-server/pkg/filterchain"
	"strconv"

	envoycluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyendpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"google.golang.org/protobuf/encoding/protojson"

	// Import proto packages for proto registration side effects
	_ "quilkin.dev/xds-management-server/pkg/filters"
)

func GenerateSnapshot(version int64, clusters []cluster.Cluster, filterChain filterchain.ProxyFilterChain) (cache.Snapshot, error) {
	var clusterResources []types.Resource
	for _, cl := range clusters {
		clusterResource, err := makeCluster(cl)
		if err != nil {
			return cache.Snapshot{}, fmt.Errorf("failed to generate cluster resources: %w", err)
		}
		clusterResources = append(clusterResources, clusterResource)
	}

	listener := &envoylistener.Listener{
		FilterChains: []*envoylistener.FilterChain{filterChain.FilterChain},
	}

	snapshot := cache.NewSnapshot(
		strconv.FormatInt(version, 10),
		[]types.Resource{}, // endpoints
		clusterResources,
		[]types.Resource{},         // routes
		[]types.Resource{listener}, // listeners
		[]types.Resource{},         // runtimes
		[]types.Resource{},         // secrets
	)

	if err := snapshot.Consistent(); err != nil {
		return cache.Snapshot{}, err
	}

	return snapshot, nil
}

func makeCluster(cl cluster.Cluster) (*envoycluster.Cluster, error) {
	loadAssignment, err := makeEndpoint(cl.Name, cl.Endpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster resource: %w", err)
	}

	return &envoycluster.Cluster{
		Name: cl.Name,
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
		if err := protojson.Unmarshal(metadataBytes, &protoValue); err != nil {
			return nil, err
		}
		output[key] = &protoValue
	}
	return output, nil
}

func makeEndpoint(
	clusterName string,
	endpoints []cluster.Endpoint,
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
