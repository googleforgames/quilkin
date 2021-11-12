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

package resources

import (
	"testing"

	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyendpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"quilkin.dev/xds-management-server/pkg/cluster"
	"quilkin.dev/xds-management-server/pkg/filterchain"
	"quilkin.dev/xds-management-server/pkg/filters"
	debugfilterv1alpha "quilkin.dev/xds-management-server/pkg/filters/debug/v1alpha1"
	ratelimitv1alpha "quilkin.dev/xds-management-server/pkg/filters/local_rate_limit/v1alpha1"
)

func TestMakeEndpoint(t *testing.T) {
	ep, err := makeEndpoint("cluster-a", []cluster.Endpoint{{
		IP:   "127.0.0.1",
		Port: 22,
		Metadata: map[string]interface{}{
			"key-1": map[string]interface{}{
				"key-1-a": "value-1",
			},
		},
	}})

	require.NoError(t, err)
	require.Len(t, ep.Endpoints, 1)
	require.Len(t, ep.Endpoints[0].LbEndpoints, 1)

	lbEndpoint := ep.Endpoints[0].LbEndpoints[0]
	endpoint := lbEndpoint.HostIdentifier.(*envoyendpoint.LbEndpoint_Endpoint)
	socketAddress := endpoint.Endpoint.Address.Address.(*envoycore.Address_SocketAddress).SocketAddress
	require.EqualValues(t, "127.0.0.1", socketAddress.Address)
	require.EqualValues(t, 22, socketAddress.PortSpecifier.(*envoycore.SocketAddress_PortValue).PortValue)

	md := lbEndpoint.Metadata.FilterMetadata
	require.Len(t, md, 1)
	value, found := md["key-1"]
	require.True(t, found)

	require.Len(t, value.Fields, 1)
	nestedValue, found := value.Fields["key-1-a"]
	require.True(t, found)

	require.EqualValues(t, "value-1", nestedValue.GetStringValue())
}

func TestMakeEndpointWithoutMetadata(t *testing.T) {
	ep, err := makeEndpoint("cluster-a", []cluster.Endpoint{{
		IP:   "127.0.0.1",
		Port: 22,
	}})

	require.NoError(t, err)
	require.Len(t, ep.Endpoints, 1)
	require.Len(t, ep.Endpoints[0].LbEndpoints, 1)

	lbEndpoint := ep.Endpoints[0].LbEndpoints[0]
	endpoint := lbEndpoint.HostIdentifier.(*envoyendpoint.LbEndpoint_Endpoint)
	socketAddress := endpoint.Endpoint.Address.Address.(*envoycore.Address_SocketAddress).SocketAddress
	require.EqualValues(t, "127.0.0.1", socketAddress.Address)
	require.EqualValues(t, 22, socketAddress.PortSpecifier.(*envoycore.SocketAddress_PortValue).PortValue)

	require.Len(t, lbEndpoint.Metadata.FilterMetadata, 0)
}

func TestMakeCluster(t *testing.T) {
	cs, err := makeCluster(cluster.Cluster{
		Name: "cluster-1",
		Endpoints: []cluster.Endpoint{{
			IP:   "127.0.0.1",
			Port: 22,
		}},
	})

	require.NoError(t, err)
	require.Len(t, cs.LoadAssignment.Endpoints, 1)

	require.EqualValues(t, "cluster-1", cs.Name)

	lbEndpoint := cs.LoadAssignment.Endpoints[0].LbEndpoints[0]
	endpoint := lbEndpoint.HostIdentifier.(*envoyendpoint.LbEndpoint_Endpoint)
	socketAddress := endpoint.Endpoint.Address.Address.(*envoycore.Address_SocketAddress).SocketAddress
	require.EqualValues(t, "127.0.0.1", socketAddress.Address)
	require.EqualValues(t, 22, socketAddress.PortSpecifier.(*envoycore.SocketAddress_PortValue).PortValue)
}

func TestGenerateSnapshot(t *testing.T) {
	clusters := []cluster.Cluster{
		{
			Name: "cluster-1",
			Endpoints: []cluster.Endpoint{{
				IP:   "127.0.0.1",
				Port: 22,
			}},
		},
		{
			Name: "cluster-2",
			Endpoints: []cluster.Endpoint{{
				IP:   "127.0.0.3",
				Port: 23,
			}},
		},
	}
	debugFilter, err := filterchain.CreateXdsFilter(filters.DebugFilterName,
		&debugfilterv1alpha.Debug{
			Id: &wrapperspb.StringValue{Value: "hello"},
		})
	require.NoError(t, err)
	rateLimitFilter, err := filterchain.CreateXdsFilter(filters.RateLimitFilterName,
		&ratelimitv1alpha.LocalRateLimit{
			MaxPackets: 400,
		})
	require.NoError(t, err)

	snapshot, err := GenerateSnapshot(19, clusters, filterchain.ProxyFilterChain{
		ProxyID: "proxy-1",
		FilterChain: &envoylistener.FilterChain{
			Filters: []*envoylistener.Filter{
				debugFilter, rateLimitFilter,
			},
		},
	})
	require.NoError(t, err)

	require.NoError(t, snapshot.Consistent())

	for _, rsc := range snapshot.Resources {
		require.EqualValues(t, "19", rsc.Version)
	}

	// Cluster
	clusterResource := snapshot.Resources[1]
	require.Len(t, clusterResource.Items, 2)

	cluster1, found := clusterResource.Items["cluster-1"]
	require.True(t, found, "cluster-1 is missing from map")
	cluster2, found := clusterResource.Items["cluster-2"]
	require.True(t, found, "cluster-2 is missing from map")

	require.Contains(t, cluster1.Resource.String(), "127.0.0.1")
	require.Contains(t, cluster2.Resource.String(), "127.0.0.3")

	// Listener
	listenerResource := snapshot.Resources[3]
	require.Len(t, listenerResource.Items, 1)

	filterChain, found := listenerResource.Items[""]
	require.True(t, found, "missing default filter chain")

	require.Contains(t, filterChain.Resource.String(), filters.DebugFilterName)
	require.Contains(t, filterChain.Resource.String(), "hello")

	require.Contains(t, filterChain.Resource.String(), filters.RateLimitFilterName)
	require.Contains(t, filterChain.Resource.String(), "max_packets:400")
}
