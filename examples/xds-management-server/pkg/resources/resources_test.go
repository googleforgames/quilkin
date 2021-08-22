package resources

import (
	"encoding/json"
	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyendpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
	"testing"
)

type filterConfig struct {
	Name        string                 `json:"name"`
	TypedConfig map[string]interface{} `json:"typed_config"`
}

func TestMakeEndpoint(t *testing.T) {
	ep, err := makeEndpoint("cluster-a", []Endpoint{{
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
	ep, err := makeEndpoint("cluster-a", []Endpoint{{
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
	cluster, err := makeCluster(Cluster{
		Name: "cluster-1",
		Endpoints: []Endpoint{{
			IP:   "127.0.0.1",
			Port: 22,
		}},
	})

	require.NoError(t, err)
	require.Len(t, cluster.LoadAssignment.Endpoints, 1)

	require.EqualValues(t, "cluster-1", cluster.Name)

	lbEndpoint := cluster.LoadAssignment.Endpoints[0].LbEndpoints[0]
	endpoint := lbEndpoint.HostIdentifier.(*envoyendpoint.LbEndpoint_Endpoint)
	socketAddress := endpoint.Endpoint.Address.Address.(*envoycore.Address_SocketAddress).SocketAddress
	require.EqualValues(t, "127.0.0.1", socketAddress.Address)
	require.EqualValues(t, 22, socketAddress.PortSpecifier.(*envoycore.SocketAddress_PortValue).PortValue)
}

func TestMakeFilterChain(t *testing.T) {
	dbgFilter := `
name: my-filter-1
typed_config:
  '@type': quilkin.extensions.filters.debug.v1alpha1.Debug
  id: hello
`
	rateLimitFilter := `
name: my-filter-2
typed_config:
  '@type': quilkin.extensions.filters.local_rate_limit.v1alpha1.LocalRateLimit
  max_packets: 400
  period: 1s
`
	filterConfigs := makeTestFilterConfig(t, []string{dbgFilter, rateLimitFilter})

	got, err := makeFilterChain(filterConfigs)
	require.NoError(t, err)

	require.EqualValues(t, "", got.Name)
	require.Len(t, got.Filters, 2)

	require.EqualValues(t, "my-filter-1", got.Filters[0].Name)
	require.EqualValues(t, "my-filter-2", got.Filters[1].Name)

	require.Contains(t, got.Filters[0].String(), "id:{value:\"hello\"}")
	require.Contains(t, got.Filters[1].String(), "max_packets:400")
}

func TestMakeFilterChainInvalid(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "invalid filter config",
			config: `
name: my-filter-1
typed_config:
  '@type': quilkin.extensions.filters.debug.v1alpha1.Debug
  notExists: hello
`,
		},
		{
			name: "missing proto",
			config: `
name: my-filter-1
typed_config:
  '@type': quilkin.extensions.filters.debug.v1alpha1.Debug2
  id: hello
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := makeFilterChain(makeTestFilterConfig(t, []string{tt.config}))
			require.Error(t, err)
		})
	}
}

func makeTestFilterConfig(t *testing.T, configs []string) []FilterConfig {
	var filterConfigs []FilterConfig

	for _, config := range configs {
		jsonBytes, err := yaml.YAMLToJSON([]byte(config))
		require.NoError(t, err, "failed to convert filter config from yaml to json")

		fc := &filterConfig{}
		require.NoError(t, json.Unmarshal(jsonBytes, fc), "failed to unmarshal test data filter config")

		filterConfigs = append(filterConfigs, fc)
	}

	return filterConfigs
}

func TestMakeListener(t *testing.T) {
	dbgFilter := `
name: my-filter-1
typed_config:
  '@type': quilkin.extensions.filters.debug.v1alpha1.Debug
  id: hello
`
	listener, err := makeListener(makeTestFilterConfig(t, []string{dbgFilter}))
	require.NoError(t, err)

	require.EqualValues(t, "", listener.Name)
	require.Len(t, listener.FilterChains, 1)

	filterChain := listener.FilterChains[0]
	require.EqualValues(t, "", filterChain.Name)

	require.Len(t, filterChain.Filters, 1)
	filter := filterChain.Filters[0]
	require.EqualValues(t, "my-filter-1", filter.Name)
	require.Contains(t, filter.String(), "id:{value:\"hello\"}")
}

func TestGenerateSnapshot(t *testing.T) {
	resources := Resources{
		Clusters: []Cluster{
			{
				Name: "cluster-1",
				Endpoints: []Endpoint{{
					IP:   "127.0.0.1",
					Port: 22,
				}},
			},
			{
				Name: "cluster-2",
				Endpoints: []Endpoint{{
					IP:   "127.0.0.3",
					Port: 23,
				}},
			},
		},
		FilterChain: makeTestFilterConfig(t, []string{`
name: my-filter-1
typed_config:
  '@type': quilkin.extensions.filters.debug.v1alpha1.Debug
  id: hello
`,
			`
name: my-filter-2
typed_config:
  '@type': quilkin.extensions.filters.local_rate_limit.v1alpha1.LocalRateLimit
  max_packets: 400
  period: 1s
`,
		}),
	}

	snapshot, err := GenerateSnapshot(19, resources)
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

	require.Contains(t, filterChain.Resource.String(), "my-filter-1")
	require.Contains(t, filterChain.Resource.String(), "my-filter-2")
}
