package config

import (
    "testing"
	"github.com/stretchr/testify/require"
    "google.golang.org/protobuf/proto"
	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
    debug "quilkin.dev/xds-management-server/pkg/filters/debug/v1alpha1"
    wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

func TestConfigSerde(t *testing.T) {
    raw := `{
        "clusters": [],
        "filters": [{
            "name": "debug-layer",
            "typed_config": {
                "@type": "quilkin.dev/quilkin.extensions.filters.debug.v1alpha1.Debug",
                "id": "hello"
            }
        }],
    }`
    unmarshaled := map[string]interface{}{
        "clusters": []interface{}{},
        "filters": []map[string]interface{} {
            {
                "name": "debug-layer",
                "typed_config": map[string]interface{} {
                    "@type": "quilkin.dev/quilkin.extensions.filters.debug.v1alpha1.Debug",
                    "id": "hello",
                },
            },
        },
    }

    config, err := FromJsonString(raw)
    require.Nil(t, err)
    require.Equal(t, config, unmarshaled)

    bytes, err := proto.Marshal(config.FilterChain.Filters[0])
    require.Nil(t, err)

    var decoded envoylistener.Filter
    err = proto.Unmarshal(bytes, &decoded)
    require.Nil(t, err)

    debugMessage := new(debug.Debug)
    err = decoded.GetTypedConfig().UnmarshalTo(debugMessage)
    require.Nil(t, err)

    require.Equal(t, debugMessage, debug.Debug {
        Id: &wrapperspb.StringValue{ Value: "hello", },
    })
}
