package filterchain

import (
	"context"
	"fmt"

	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// ProxyFilterChain represents a filter chain for a specific proxy.
type ProxyFilterChain struct {
	// ProxyID is the ID of the associated proxy.
	// this is the same as the XDS node id provided by the proxy
	// when it first connects.
	ProxyID string
	// FilterChain is the filter chain for the associated proxy.
	FilterChain *envoylistener.FilterChain
}

// Provider is an abstraction over the source of filter chains.
type Provider interface {
	// Run returns a channel that the server reads filter chain
	// updates from.
	Run(ctx context.Context) <-chan ProxyFilterChain
}

// CreateXdsFilter creates an xds filter with the provided proto.
func CreateXdsFilter(name string, filter proto.Message) (*envoylistener.Filter, error) {
	filterProto, err := anypb.New(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s filter to protobuf: %w", name, err)
	}

	return &envoylistener.Filter{
		Name: name,
		ConfigType: &envoylistener.Filter_TypedConfig{
			TypedConfig: filterProto,
		},
	}, nil
}
