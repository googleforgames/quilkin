package filters

// Import all filters we know of so that they're registered and
// available at runtime during (un)marshaling
import (
	//nolint:revive
	_ "quilkin.dev/xds-management-server/pkg/filters/capture_bytes/v1alpha1"
	_ "quilkin.dev/xds-management-server/pkg/filters/compress/v1alpha1"
	_ "quilkin.dev/xds-management-server/pkg/filters/concatenate_bytes/v1alpha1"
	_ "quilkin.dev/xds-management-server/pkg/filters/debug/v1alpha1"
	_ "quilkin.dev/xds-management-server/pkg/filters/load_balancer/v1alpha1"
	_ "quilkin.dev/xds-management-server/pkg/filters/local_rate_limit/v1alpha1"
)

const (
	// These following filters are referenced directly throughout the repository.
	//
	// DebugFilterName is the name of the Debug filter
	DebugFilterName = "quilkin.extensions.filters.debug.v1alpha1.Debug"
	// RateLimitFilterName is the name of the RateLimit filter
	RateLimitFilterName = "quilkin.extensions.filters.local_rate_limit.v1alpha1.LocalRateLimit"
)
