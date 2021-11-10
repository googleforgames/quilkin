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
