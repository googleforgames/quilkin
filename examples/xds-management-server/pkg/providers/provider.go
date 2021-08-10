package providers

import (
	"context"

	"quilkin.dev/xds-management-server/pkg/resources"
)

// Provider finds and returns resources.
type Provider interface {
	Run(ctx context.Context) (<-chan resources.Resources, <-chan error)
}
