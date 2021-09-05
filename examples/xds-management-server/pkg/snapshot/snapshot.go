package snapshot

import (
	"context"
	"time"

	"quilkin.dev/xds-management-server/pkg/cluster"
	"quilkin.dev/xds-management-server/pkg/filterchain"

	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/clock"

	"quilkin.dev/xds-management-server/pkg/resources"
)

// Updater periodically generates xds config snapshots from resources
// and updates a snapshot cache with the latest snapshot for each connected
// node.
type Updater struct {
	logger         *log.Logger
	clusterCh      <-chan []cluster.Cluster
	filterChainCh  <-chan filterchain.ProxyFilterChain
	updateInterval time.Duration
	clock          clock.Clock
	snapshotCache  cache.SnapshotCache
}

// NewUpdater returns a new Updater.
func NewUpdater(
	logger *log.Logger,
	clusterCh <-chan []cluster.Cluster,
	filterChainCh <-chan filterchain.ProxyFilterChain,
	updateInterval time.Duration,
	clock clock.Clock,
) *Updater {
	logger = logger.WithFields(log.Fields{
		"component": "SnapshotUpdater",
	}).Logger
	return &Updater{
		logger:         logger,
		clusterCh:      clusterCh,
		filterChainCh:  filterChainCh,
		snapshotCache:  cache.NewSnapshotCache(false, cache.IDHash{}, logger),
		updateInterval: updateInterval,
		clock:          clock,
	}
}

// GetSnapshotCache returns the backing snapshot cache.
func (u *Updater) GetSnapshotCache() cache.SnapshotCache {
	return u.snapshotCache
}

// Run starts a goroutine that listens for resource updates,
// uses the updates to generate an xds config snapshot and updates the snapshot from the provided channel and generates xds config snapshots.
// cache with the latest snapshot for each connected node.

// Run runs a loop that periodically checks if there are any
// cluster/filter-chain updates and if so creates a snapshot for
// affected proxies in the snapshot cache.
func (u *Updater) Run(ctx context.Context) {
	updateTicker := u.clock.NewTicker(u.updateInterval)
	defer updateTicker.Stop()

	currentSnapshotVersion := int64(0)

	type proxyStatus struct {
		hasPendingFilterChainUpdate bool
		filterChain                 filterchain.ProxyFilterChain
	}
	proxyStatuses := make(map[string]proxyStatus)

	var pendingClusterUpdate bool
	var clusterUpdate []cluster.Cluster

	// TODO: Implement cleanup of stale nodes in the snapshot Cache
	//   (If we have no open watchers for a node we can forget it?).
	for {
		select {
		case <-ctx.Done():
			u.logger.Infof("Exiting snapshot updater loop: Context cancelled")
			return
		case filterChain := <-u.filterChainCh:
			proxyID := filterChain.ProxyID
			proxyStatuses[proxyID] = proxyStatus{
				hasPendingFilterChainUpdate: true,
				filterChain:                 filterChain,
			}
		case clusterUpdate = <-u.clusterCh:
			pendingClusterUpdate = true
		case <-updateTicker.C():
			u.logger.Tracef("Checking for update")

			version := currentSnapshotVersion + 1
			numUpdates := 0
			for proxyID, status := range proxyStatuses {
				if !pendingClusterUpdate && !status.hasPendingFilterChainUpdate {
					// Nothing to do for this proxy.
					continue
				}

				status.hasPendingFilterChainUpdate = false
				proxyStatuses[proxyID] = status

				numUpdates++

				proxyLog := u.logger.WithFields(log.Fields{
					"proxy_id": proxyID,
				})

				snapshot, err := resources.GenerateSnapshot(version, clusterUpdate, status.filterChain)
				if err != nil {
					proxyLog.WithError(err).Warn("failed to generate snapshot")
					continue
				}

				if err := u.snapshotCache.SetSnapshot(proxyID, snapshot); err != nil {
					proxyLog.WithError(err).Warnf("Failed to set snapshot")
				}
			}

			pendingClusterUpdate = false
			if numUpdates > 0 {
				currentSnapshotVersion = version
			}
		}
	}
}
