package snapshot

import (
	"context"
	"quilkin.dev/xds-management-server/pkg/cluster"
	"quilkin.dev/xds-management-server/pkg/filterchain"
	"time"

	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	log "github.com/sirupsen/logrus"

	"quilkin.dev/xds-management-server/pkg/resources"
)

// RunSnapshotUpdater starts a goroutine that listens for resource updates,
// uses the updates to generate an xds config snapshot and updates the snapshot from the provided channel and generates xds config snapshots.
// cache with the latest snapshot for each connected node.
// It returns the snapshot cache which can be passed on to the xds server impl.
func RunSnapshotUpdater(
	ctx context.Context,
	logger *log.Logger,
	clusterCh <-chan []cluster.Cluster,
	filterChainCh <-chan filterchain.ProxyFilterChain,
	updateInterval time.Duration,
) cache.SnapshotCache {
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, logger)
	go runSnapshotUpdater(
		ctx,
		logger,
		clusterCh,
		filterChainCh,
		snapshotCache,
		updateInterval)
	return snapshotCache
}

// runSnapshotUpdater runs a loop that periodically checks if there are any
// cluster/filter-chain updates and if so creates a snapshot for affected proxies
// in the snapshot cache.
func runSnapshotUpdater(
	ctx context.Context,
	logger *log.Logger,
	clusterCh <-chan []cluster.Cluster,
	filterChainCh <-chan filterchain.ProxyFilterChain,
	snapshotCache cache.SnapshotCache,
	updateInterval time.Duration,
) {
	logger = logger.WithFields(log.Fields{
		"component": "SnapshotUpdater",
	}).Logger

	updateTicker := time.NewTicker(updateInterval)
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
			logger.Infof("Exiting snapshot updater loop: Context cancelled")
			return
		case filterChain := <-filterChainCh:
			proxyID := filterChain.ProxyID
			proxyStatuses[proxyID] = proxyStatus{
				hasPendingFilterChainUpdate: true,
				filterChain:                 filterChain,
			}
		case clusterUpdate = <-clusterCh:
			pendingClusterUpdate = true
		case <-updateTicker.C:
			logger.Tracef("Checking for update")

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

				proxyLog := logger.WithFields(log.Fields{
					"proxy_id": proxyID,
				})

				snapshot, err := resources.GenerateSnapshot(version, clusterUpdate, status.filterChain)
				if err != nil {
					proxyLog.WithError(err).Warn("failed to generate snapshot")
					continue
				}

				if err := snapshotCache.SetSnapshot(proxyID, snapshot); err != nil {
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
