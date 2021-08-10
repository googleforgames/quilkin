package snapshot

import (
	"context"
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
	nodeIDCh <-chan string,
	resourcesCh <-chan resources.Resources,
	updateInterval time.Duration,
) cache.SnapshotCache {
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, logger)
	go runSnapshotUpdater(
		ctx,
		logger,
		nodeIDCh,
		resourcesCh,
		snapshotCache,
		updateInterval)
	return snapshotCache
}

func runSnapshotUpdater(
	ctx context.Context,
	logger *log.Logger,
	nodeIDCh <-chan string,
	resourcesCh <-chan resources.Resources,
	snapshotCache cache.SnapshotCache,
	updateInterval time.Duration,
) {
	logger = logger.WithFields(log.Fields{
		"component": "SnapshotUpdater",
	}).Logger

	updateTicker := time.NewTicker(updateInterval)
	defer updateTicker.Stop()

	noSnapshot := int64(0)
	currentSnapshotVersion := noSnapshot
	var currentSnapshot cache.Snapshot

	var latestResources resources.Resources
	// Map each node to the most recent snapshot version they've seen.
	//  we use this to figure out whether or not to update the ndoe
	nodeStatus := make(map[string]int64)

	// TODO: Implement cleanup of stale nodes in the snapshot Cache
	//   (If we have no open watchers for a node we can forget it?).
	for {
		select {
		case <-ctx.Done():
			logger.Infof("Exiting snapshot updater loop: Context cancelled")
			return
		case nodeID := <-nodeIDCh:
			if _, exists := nodeStatus[nodeID]; !exists {
				// New node. The node has seen no update so assign 0 index.
				nodeStatus[nodeID] = noSnapshot
			}
		case latestResources = <-resourcesCh:
			version := currentSnapshotVersion + 1
			snapshot, err := resources.GenerateSnapshot(version, latestResources)
			if err != nil {
				logger.WithError(err).Warn("failed to generate snapshot")
				continue
			}

			currentSnapshot = snapshot
			currentSnapshotVersion = version
		case <-updateTicker.C:
			logger.Tracef("Checking for update")

			// If we haven't generated any snapshot at all, nothing to do.
			if currentSnapshotVersion == noSnapshot {
				continue
			}

			var nodeIDsToUpdate []string
			for nodeID, lastSeenSnapshotVersion := range nodeStatus {
				// Nothing to send if the node has already seen this update.
				if lastSeenSnapshotVersion == currentSnapshotVersion {
					continue
				}

				// Mark the node as having seen this version since we're about to send it.
				nodeStatus[nodeID] = currentSnapshotVersion

				nodeIDsToUpdate = append(nodeIDsToUpdate, nodeID)
			}

			if len(nodeIDsToUpdate) == 0 {
				continue
			}

			for _, nodeID := range nodeIDsToUpdate {
				if err := snapshotCache.SetSnapshot(nodeID, currentSnapshot); err != nil {
					logger.WithError(err).WithFields(log.Fields{
						"node": nodeID,
					}).Warnf("Failed to set snapshot")
				}
			}
		}
	}
}
