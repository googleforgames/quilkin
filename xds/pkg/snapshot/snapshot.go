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

package snapshot

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"quilkin.dev/xds-management-server/pkg/metrics"

	"quilkin.dev/xds-management-server/pkg/cluster"
	"quilkin.dev/xds-management-server/pkg/filterchain"

	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/clock"

	"quilkin.dev/xds-management-server/pkg/resources"
)

var (
	snapshotErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: metrics.Subsystem,
		Name:      "snapshot_generation_errors_total",
		Help:      "Total number of errors encountered while generating snapshots",
	})
	snapshotGeneratedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: metrics.Subsystem,
		Name:      "snapshots_generated_total",
		Help:      "Total number of snapshots generated across all proxies",
	})
)

const (
	// defaultUpdateInterval is how often to check for snapshot updates.
	defaultUpdateInterval = 100 * time.Millisecond
	// defaultSnapshotCleanupInterval is how often to check for expired snapshots.
	defaultSnapshotCleanupInterval = 30 * time.Second
	// defaultSnapshotGracePeriod is how long before considering a snapshot without open watches expired.
	defaultSnapshotGracePeriod = 2 * time.Minute
)

// Updater periodically generates xds config snapshots from resources
// and updates a snapshot cache with the latest snapshot for each connected
// node.
type Updater struct {
	logger                  *log.Logger
	clusterCh               <-chan []cluster.Cluster
	filterChainCh           <-chan filterchain.ProxyFilterChain
	updateInterval          time.Duration
	snapshotCleanupInterval time.Duration
	snapshotGracePeriod     time.Duration
	clock                   clock.Clock
	snapshotCache           cache.SnapshotCache
	snapshotCleanupView     snapshotCleanupView
}

// NewUpdater returns a new Updater.
func NewUpdater(
	logger *log.Logger,
	clusterCh <-chan []cluster.Cluster,
	filterChainCh <-chan filterchain.ProxyFilterChain,
	configSetter ...func(updater *Updater),
) *Updater {
	logger = logger.WithFields(log.Fields{
		"component": "SnapshotUpdater",
	}).Logger
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, logger)
	u := &Updater{
		logger:                  logger,
		clusterCh:               clusterCh,
		filterChainCh:           filterChainCh,
		snapshotCache:           snapshotCache,
		updateInterval:          defaultUpdateInterval,
		snapshotCleanupInterval: defaultSnapshotCleanupInterval,
		snapshotGracePeriod:     defaultSnapshotGracePeriod,
		clock:                   clock.RealClock{},
		snapshotCleanupView:     snapshotCache,
	}

	for _, f := range configSetter {
		f(u)
	}

	return u
}

// GetSnapshotCache returns the backing snapshot cache.
func (u *Updater) GetSnapshotCache() cache.SnapshotCache {
	return u.snapshotCache
}

// Run runs a loop that periodically checks if there are any
// cluster/filter-chain updates and if so creates a snapshot for
// affected proxies in the snapshot cache.
func (u *Updater) Run(ctx context.Context) {
	updateTicker := u.clock.NewTicker(u.updateInterval)
	defer updateTicker.Stop()

	cleanupTicker := u.clock.NewTicker(u.snapshotCleanupInterval)
	defer cleanupTicker.Stop()

	currentSnapshotVersion := int64(0)

	type proxyStatus struct {
		hasPendingFilterChainUpdate bool
		filterChain                 filterchain.ProxyFilterChain
	}
	proxyStatuses := make(map[string]proxyStatus)

	var pendingClusterUpdate bool
	var clusterUpdate []cluster.Cluster

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

				proxyLog.Debug("Setting snapshot update")

				if err := u.snapshotCache.SetSnapshot(proxyID, snapshot); err != nil {
					snapshotErrorsTotal.Inc()
					proxyLog.WithError(err).Warnf("Failed to set snapshot")
				} else {
					snapshotGeneratedTotal.Inc()
				}
			}

			pendingClusterUpdate = false
			if numUpdates > 0 {
				currentSnapshotVersion = version
			}
		case <-cleanupTicker.C():
			u.cleanup()
		}
	}
}

// snapshotCleanupView implements the relevant functions of cache.SnapshotCache that
// the cleanup function needs to do its work. This allows us to test the cleanup
// function.
type snapshotCleanupView interface {
	// GetStatusInfo retrieves status information for a node ID.
	GetStatusInfo(string) cache.StatusInfo

	// GetStatusKeys retrieves node IDs for all statuses.
	GetStatusKeys() []string

	// ClearSnapshot removes all status and snapshot information associated with a node.
	ClearSnapshot(node string)
}

// cleanup deletes snapshots from the cache for any node that is no longer
// connected to the server.
func (u *Updater) cleanup() {
	// If a node has had no open watches in a while (specified by the
	// configurable snapshot grace period) then let's delete its snapshot.
	nodeIDs := u.snapshotCleanupView.GetStatusKeys()
	numRemoved := 0
	for _, nodeID := range nodeIDs {
		statusInfo := u.snapshotCleanupView.GetStatusInfo(nodeID)
		if statusInfo == nil {
			continue
		}

		// If there is at least 1 open watch then nothing to do.
		if statusInfo.GetNumWatches() > 0 || statusInfo.GetNumDeltaWatches() > 0 {
			continue
		}

		// No open watches exist for this node. Check how long it has been since
		// the last watch. If it exceeds the TTL, then delete its snapshot.
		now := u.clock.Now()
		lastWatchTime := statusInfo.GetLastWatchRequestTime()
		lastDeltaWatchTime := statusInfo.GetLastDeltaWatchRequestTime()

		shouldRemove := false
		if lastWatchTime.Unix() > 0 && now.Sub(lastWatchTime) >= u.snapshotGracePeriod {
			shouldRemove = true
		}
		if lastDeltaWatchTime.Unix() > 0 && now.Sub(lastDeltaWatchTime) >= u.snapshotGracePeriod {
			shouldRemove = true
		}

		if shouldRemove {
			numRemoved++
			u.logger.WithFields(log.Fields{
				"proxy_id": nodeID,
			}).Debugf("Removing expired snapshot")
			u.snapshotCleanupView.ClearSnapshot(nodeID)
		}
	}

	u.logger.Debugf("Snapshot cleanup: Removed %d/%d snapshots", numRemoved, len(nodeIDs))
}
