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
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	envoyconfigcorev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/apimachinery/pkg/util/clock"
	"quilkin.dev/xds-management-server/pkg/cluster"
	"quilkin.dev/xds-management-server/pkg/filterchain"
	"quilkin.dev/xds-management-server/pkg/filters"
	debugfilterv1alpha "quilkin.dev/xds-management-server/pkg/filters/debug/v1alpha1"
)

const (
	// testDefaultUpdateInterval is how often to check for updates in tests.
	testDefaultUpdateInterval = 1 * time.Millisecond
	// testDefaultSnapshotCleanupInterval is how often to check for expired snapshots in tests.
	testDefaultSnapshotCleanupInterval = 60 * time.Minute
	// testDefaultSnapshotGracePeriod is how long before considering a snapshot expired.
	testDefaultSnapshotGracePeriod = 60 * time.Minute
)

func getDefaultFilterChain(t *testing.T, snapshot cache.Snapshot) types.Resource {
	listeners := snapshot.GetResources(resource.ListenerType)
	require.Len(t, listeners, 1)
	defaultListener, found := listeners[""]
	require.True(t, found)
	return defaultListener
}

func getProxySnapshot(t *testing.T, snapshotCache cache.SnapshotCache, proxyID string, version string) cache.Snapshot {
	snapshot, err := snapshotCache.GetSnapshot(proxyID)
	require.NoError(t, err)
	require.NoError(t, snapshot.Consistent())
	require.EqualValues(t, version, snapshot.GetVersion(resource.ListenerType))
	return snapshot
}

func waitForSnapshotUpdate(t *testing.T, snapshotCache cache.SnapshotCache, proxyIDs []string, version string) {
	require.Eventually(t, func() bool {
		for _, proxyID := range proxyIDs {
			snapshot, err := snapshotCache.GetSnapshot(proxyID)
			if err != nil {
				return false
			}
			if snapshot.GetVersion(resource.ClusterType) != version {
				return false
			}
		}
		return true
	}, 1*time.Second, 1*time.Millisecond)
}

func makeTestUpdater(
	ctx context.Context,
	configSetter ...func(updater *Updater),
) (
	*Updater,
	chan<- []cluster.Cluster,
	chan<- filterchain.ProxyFilterChain,
	*clock.FakeClock,
) {
	fakeClock := clock.NewFakeClock(time.Now())
	u, c, f := makeTestUpdaterWithClock(ctx, fakeClock, configSetter...)
	return u, c, f, fakeClock
}

func makeTestUpdaterWithClock(
	ctx context.Context,
	fakeClock *clock.FakeClock,
	configSetter ...func(updater *Updater),
) (
	*Updater,
	chan<- []cluster.Cluster,
	chan<- filterchain.ProxyFilterChain,
) {
	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.WarnLevel)

	clusterCh := make(chan []cluster.Cluster)
	filterChainCh := make(chan filterchain.ProxyFilterChain)

	configSetter = append([]func(*Updater){
		func(updater *Updater) {
			updater.clock = fakeClock
			updater.updateInterval = testDefaultUpdateInterval
			updater.snapshotCleanupInterval = testDefaultSnapshotCleanupInterval
			updater.snapshotGracePeriod = testDefaultSnapshotGracePeriod
		},
	}, configSetter...)
	u := NewUpdater(
		logger,
		clusterCh,
		filterChainCh,
		configSetter...)

	go u.Run(ctx)

	return u, clusterCh, filterChainCh
}

func TestSnapshotUpdaterClusterUpdate(t *testing.T) {
	// Test if we get a cluster update, all proxies are updated.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u, clusterCh, filterChainCh, fakeClock := makeTestUpdater(ctx)

	proxyIDs := []string{"proxy-1", "proxy-2", "proxy-3"}
	for _, proxyID := range proxyIDs {
		filterChainCh <- filterchain.ProxyFilterChain{
			ProxyID:     proxyID,
			FilterChain: &envoylistener.FilterChain{},
		}
	}

	// Wait for the first round of updates.
	fakeClock.Step(defaultUpdateInterval)
	waitForSnapshotUpdate(t, u.snapshotCache, proxyIDs, "1")

	// Send cluster update.
	clusterCh <- []cluster.Cluster{{
		Name: "cluster-1", Endpoints: []cluster.Endpoint{{
			IP:   "127.0.0.2",
			Port: 32,
		}}}}

	// Wait for a v2 snapshot.
	fakeClock.Step(defaultUpdateInterval)
	waitForSnapshotUpdate(t, u.snapshotCache, proxyIDs, "2")

	for _, proxyID := range proxyIDs {
		proxySnapshot, err := u.snapshotCache.GetSnapshot(proxyID)
		require.NoError(t, err)
		require.NoError(t, proxySnapshot.Consistent())

		clusters := proxySnapshot.GetResources(resource.ClusterType)
		require.Len(t, clusters, 1)
		testCluster, found := clusters["cluster-1"]
		require.True(t, found)
		require.Contains(t, testCluster.String(), "127.0.0.2")
	}
}

func TestSnapshotUpdaterProxyFilterChainUpdates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u, _, filterChainCh, fakeClock := makeTestUpdater(ctx)

	proxyIDs := []string{"proxy-1", "proxy-2", "proxy-3"}
	for _, proxyID := range proxyIDs {
		_, err := u.snapshotCache.GetSnapshot(proxyID)
		require.Error(t, err, "found unexpected snapshot for proxy")
	}

	for _, proxyID := range proxyIDs {
		filterChainCh <- filterchain.ProxyFilterChain{
			ProxyID:     proxyID,
			FilterChain: &envoylistener.FilterChain{},
		}
	}

	fakeClock.Step(defaultUpdateInterval)
	waitForSnapshotUpdate(t, u.snapshotCache, proxyIDs, "1")

	for _, proxyID := range proxyIDs {
		proxySnapshot, err := u.snapshotCache.GetSnapshot(proxyID)
		require.NoError(t, err)
		require.NoError(t, proxySnapshot.Consistent())

		require.EqualValues(t, "1", proxySnapshot.GetVersion(resource.ClusterType))
		require.EqualValues(t, "1", proxySnapshot.GetVersion(resource.ListenerType))

		clusters := proxySnapshot.GetResources(resource.ClusterType)
		require.Empty(t, clusters)

		listeners := proxySnapshot.GetResources(resource.ListenerType)
		require.Len(t, listeners, 1)
	}
}

func TestSnapshotUpdaterContinuousProxyFilterChainUpdates(t *testing.T) {
	// Test that proxies are updated independently and continuously.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u, _, filterChainCh, fakeClock := makeTestUpdater(ctx)

	proxyIDs := []string{"proxy-1", "proxy-2"}

	// Start with empty an filter chain for all proxies.
	for _, proxyID := range proxyIDs {
		filterChainCh <- filterchain.ProxyFilterChain{
			ProxyID:     proxyID,
			FilterChain: &envoylistener.FilterChain{},
		}
	}

	fakeClock.Step(defaultUpdateInterval)
	waitForSnapshotUpdate(t, u.snapshotCache, proxyIDs, "1")

	// Send an updated filter chain to proxy-2
	debugFilter, err := filterchain.CreateXdsFilter(filters.DebugFilterName,
		&debugfilterv1alpha.Debug{
			Id: &wrapperspb.StringValue{Value: "hello"},
		})
	require.NoError(t, err)

	filterChainCh <- filterchain.ProxyFilterChain{
		ProxyID: "proxy-2",
		FilterChain: &envoylistener.FilterChain{
			Filters: []*envoylistener.Filter{debugFilter},
		},
	}
	fakeClock.Step(defaultUpdateInterval)
	waitForSnapshotUpdate(t, u.snapshotCache, []string{"proxy-2"}, "2")

	// Check that proxy-1 is on v1 while proxy-2 is on v2
	proxy1Snapshot := getProxySnapshot(t, u.snapshotCache, "proxy-1", "1")
	require.EqualValues(t, "filter_chains:{}", getDefaultFilterChain(t, proxy1Snapshot).String())

	proxy2Snapshot := getProxySnapshot(t, u.snapshotCache, "proxy-2", "2")
	require.Contains(t, getDefaultFilterChain(t, proxy2Snapshot).String(), "hello")
}

// testSnapshotCleanupView implements snapshotCleanupView for tests.
type testSnapshotCleanupView map[string]cache.StatusInfo

func (c testSnapshotCleanupView) GetStatusInfo(nodeID string) cache.StatusInfo {
	return c[nodeID]
}

func (c testSnapshotCleanupView) GetStatusKeys() []string {
	keys := make([]string, 0, len(c))
	for nodeID := range c {
		keys = append(keys, nodeID)
	}
	return keys
}

func (c testSnapshotCleanupView) ClearSnapshot(nodeID string) {
	delete(c, nodeID)
}

type testStatusInfo struct {
	*sync.Mutex
	t                         *testing.T
	numWatches                int
	numDeltaWatches           int
	lastWatchRequestTime      time.Time
	lastDeltaWatchRequestTime time.Time
}

func (s *testStatusInfo) GetNode() *envoyconfigcorev3.Node {
	require.FailNow(s.t, "GetNode is not implemented")
	return nil
}

func (s *testStatusInfo) GetNumWatches() int {
	s.Lock()
	defer s.Unlock()

	return s.numWatches
}

func (s *testStatusInfo) GetNumDeltaWatches() int {
	s.Lock()
	defer s.Unlock()

	return s.numDeltaWatches
}

func (s *testStatusInfo) GetLastWatchRequestTime() time.Time {
	s.Lock()
	defer s.Unlock()

	return s.lastWatchRequestTime
}

func (s *testStatusInfo) GetLastDeltaWatchRequestTime() time.Time {
	s.Lock()
	defer s.Unlock()

	return s.lastDeltaWatchRequestTime
}

func (s *testStatusInfo) SetLastDeltaWatchRequestTime(time.Time) {
	require.FailNow(s.t, "SetLastDeltaWatchRequestTime is not implemented")
}

func (s *testStatusInfo) SetDeltaResponseWatch(int64, cache.DeltaResponseWatch) {
	require.FailNow(s.t, "SetDeltaResponseWatch is not implemented")
}

func TestSnapshotCleanup(t *testing.T) {
	// Test that proxy snapshot are cleaned up upon disconnection after grace period.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fakeClock := clock.NewFakeClock(time.Now())
	state := testSnapshotCleanupView{
		// watch expired.
		"node-1": &testStatusInfo{
			Mutex:                &sync.Mutex{},
			t:                    t,
			numWatches:           0,
			lastWatchRequestTime: fakeClock.Now(),
		},
		// delta watch expired.
		"node-2": &testStatusInfo{
			Mutex:                     &sync.Mutex{},
			t:                         t,
			numDeltaWatches:           0,
			lastDeltaWatchRequestTime: fakeClock.Now(),
		},
		// has old open watch.
		"node-3": &testStatusInfo{
			Mutex:                &sync.Mutex{},
			t:                    t,
			numWatches:           1,
			lastWatchRequestTime: fakeClock.Now(),
		},
		// has old open delta watch.
		"node-4": &testStatusInfo{
			Mutex:                &sync.Mutex{},
			t:                    t,
			numWatches:           1,
			lastWatchRequestTime: fakeClock.Now(),
		},
		// watch not yet expired.
		"node-5": &testStatusInfo{
			Mutex:                &sync.Mutex{},
			t:                    t,
			numWatches:           0,
			lastWatchRequestTime: fakeClock.Now().Add(3 * time.Second),
		},
		// delta watch not yet expired.
		"node-6": &testStatusInfo{
			Mutex:                     &sync.Mutex{},
			t:                         t,
			numDeltaWatches:           0,
			lastDeltaWatchRequestTime: fakeClock.Now().Add(3 * time.Second),
		},
	}

	cleanupInterval := 1 * time.Second
	_, _, _ = makeTestUpdaterWithClock(ctx, fakeClock, func(updater *Updater) {
		updater.snapshotCleanupView = state
		updater.snapshotCleanupInterval = cleanupInterval
		updater.snapshotGracePeriod = 2 * time.Second
	})

	require.Eventually(t, func() bool {
		remainingNodeIDs := state.GetStatusKeys()
		if len(remainingNodeIDs) != 4 {
			fakeClock.Step(cleanupInterval)
			return false
		}

		sort.Strings(remainingNodeIDs)

		require.EqualValues(t, []string{
			"node-3", "node-4", "node-5", "node-6",
		}, remainingNodeIDs)
		return true
	}, 1*time.Second, 10*time.Millisecond)
}
