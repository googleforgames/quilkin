package snapshot

import (
	"context"
	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"os"
	"quilkin.dev/xds-management-server/pkg/cluster"
	"quilkin.dev/xds-management-server/pkg/filterchain"
	"quilkin.dev/xds-management-server/pkg/filters"
	debugfilterv1alpha "quilkin.dev/xds-management-server/pkg/filters/debug/v1alpha1"
	"testing"
	"time"
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

func runTestSnapshotUpdater(
	ctx context.Context,
) (
	cache.SnapshotCache,
	chan<- []cluster.Cluster,
	chan<- filterchain.ProxyFilterChain,
) {
	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.WarnLevel)

	clusterCh := make(chan []cluster.Cluster)
	filterChainCh := make(chan filterchain.ProxyFilterChain)

	return RunSnapshotUpdater(
		ctx,
		logger,
		clusterCh,
		filterChainCh,
		1*time.Millisecond), clusterCh, filterChainCh
}

func TestSnapshotUpdaterClusterUpdate(t *testing.T) {
	// Test if we get a cluster update, all proxies are updated.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	snapshotCache, clusterCh, filterChainCh := runTestSnapshotUpdater(ctx)

	proxyIDs := []string{"proxy-1", "proxy-2", "proxy-3"}
	for _, proxyID := range proxyIDs {
		filterChainCh <- filterchain.ProxyFilterChain{
			ProxyID:     proxyID,
			FilterChain: &envoylistener.FilterChain{},
		}
	}

	// Wait for the first round of updates.
	waitForSnapshotUpdate(t, snapshotCache, proxyIDs, "1")

	// Send cluster update.
	clusterCh <- []cluster.Cluster{{
		Name: "cluster-1", Endpoints: []cluster.Endpoint{{
			IP:   "127.0.0.2",
			Port: 32,
		}}}}

	// Wait for a v2 snapshot.
	waitForSnapshotUpdate(t, snapshotCache, proxyIDs, "2")

	for _, proxyID := range proxyIDs {
		proxySnapshot, err := snapshotCache.GetSnapshot(proxyID)
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

	snapshotCache, _, filterChainCh := runTestSnapshotUpdater(ctx)

	proxyIDs := []string{"proxy-1", "proxy-2", "proxy-3"}
	for _, proxyID := range proxyIDs {
		_, err := snapshotCache.GetSnapshot(proxyID)
		require.Error(t, err, "found unexpected snapshot for proxy")
	}

	for _, proxyID := range proxyIDs {
		filterChainCh <- filterchain.ProxyFilterChain{
			ProxyID:     proxyID,
			FilterChain: &envoylistener.FilterChain{},
		}
	}

	waitForSnapshotUpdate(t, snapshotCache, proxyIDs, "1")

	for _, proxyID := range proxyIDs {
		proxySnapshot, err := snapshotCache.GetSnapshot(proxyID)
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

	snapshotCache, _, filterChainCh := runTestSnapshotUpdater(ctx)

	proxyIDs := []string{"proxy-1", "proxy-2"}

	// Start with empty an filter chain for all proxies.
	for _, proxyID := range proxyIDs {
		filterChainCh <- filterchain.ProxyFilterChain{
			ProxyID:     proxyID,
			FilterChain: &envoylistener.FilterChain{},
		}
	}

	waitForSnapshotUpdate(t, snapshotCache, proxyIDs, "1")

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
	waitForSnapshotUpdate(t, snapshotCache, []string{"proxy-2"}, "2")

	// Check that proxy-1 is on v1 while proxy-2 is on v2
	proxy1Snapshot := getProxySnapshot(t, snapshotCache, "proxy-1", "1")
	require.EqualValues(t, "filter_chains:{}", getDefaultFilterChain(t, proxy1Snapshot).String())

	proxy2Snapshot := getProxySnapshot(t, snapshotCache, "proxy-2", "2")
	require.Contains(t, getDefaultFilterChain(t, proxy2Snapshot).String(), "hello")
}
