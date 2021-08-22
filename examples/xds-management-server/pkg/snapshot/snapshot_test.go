package snapshot

import (
	"context"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"os"
	"quilkin.dev/xds-management-server/pkg/resources"
	"testing"
	"time"
)

func TestSnapshotUpdaterNodePendingUpdate(t *testing.T) {
	// Test if we discover a node at a time when we have no update to push to it,
	// we end up pushing to it the next time an update appears
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)

	nodeIDCh := make(chan string)
	resourcesCh := make(chan resources.Resources)

	snapshotCache := RunSnapshotUpdater(ctx, logger, nodeIDCh, resourcesCh, 2*time.Millisecond)

	// Send a node notification.
	nodeIDCh <- "node-1"
	// Wait a bit for the message to be processed
	time.Sleep(10 * time.Millisecond)

	_, err := snapshotCache.GetSnapshot("node-1")
	require.Error(t, err, "found unexpected snapshot for node")

	// Send a resource update.
	resourcesCh <- resources.Resources{}
	// Wait a bit for the message to be processed
	require.Eventually(t, func() bool {
		_, err := snapshotCache.GetSnapshot("node-1")
		return err == nil
	}, 1*time.Second, 1*time.Millisecond)

	nodeSnapshot, err := snapshotCache.GetSnapshot("node-1")
	require.NoError(t, err)

	require.NoError(t, nodeSnapshot.Consistent())
}

func TestSnapshotUpdaterNodeUpdateAtDiscovery(t *testing.T) {
	// Test if we have an update at the time we discover a new node, we push it
	//  immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)

	nodeIDCh := make(chan string)
	resourcesCh := make(chan resources.Resources)

	snapshotCache := RunSnapshotUpdater(ctx, logger, nodeIDCh, resourcesCh, 2*time.Millisecond)

	// Send a resource update.
	resourcesCh <- resources.Resources{}
	// Wait a bit for the message to be processed
	time.Sleep(10 * time.Millisecond)

	// Send a node notification.
	nodeIDCh <- "node-1"
	// Wait a bit for the message to be processed
	time.Sleep(10 * time.Millisecond)
	// Wait a bit for the message to be processed
	require.Eventually(t, func() bool {
		_, err := snapshotCache.GetSnapshot("node-1")
		return err == nil
	}, 1*time.Second, 1*time.Millisecond)

	nodeSnapshot, err := snapshotCache.GetSnapshot("node-1")
	require.NoError(t, err)

	require.NoError(t, nodeSnapshot.Consistent())
}

func TestSnapshotUpdaterMultipleNodeUpdates(t *testing.T) {
	// Test that we continuously push updates to nodes.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)

	nodeIDCh := make(chan string)
	resourcesCh := make(chan resources.Resources)

	snapshotCache := RunSnapshotUpdater(ctx, logger, nodeIDCh, resourcesCh, 2*time.Millisecond)

	// Send a resource update.
	resourcesCh <- resources.Resources{}
	// Wait a bit for the message to be processed
	time.Sleep(10 * time.Millisecond)

	// Send node notifications.
	nodeIDCh <- "node-1"
	nodeIDCh <- "node-2"
	// Wait a bit for the messages to be processed
	time.Sleep(10 * time.Millisecond)

	// Wait a bit for node snapshots
	require.Eventually(t, func() bool {
		_, err1 := snapshotCache.GetSnapshot("node-1")
		_, err2 := snapshotCache.GetSnapshot("node-2")
		return err1 == nil && err2 == nil
	}, 1*time.Second, 1*time.Millisecond)

	// Send a new resource update.
	resourcesCh <- resources.Resources{
		Clusters: []resources.Cluster{{
			Name: "cluster-1",
			Endpoints: []resources.Endpoint{{
				IP:   "127.0.0.1",
				Port: 22,
			}},
		}},
	}

	// Wait a bit for node snapshots
	require.Eventually(t, func() bool {
		for _, nodeID := range []string{"node-1", "node-2"} {
			snapshot, err := snapshotCache.GetSnapshot(nodeID)
			if err != nil {
				return false
			}

			rs := snapshot.GetResources(resource.ClusterType)
			if _, found := rs["cluster-1"]; !found {
				return false
			}
		}
		return true
	}, 1*time.Second, 1*time.Millisecond)

	for _, nodeID := range []string{"node-1", "node-2"} {
		snapshot, err := snapshotCache.GetSnapshot(nodeID)
		require.NoError(t, err)

		require.NoError(t, snapshot.Consistent())

		clusters := snapshot.GetResources(resource.ClusterType)
		require.Len(t, clusters, 1)
		cluster, found := clusters["cluster-1"]
		require.True(t, found)

		require.Contains(t, cluster.String(), "127.0.0.1")
	}
}
