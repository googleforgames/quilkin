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

package k8s

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	kubernetesv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	testing2 "k8s.io/client-go/testing"
	"quilkin.dev/xds-management-server/pkg/filterchain"
	"quilkin.dev/xds-management-server/pkg/filters"
)

// defaultUpdateInterval is how often to check for updates in tests.
const defaultUpdateInterval = 1 * time.Millisecond

func TestProviderCreateFilterChainForWatchedPods(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, watcherStarted := testClient()

	p, fakeClock := testProvider(ctx, t, client)
	filterChainCh := p.Run(ctx)
	<-watcherStarted

	// A new pod is created.
	pod1 := testPod("pod-1")
	pod1.Annotations[annotationKeyDebug] = "true"
	createPod(ctx, t, client, pod1)

	pfc := waitForFilterChainUpdate(t, fakeClock, filterChainCh)

	require.EqualValues(t, "pod-1", pfc.ProxyID)
	require.Len(t, pfc.FilterChain.Filters, 1)
	require.Contains(t, pfc.FilterChain.Filters[0].String(), filters.DebugFilterName)
}

func TestProviderCreateProxySpecificFilterChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, watcherStarted := testClient()

	p, fakeClock := testProvider(ctx, t, client)
	filterChainCh := p.Run(ctx)
	<-watcherStarted

	pod1 := testPod("pod-1")
	pod1.Annotations[annotationKeyDebug] = "true"
	createPod(ctx, t, client, pod1)

	pod2 := testPod("pod-2")
	pod2.Annotations[annotationKeyDebug] = "false"
	createPod(ctx, t, client, pod2)

	pod3 := testPod("pod-3")
	pod3.Annotations[annotationKeyDebug] = "true"
	createPod(ctx, t, client, pod3)

	// Wait for a filter chain to be delivered for each pod
	pfcs := []filterchain.ProxyFilterChain{
		waitForFilterChainUpdate(t, fakeClock, filterChainCh),
		waitForFilterChainUpdate(t, fakeClock, filterChainCh),
		waitForFilterChainUpdate(t, fakeClock, filterChainCh),
	}

	sort.Slice(pfcs, func(i, j int) bool {
		return strings.Compare(pfcs[i].ProxyID, pfcs[j].ProxyID) < 0
	})

	pfc1, pfc2, pfc3 := pfcs[0], pfcs[1], pfcs[2]

	require.EqualValues(t, "pod-1", pfc1.ProxyID)
	require.EqualValues(t, "pod-2", pfc2.ProxyID)
	require.EqualValues(t, "pod-3", pfc3.ProxyID)

	for _, pfc := range []filterchain.ProxyFilterChain{pfc1, pfc3} {
		require.Len(t, pfc.FilterChain.Filters, 1)
		require.Contains(t, pfc.FilterChain.Filters[0].String(), filters.DebugFilterName)
	}

	// Shutdown
	cancel()

	// Check that we don't have any more updates.
	empty, more := <-filterChainCh
	require.False(t, more, "received unexpected filter chain update")
	require.EqualValues(t, filterchain.ProxyFilterChain{}, empty)
}

func TestProviderPushNewFilterChainWhenPodIsUpdated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, watcherStarted := testClient()

	p, fakeClock := testProvider(ctx, t, client)
	filterChainCh := p.Run(ctx)
	<-watcherStarted

	// Create the pod with debug enabled.
	pod := testPod("pod-1")
	pod.Annotations[annotationKeyDebug] = "true"
	createPod(ctx, t, client, pod)

	// Check that the generated filter chain has the debug filter.
	pfc := waitForFilterChainUpdate(t, fakeClock, filterChainCh)
	require.Contains(t, pfc.FilterChain.Filters[0].String(), filters.DebugFilterName)

	// Update the pod to turn off debug.
	pod.Annotations[annotationKeyDebug] = "false"
	_, err := client.
		CoreV1().
		Pods(pod.Namespace).
		Update(ctx, pod, metav1.UpdateOptions{})
	require.NoError(t, err, "failed to create pod")

	// Check that the generated filter chain has no filter.
	pfc = waitForFilterChainUpdate(t, fakeClock, filterChainCh)
	require.Empty(t, pfc.FilterChain.Filters)

	// Shutdown
	cancel()

	// Check that we don't have any more updates.
	empty, more := <-filterChainCh
	require.False(t, more, "received unexpected filter chain update")
	require.EqualValues(t, filterchain.ProxyFilterChain{}, empty)
}

func TestProviderIgnoreNonProxyPods(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, watcherStarted := testClient()

	p, fakeClock := testProvider(ctx, t, client)
	filterChainCh := p.Run(ctx)
	<-watcherStarted

	// A new pod is created but in a different namespace.
	createPod(ctx, t, client, &kubernetesv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "quilkin-2",
		},
	})

	// Give enough time for any updates to have been processed.
	time.Sleep(2 * time.Millisecond)
	fakeClock.Step(defaultUpdateInterval)

	// Shutdown
	cancel()

	// Check that we did not receive any update.
	empty, more := <-filterChainCh
	require.False(t, more, "received unexpected filter chain update")
	require.EqualValues(t, filterchain.ProxyFilterChain{}, empty)
}

func testProvider(ctx context.Context, t *testing.T, client kubernetes.Interface) (*Provider, *clock.FakeClock) {
	fakeClock := clock.NewFakeClock(time.Now())
	p, err := NewProvider(
		ctx,
		testLogger(),
		fakeClock,
		client,
		defaultProxyNamespace,
		defaultUpdateInterval)
	require.NoError(t, err, "failed to create provider")
	return p, fakeClock
}

func testPod(name string) *kubernetesv1.Pod {
	return &kubernetesv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   defaultProxyNamespace,
			Annotations: map[string]string{},
		},
	}
}

func testClient() (kubernetes.Interface, <-chan struct{}) {
	// From the kubernetes example docs...
	// The fake client doesn't support resource version. Any writes to the client
	// after the informer's initial LIST and before the informer establishing the
	// watcher will be missed by the informer. Therefore we wait until the watcher
	// starts.
	watcherStarted := make(chan struct{})

	client := fake.NewSimpleClientset()
	client.PrependWatchReactor("*", func(action testing2.Action) (handled bool, ret watch.Interface, err error) {
		rs := action.GetResource()
		ns := action.GetNamespace()

		w, err := client.Tracker().Watch(rs, ns)
		if err != nil {
			return false, nil, err
		}
		close(watcherStarted)
		return true, w, nil
	})

	return client, watcherStarted
}

func waitForFilterChainUpdate(
	t *testing.T,
	fakeClock *clock.FakeClock,
	filterChainCh <-chan filterchain.ProxyFilterChain,
) filterchain.ProxyFilterChain {
	var pfc filterchain.ProxyFilterChain
	require.Eventually(t, func() bool {
		// Run update loop.
		fakeClock.Step(defaultUpdateInterval)

		select {
		case f := <-filterChainCh:
			pfc = f
			return true
		default:
			return false
		}
	}, 10*time.Second, 1*time.Millisecond)

	return pfc
}

func createPod(ctx context.Context, t *testing.T, client kubernetes.Interface, pod *kubernetesv1.Pod) {
	_, err := client.
		CoreV1().
		Pods(pod.Namespace).
		Create(ctx, pod, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create pod")
}

func testLogger() *log.Logger {
	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)
	return logger
}
