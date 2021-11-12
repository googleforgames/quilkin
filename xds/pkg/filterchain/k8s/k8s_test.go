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

	servertesting "quilkin.dev/xds-management-server/pkg/testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	kubernetesv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/watch"
	k8stesting "k8s.io/client-go/testing"
	"quilkin.dev/xds-management-server/pkg/filterchain"
	"quilkin.dev/xds-management-server/pkg/filters"
)

// defaultUpdateInterval is how often to check for updates in tests.
const defaultUpdateInterval = 1 * time.Millisecond

func TestProviderCreateFilterChainForWatchedPods(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	m := servertesting.NewMocks()

	p, fakeClock, fakeWatch := testProvider(t, m)
	filterChainCh := p.Run(ctx)

	// A new pod is created.
	pod1 := testPod("pod-1")
	pod1.Annotations[annotationKeyDebug] = "true"

	fakeWatch.Add(pod1)

	pfc := waitForFilterChainUpdate(t, fakeClock, filterChainCh)

	require.EqualValues(t, "pod-1", pfc.ProxyID)
	require.Len(t, pfc.FilterChain.Filters, 1)
	require.Contains(t, pfc.FilterChain.Filters[0].String(), filters.DebugFilterName)
}

func TestProviderCreateProxySpecificFilterChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	m := servertesting.NewMocks()

	p, fakeClock, fakeWatch := testProvider(t, m)
	filterChainCh := p.Run(ctx)

	pod1 := testPod("pod-1")
	pod1.Annotations[annotationKeyDebug] = "true"
	fakeWatch.Add(pod1)

	pod2 := testPod("pod-2")
	pod2.Annotations[annotationKeyDebug] = "false"
	fakeWatch.Add(pod2)

	pod3 := testPod("pod-3")
	pod3.Annotations[annotationKeyDebug] = "true"
	fakeWatch.Add(pod3)

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

	m := servertesting.NewMocks()

	p, fakeClock, fakeWatch := testProvider(t, m)
	filterChainCh := p.Run(ctx)

	// Create the pod with debug enabled.
	pod := testPod("pod-1")
	pod.Annotations[annotationKeyDebug] = "true"
	fakeWatch.Add(pod)

	// Check that the generated filter chain has the debug filter.
	pfc := waitForFilterChainUpdate(t, fakeClock, filterChainCh)
	require.Contains(t, pfc.FilterChain.Filters[0].String(), filters.DebugFilterName)

	// Update the pod to turn off debug.
	updatedPod := testPod("pod-1")
	updatedPod.Annotations[annotationKeyDebug] = "false"
	fakeWatch.Add(updatedPod)

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

	m := servertesting.NewMocks()

	p, fakeClock, fakeWatch := testProvider(t, m)
	filterChainCh := p.Run(ctx)
	fakeWatch.Add(&kubernetesv1.Pod{
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

func testProvider(
	t *testing.T,
	mocks *servertesting.Mocks,
) (*Provider, *clock.FakeClock, *watch.FakeWatcher) {
	fakeClock := clock.NewFakeClock(time.Now())

	fakeWatch := watch.NewFake()
	mocks.K8sClient.AddWatchReactor("pods", k8stesting.DefaultWatchReactor(fakeWatch, nil))
	mocks.StartInformers(t, mocks.K8sInformerFactory.Core().V1().Pods().Informer().HasSynced)

	p := NewProvider(
		testLogger(),
		fakeClock,
		mocks.K8sInformerFactory.Core().V1().Pods().Lister(),
		defaultUpdateInterval)
	return p, fakeClock, fakeWatch
}

func testPod(name string) *kubernetesv1.Pod {
	return &kubernetesv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   defaultProxyNamespace,
			Annotations: map[string]string{},
			Labels: map[string]string{
				"quilkin.dev/role": "proxy",
			},
		},
	}
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

func testLogger() *log.Logger {
	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)
	return logger
}
