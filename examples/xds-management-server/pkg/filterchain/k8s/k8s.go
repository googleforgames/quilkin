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
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	v1 "k8s.io/client-go/listers/core/v1"

	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/apimachinery/pkg/util/clock"
	"quilkin.dev/xds-management-server/pkg/filterchain"
	filters2 "quilkin.dev/xds-management-server/pkg/filters"
	debugfilterv1alpha "quilkin.dev/xds-management-server/pkg/filters/debug/v1alpha1"
)

const (
	annotationKeyPrefix = "quilkin.dev/"
	labelKeyRole        = annotationKeyPrefix + "role"
	annotationKeyDebug  = annotationKeyPrefix + "debug-packets"
	labelProxy          = "proxy"
	// LabelSelectorProxyRole is the label selector for proxy pods.
	LabelSelectorProxyRole = labelKeyRole + "=" + labelProxy
	defaultProxyNamespace  = "quilkin"
)

var _ filterchain.Provider = &Provider{}

// relevantAnnotations lists the pod annotations that we care about.
var relevantAnnotations = []string{
	annotationKeyDebug,
}

// proxyPod represents a proxy's pod connected to the server.
type proxyPod struct {
	podID string
	// We use pod annotations to configure the behavior of the proxy
	//  on that pod. This tracks the last set of annotations that we
	//  have seen on the pod. The proxy's filter-chain is updated accordingly
	//  if the set changes.
	latestPodAnnotations map[string]string
}

// Provider is a filter chain provider implementation for kubernetes that
// generates filter chain per proxy based on each proxy's pod annotations.
type Provider struct {
	logger *log.Logger
	// podStore contains the current list of all pods.
	podLister v1.PodLister
	// proxyRefreshInterval is how often to check pods for updates.
	proxyRefreshInterval time.Duration
	// proxyFilterChainCh is the channel on which proxies filter chains are made available.
	proxyFilterChainCh chan filterchain.ProxyFilterChain
	// clock is used for time and timers.
	clock clock.Clock
}

// NewProvider returns a new provider.
func NewProvider(
	logger *log.Logger,
	clock clock.Clock,
	podLister v1.PodLister,
	proxyRefreshInterval time.Duration) *Provider {
	return &Provider{
		logger:               logger,
		clock:                clock,
		podLister:            podLister,
		proxyRefreshInterval: proxyRefreshInterval,
		proxyFilterChainCh:   make(chan filterchain.ProxyFilterChain, 1000),
	}
}

// Run is a blocking function that periodically checks proxy pod annotations on
// and generates new filter chain for them as needed.
func (p *Provider) Run(ctx context.Context) <-chan filterchain.ProxyFilterChain {
	go p.run(ctx)
	return p.proxyFilterChainCh
}

func (p *Provider) run(ctx context.Context) {
	defer close(p.proxyFilterChainCh)

	ticker := p.clock.NewTicker(p.proxyRefreshInterval)
	defer ticker.Stop()

	proxies := make(map[string]*proxyPod)
	for {
		select {
		case <-ticker.C():
			pods, err := p.podLister.List(labels.Everything())
			if err != nil {
				p.logger.WithError(err).Warn("failed to list pods")
				continue
			}

			for i := range pods {
				pod := pods[i]

				// If this is not a proxy pod ignore it.
				if pod.Labels[labelKeyRole] != labelProxy {
					continue
				}

				proxy, existingProxy := proxies[pod.Name]
				if !existingProxy {
					proxy = &proxyPod{
						podID:                pod.Name,
						latestPodAnnotations: map[string]string{},
					}
					proxies[pod.Name] = proxy
				}

				currAnnotations := map[string]string{}
				for _, key := range relevantAnnotations {
					if value, found := pod.Annotations[key]; found {
						currAnnotations[key] = value
					}
				}

				if existingProxy && reflect.DeepEqual(proxy.latestPodAnnotations, currAnnotations) {
					// Nothing has changed so no update
					continue
				}

				proxy.latestPodAnnotations = currAnnotations

				proxyFilterChain, err := createFilterChainForProxy(currAnnotations)
				if err != nil {
					p.logger.WithError(err).WithFields(log.Fields{
						"proxy_id": proxy.podID,
					}).Warn("Failed to create filter chain. Skipping update.")
					continue
				}

				p.proxyFilterChainCh <- filterchain.ProxyFilterChain{
					ProxyID:     proxy.podID,
					FilterChain: proxyFilterChain,
				}
			}
		case <-ctx.Done():
			p.logger.Debug("Exiting run loop due to context cancelled")
			return
		}
	}
}

func createFilterChainForProxy(podAnnotations map[string]string) (*envoylistener.FilterChain, error) {
	var filters []*envoylistener.Filter

	debugEnabled := podAnnotations[annotationKeyDebug] == "true"
	if debugEnabled {
		filter, err := filterchain.CreateXdsFilter(
			filters2.DebugFilterName,
			&debugfilterv1alpha.Debug{
				Id: &wrapperspb.StringValue{Value: "debug-filter"},
			},
		)
		if err != nil {
			return nil, err
		}

		filters = append(filters, filter)
	}

	return &envoylistener.FilterChain{Filters: filters}, nil
}
