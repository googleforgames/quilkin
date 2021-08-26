package k8s

import (
	"context"
	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/wrapperspb"
	k8scorev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	informersv1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"quilkin.dev/xds-management-server/pkg/filterchain"
	filters2 "quilkin.dev/xds-management-server/pkg/filters"
	debugfilterv1alpha "quilkin.dev/xds-management-server/pkg/filters/debug/v1alpha1"
	"reflect"
	"time"
)

const (
	annotationKeyPrefix    = "quilkin.dev/"
	labelKeyRole           = annotationKeyPrefix + "role"
	annotationKeyDebug     = annotationKeyPrefix + "debug-packets"
	labelSelectorProxyRole = labelKeyRole + "=proxy"
	defaultProxyNamespace  = "quilkin"
)

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

type Provider struct {
	logger   *log.Logger
	podStore cache.Store
}

func NewProvider(
	ctx context.Context,
	logger *log.Logger,
	k8sClient kubernetes.Interface,
	podNamespace string) (*Provider, error) {
	podInformer := informersv1.NewFilteredPodInformer(k8sClient, podNamespace, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, func(options *metav1.ListOptions) {
		options.LabelSelector = labelSelectorProxyRole
	})
	go podInformer.Run(ctx.Done())

	return &Provider{
		logger:   logger,
		podStore: podInformer.GetStore(),
	}, nil
}

func (p *Provider) Run(
	ctx context.Context,
	proxyRefreshInterval time.Duration,
) <-chan filterchain.ProxyFilterChain {
	proxyFilterChainCh := make(chan filterchain.ProxyFilterChain, 1000)
	go p.run(ctx, p.logger, proxyRefreshInterval, proxyFilterChainCh)
	return proxyFilterChainCh
}
func (p *Provider) run(
	ctx context.Context,
	logger *log.Logger,
	proxyRefreshInterval time.Duration,
	proxyFilterChainCh chan<- filterchain.ProxyFilterChain,
) {
	defer close(proxyFilterChainCh)

	ticker := time.NewTicker(proxyRefreshInterval)
	defer ticker.Stop()

	proxies := make(map[string]*proxyPod)
	for {
		select {
		case <-ticker.C:
			pods := p.podStore.List()
			for i := range pods {
				pod := pods[i].(*k8scorev1.Pod)

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

				if !existingProxy && reflect.DeepEqual(proxy.latestPodAnnotations, currAnnotations) {
					// Nothing has changed so no update
					continue
				}

				proxy.latestPodAnnotations = currAnnotations

				proxyFilterChain, err := createFilterChainForProxy(currAnnotations)
				if err != nil {
					logger.WithError(err).WithFields(log.Fields{
						"proxy_id": proxy.podID,
					}).Warn("Failed to create filter chain. Skipping update.")
					continue
				}

				proxyFilterChainCh <- filterchain.ProxyFilterChain{
					ProxyID:     proxy.podID,
					FilterChain: proxyFilterChain,
				}
			}
		case <-ctx.Done():
			logger.Debug("Exiting run loop due to context cancelled")
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
				// TODO: use uuid
				Id: &wrapperspb.StringValue{Value: "quilkin-filter-debug"},
			},
		)
		if err != nil {
			return nil, err
		}

		filters = append(filters, filter)
	}

	return &envoylistener.FilterChain{Filters: filters}, nil
}
