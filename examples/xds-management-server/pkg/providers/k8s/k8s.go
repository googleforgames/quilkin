package k8s

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/fields"
	"os"
	"quilkin.dev/xds-management-server/pkg/providers/cds"
	"quilkin.dev/xds-management-server/pkg/resources"
	"reflect"
	"strings"
	"time"

	agonesv1 "agones.dev/agones/pkg/apis/agones/v1"
	agones "agones.dev/agones/pkg/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type Config struct {
	KubeHost                string
	GameServersNamespace    string
	GameServersPollInterval time.Duration
}

type ResourceProvider struct {
	cds *cds.AgonesCDS
}

func NewResourceProvider(logger *log.Logger, config Config) (*ResourceProvider, error) {
	agonesCDS, err := cds.NewAgonesCDS(logger, cds.Config{
		KubeHost:                config.KubeHost,
		GameServersNamespace:    config.GameServersNamespace,
		GameServersPollInterval: config.GameServersPollInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Agones CDS")
	}

	return &ResourceProvider{
		cds: agonesCDS,
	}, nil
}

func (p *ResourceProvider) Run(ctx context.Context, logger *log.Logger) (<-chan resources.Resources, <-chan error, error) {
	clusterCh, err := p.cds.Run(ctx, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run CDS: %w", err)
	}
	errorCh := make(chan error)
	// TODO:
	//  lds is per proxy?
	return resourcesCh, errorCh, nil
}

func fo(ctx context.Context, logger *log.Logger, config Config) error {
	var restConfig *rest.Config
	var err error

	if config.KubeHost == "cluster" {
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("failed to initialize in-cluster config: %w", err)
		}
	} else {
		restConfig = &rest.Config{
			Host: config.KubeHost,
		}

		if kubeConfig := os.Getenv("KUBE_CONFIG"); kubeConfig != "" {
			if cfg, err := clientcmd.BuildConfigFromFlags("", kubeConfig); err == nil {
				restConfig = cfg
			} else {
				logger.WithError(err).Warn("failed to load kube config, will use empty configuration")
			}
		}
	}

	_, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s clientset: %w", err)
	}

	agonesClient, err := agones.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create Agones clientset")
	}

	gameserverListWatch := cache.NewListWatchFromClient(
		agonesClient.AgonesV1().RESTClient(),
		"gameservers",
		config.GameServersNamespace,
		// TODO ONly watch those that are allocated!
		fields.Everything())

	gameserverInformer := cache.NewSharedInformer(gameserverListWatch, &agonesv1.GameServer{}, 0)
	gameserverStore := gameserverInformer.GetStore()

	go func() {
		var prevEndpoints []resources.Endpoint
		var endpoints []resources.Endpoint
		for {
			time.Sleep(config.GameServersPollInterval)

			gameservers := gameserverStore.List()
			for i := range gameservers {
				gs := gameservers[i].(*agonesv1.GameServer)

				gsLogger := logger.WithFields(log.Fields{
					"gameserver": gs.Name,
				})

				if gs.Status.State != agonesv1.GameServerStateAllocated {
					continue
				}

				if gs.Status.Address == "" {
					continue
				}

				numPorts := len(gs.Status.Ports)
				if numPorts == 0 {
					continue
				}

				gsPort := gs.Status.Ports[0]

				// TODO: What does this mean??
				if numPorts > 1 {
					gsLogger.Warnf("found %d ports: will pick the first one %v", numPorts, gsPort)
				}

				var metadata map[string]interface{}
				tokenStr, found := gs.Annotations["quilkin.dev/tokens"]
				if found {
					metadata = map[string]interface{}{
						// TODO is this map[interface] or map[string]
						"quilkin.dev": map[interface{}]interface{}{
							"tokens": strings.Split(tokenStr, ","),
						},
					}
				}

				endpoints = append(endpoints, resources.Endpoint{
					IP:       gs.Status.Address,
					Port:     int(gsPort.Port),
					Metadata: metadata,
				})
			}

			if len(endpoints) == 0 {
				continue
			}

			if reflect.DeepEqual(endpoints, prevEndpoints) {
				continue
			}

			// TODO send endpoint.
			prevEndpoints = endpoints
		}
	}()

	go gameserverInformer.Run(ctx.Done())

	return nil
}
