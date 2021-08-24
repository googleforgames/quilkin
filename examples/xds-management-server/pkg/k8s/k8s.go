package k8s

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"

	//  load the gcp plugin (required to authenticate against GKE clusters from outside the cluster)
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

// GetK8sConfig finds and returns a kubernetes config
func GetK8sConfig(logger *log.Logger, kubeHost string) (*rest.Config, error) {
	var restConfig *rest.Config
	var err error

	if kubeHost == "local" {
		return clientcmd.BuildConfigFromFlags("", "/home/iffy/.kube/config")
	} else if kubeHost == "cluster" {
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize in-cluster config: %w", err)
		}
		return restConfig, nil
	} else {
		if kubeConfig := os.Getenv("KUBE_CONFIG"); kubeConfig != "" {
			if restConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfig); err == nil {
				return restConfig, nil
			} else {
				logger.WithError(err).Warn("failed to load kube config, will use empty configuration")
				return &rest.Config{
					Host: kubeHost,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no kube config was found")
}

// CreateClient returns a kubernetes client for the provided config.
func CreateClient(config *rest.Config) (*kubernetes.Clientset, error) {
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s clientset: %w", err)
	}

	return k8sClient, nil
}
