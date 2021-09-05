package k8s

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	//  load the gcp plugin (required to authenticate against GKE clusters from outside the cluster)
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

// GetK8sConfig finds and returns a kubernetes config
func GetK8sConfig() (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	return kubeConfig.ClientConfig()
}

// CreateClient returns a kubernetes client for the provided config.
func CreateClient(config *rest.Config) (*kubernetes.Clientset, error) {
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s clientset: %w", err)
	}

	return k8sClient, nil
}
