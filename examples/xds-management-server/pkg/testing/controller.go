package testing

import (
	"context"
	"testing"
	"time"

	agonesfake "agones.dev/agones/pkg/client/clientset/versioned/fake"
	"agones.dev/agones/pkg/client/informers/externalversions"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// Mocks contains fake kubernetes clients
type Mocks struct {
	K8sClient             *k8sfake.Clientset
	K8sInformerFactory    informers.SharedInformerFactory
	AgonesClient          *agonesfake.Clientset
	AgonesInformerFactory externalversions.SharedInformerFactory
}

// NewMocks returns a new mock instance.
func NewMocks() *Mocks {
	k8sClient := &k8sfake.Clientset{}
	agonesClient := &agonesfake.Clientset{}
	return &Mocks{
		K8sClient:             k8sClient,
		K8sInformerFactory:    informers.NewSharedInformerFactory(k8sClient, 30*time.Second),
		AgonesClient:          agonesClient,
		AgonesInformerFactory: externalversions.NewSharedInformerFactory(agonesClient, 30*time.Second),
	}
}

// StartInformers starts the mock's informers
func (m *Mocks) StartInformers(t *testing.T, sync ...cache.InformerSynced) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	m.K8sInformerFactory.Start(ctx.Done())
	m.AgonesInformerFactory.Start(ctx.Done())

	require.True(t, cache.WaitForCacheSync(
		ctx.Done(),
		sync...,
	))
	return ctx, cancel
}
