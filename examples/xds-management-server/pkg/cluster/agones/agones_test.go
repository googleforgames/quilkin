package agones

import (
	"os"
	"sync"
	"testing"

	agonesv1 "agones.dev/agones/pkg/apis/agones/v1"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type testStore struct {
	mu    *sync.Mutex
	items []interface{}
}

func newTestGameServerStore() *testStore {
	return &testStore{
		mu: &sync.Mutex{},
	}
}

func (s *testStore) Set(items []interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items = items
}
func (s *testStore) List() []interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.items
}

func (s *testStore) Add(_ interface{}) error {
	panic("NotImplemented")
}
func (s *testStore) Update(_ interface{}) error {
	panic("NotImplemented")
}
func (s *testStore) Delete(_ interface{}) error {
	panic("NotImplemented")
}
func (s *testStore) ListKeys() []string {
	panic("NotImplemented")
}
func (s *testStore) Get(_ interface{}) (item interface{}, exists bool, err error) {
	panic("NotImplemented")
}
func (s *testStore) GetByKey(_ string) (item interface{}, exists bool, err error) {
	panic("NotImplemented")
}
func (s *testStore) Replace([]interface{}, string) error {
	panic("NotImplemented")
}
func (s *testStore) Resync() error {
	panic("NotImplemented")
}

const defaultGameServerPort = 73

func testGameServer(name string) *agonesv1.GameServer {
	return &agonesv1.GameServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   "gameservers",
			Annotations: make(map[string]string),
		},
		Status: agonesv1.GameServerStatus{
			Address: "127.0.0.1",
			State:   agonesv1.GameServerStateAllocated,
			Ports: []agonesv1.GameServerStatusPort{{
				Name: "of miami",
				Port: defaultGameServerPort,
			}},
		},
	}
}

func TestGetEndpointsFromStoreEndpointInfo(t *testing.T) {
	store := newTestGameServerStore()

	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)

	require.Empty(t, getEndpointsFromStore(logger, store))

	gs := testGameServer("gs-2")
	gs.Annotations["quilkin.dev/tokens"] = "abc,xyz,ijk"
	gs.Status.Ports[0].Port = 22
	gs.Status.Address = "127.0.0.2"

	store.Set([]interface{}{
		&agonesv1.GameServer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "gs-1",
				Namespace: "gameservers",
			},
		},
		gs,
	})

	endpoints := getEndpointsFromStore(logger, store)
	require.Len(t, endpoints, 1)

	ep := endpoints[0]

	require.EqualValues(t, 22, ep.Port)
	require.EqualValues(t, "127.0.0.2", ep.IP)

	expectedTokens := map[string]interface{}{
		"quilkin.dev": map[string]interface{}{
			"tokens": []string{
				"abc",
				"xyz",
				"ijk",
			},
		},
	}
	require.EqualValues(t, expectedTokens, ep.Metadata)
}

func TestGetEndpointsFromStoreMultipleEndpoints(t *testing.T) {
	store := newTestGameServerStore()

	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)

	gs1, gs2 := testGameServer("gs-1"), testGameServer("gs-2")
	gs1.Status.Ports[0].Port = 21
	gs2.Status.Ports[0].Port = 22

	store.Set([]interface{}{
		gs1,
		&agonesv1.GameServer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "gs-1",
				Namespace: "gameservers",
			},
		},
		gs2,
	})

	endpoints := getEndpointsFromStore(logger, store)
	require.Len(t, endpoints, 2)

	require.EqualValues(t, 21, endpoints[0].Port)
	require.EqualValues(t, 22, endpoints[1].Port)
}

func TestGetEndpointsFromStoreIgnoredGameServers(t *testing.T) {
	store := newTestGameServerStore()

	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)

	emptyStatus := &agonesv1.GameServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gs-1",
			Namespace: "gameservers",
		},
	}

	missingAddress := testGameServer("gs-missing-address")
	missingAddress.Status.Address = ""

	nonAllocated := testGameServer("gs-non-allocated")
	nonAllocated.Status.State = agonesv1.GameServerStateReady

	noPorts := testGameServer("gs-no-ports")
	noPorts.Status.Ports = []agonesv1.GameServerStatusPort{}

	for _, gs := range []*agonesv1.GameServer{
		emptyStatus, missingAddress, nonAllocated, noPorts,
	} {
		store.Set([]interface{}{gs})
		require.Empty(t, getEndpointsFromStore(logger, store))
	}

	store.Set([]interface{}{testGameServer("gs-valid")})
	endpoints := getEndpointsFromStore(logger, store)
	require.Len(t, endpoints, 1)
}
