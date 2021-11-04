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

package agones

import (
	"os"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	agonesv1 "agones.dev/agones/pkg/apis/agones/v1"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	servertesting "quilkin.dev/xds-management-server/pkg/testing"
)

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

func setListGameServers(mock *servertesting.Mocks, gs ...agonesv1.GameServer) {
	mock.AgonesClient.AddReactor("list", "gameservers", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &agonesv1.GameServerList{Items: gs}, nil
	})
}

func TestGetEndpointsFromStoreEndpointInfo(t *testing.T) {
	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)
	m := servertesting.NewMocks()

	gs1 := testGameServer("gs-1")
	gs1.Status.State = agonesv1.GameServerStateCreating

	gs2 := testGameServer("gs-2")
	gs2.Annotations["quilkin.dev/tokens"] = "abc,xyz,ijk"
	gs2.Status.Ports[0].Port = 22
	gs2.Status.Address = "127.0.0.2"

	setListGameServers(m, *gs1, *gs2)

	gsInformer := m.AgonesInformerFactory.Agones().V1().GameServers().Informer()
	_, cancel := m.StartInformers(t, gsInformer.HasSynced)
	defer cancel()
	store := gsInformer.GetStore()

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
	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)
	m := servertesting.NewMocks()

	gs1, gs2 := testGameServer("gs-1"), testGameServer("gs-2")
	gs1.Status.Ports[0].Port = 21
	gs2.Status.Ports[0].Port = 22
	gs3 := testGameServer("gs-3")
	gs3.Status.State = agonesv1.GameServerStateCreating

	setListGameServers(m, *gs1, *gs2)

	gsInformer := m.AgonesInformerFactory.Agones().V1().GameServers().Informer()
	_, cancel := m.StartInformers(t, gsInformer.HasSynced)
	defer cancel()

	store := gsInformer.GetStore()

	endpoints := getEndpointsFromStore(logger, store)
	require.Len(t, endpoints, 2)

	require.EqualValues(t, 21, endpoints[0].Port)
	require.EqualValues(t, 22, endpoints[1].Port)
}

func TestGetEndpointsFromStoreIgnoredGameServers(t *testing.T) {
	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)
	m := servertesting.NewMocks()

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

	setListGameServers(m, *emptyStatus, *missingAddress, *nonAllocated, *noPorts, *testGameServer("gs-valid"))

	gsInformer := m.AgonesInformerFactory.Agones().V1().GameServers().Informer()
	_, cancel := m.StartInformers(t, gsInformer.HasSynced)
	defer cancel()

	store := gsInformer.GetStore()
	endpoints := getEndpointsFromStore(logger, store)
	require.Len(t, endpoints, 1)
}
