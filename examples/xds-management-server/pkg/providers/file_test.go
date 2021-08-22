package providers

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"quilkin.dev/xds-management-server/pkg/resources"
	"testing"
	"time"
)

func TestFileProviderRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	configFile, err := ioutil.TempFile("", "")
	require.NoError(t, err, "failed to create temp file")
	defer func() {
		_ = os.Remove(configFile.Name())
	}()

	p := NewFileProvider(configFile.Name())

	filterConfigTestData := `
name: my-filter
typed_config:
  '@type': quilkin.filter.MyFilter
  id: hello
`
	filterConfigTestDataYaml := map[interface{}]interface{}{
		"typed_config": map[interface{}]interface{}{
			"@type": "quilkin.filter.MyFilter",
			"id":    "hello",
		},
	}
	require.NoError(t, yaml.Unmarshal([]byte(filterConfigTestData), filterConfigTestDataYaml), "failed to unmarshal test data filter config")

	logger := &log.Logger{}
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)

	resourcesCh, errorCh := p.Run(ctx, logger)
	tests := []struct {
		name   string
		config string
		want   resources.Resources
	}{
		{
			name: "add initial config",
			config: `
clusters:
- name: cluster-a
  endpoints:
  - ip: 127.0.0.1
    port: 8080
    metadata:
      'quilkin.dev':
        tokens:
        - MXg3aWp5Ng==
`,
			want: resources.Resources{
				Clusters: []resources.Cluster{
					{
						Name: "cluster-a",
						Endpoints: []resources.Endpoint{{
							IP:   "127.0.0.1",
							Port: 8080,
							Metadata: map[string]interface{}{
								"quilkin.dev": map[interface{}]interface{}{
									"tokens": []interface{}{"MXg3aWp5Ng=="},
								},
							},
						}},
					},
				},
			},
		},
		{
			name: "update config 1 - add new cluster",
			config: `
clusters:
- name: cluster-a
  endpoints:
  - ip: 127.0.0.1
    port: 8080
    metadata:
      'quilkin.dev':
        tokens:
        - MXg3aWp5Ng==
- name: cluster-b
  endpoints:
  - ip: 127.0.0.2
    port: 8082
`,
			want: resources.Resources{
				Clusters: []resources.Cluster{
					{
						Name: "cluster-a",
						Endpoints: []resources.Endpoint{{
							IP:   "127.0.0.1",
							Port: 8080,
							Metadata: map[string]interface{}{
								"quilkin.dev": map[interface{}]interface{}{
									"tokens": []interface{}{"MXg3aWp5Ng=="},
								},
							},
						}},
					},
					{
						Name: "cluster-b",
						Endpoints: []resources.Endpoint{{
							IP:   "127.0.0.2",
							Port: 8082,
						}},
					},
				},
			},
		},
		{
			name: "update config 2 - remove cluster, add filter",
			config: `
clusters:
- name: cluster-b
  endpoints:
  - ip: 127.0.0.2
    port: 8082
filterchain:
- name: my-filter
  typed_config:
    '@type': quilkin.filter.MyFilter
    id: hello
`,
			want: resources.Resources{
				Clusters: []resources.Cluster{
					{
						Name: "cluster-b",
						Endpoints: []resources.Endpoint{{
							IP:   "127.0.0.2",
							Port: 8082,
						}},
					},
				},
				FilterChain: []resources.FilterConfig{filterConfigTestDataYaml},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, ioutil.WriteFile(configFile.Name(), []byte(tt.config), 0644))

			select {
			case r := <-resourcesCh:
				require.EqualValues(t, tt.want, r)
			case err := <-errorCh:
				require.NoError(t, err, "received error from provider")
			}
		})
	}

	// Cancel the context to shutdown the provider.
	cancel()

	// Then check for any errors or unexpected resource updates.
	err, ok := <-errorCh
	require.False(t, ok, "received error from provider at shutdown: %v", err)

	update, ok := <-resourcesCh
	require.False(t, ok, "received unexpected resource update %v", update)
}
