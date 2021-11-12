module quilkin.dev/xds-management-server

go 1.14

require (
	agones.dev/agones v1.16.0
	github.com/alecthomas/kong v0.2.17
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/envoyproxy/go-control-plane v0.9.9
	github.com/fsnotify/fsnotify v1.4.9
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.5.2
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	google.golang.org/grpc v1.36.0
	google.golang.org/protobuf v1.26.0
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/api v0.22.3
	k8s.io/apimachinery v0.22.3
	k8s.io/client-go v0.22.3
	k8s.io/sample-controller v0.22.3
	sigs.k8s.io/yaml v1.2.0
)
