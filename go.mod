module github.com/razatechofficial/edr

go 1.26.0

require (
	github.com/bradleyjkemp/sigma-go v0.6.7-0.20250515115046-0c42bd984cf2
	github.com/cilium/ebpf v0.21.0
	github.com/dgraph-io/badger/v4 v4.9.1
	github.com/fsnotify/fsnotify v1.9.0
	github.com/go-viper/mapstructure/v2 v2.4.0
	github.com/google/cel-go v0.27.0
	github.com/google/uuid v1.6.0
	github.com/hillu/go-yara/v4 v4.3.4
	github.com/klauspost/compress v1.18.5
	github.com/philippgille/chromem-go v0.7.0
	github.com/prometheus/client_golang v1.23.2
	github.com/razatechofficial/xdr/api v0.0.0
	github.com/sashabaranov/go-openai v1.41.2
	github.com/segmentio/kafka-go v0.4.47
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	github.com/yalue/onnxruntime_go v1.27.0
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.27.1
	golang.org/x/crypto v0.51.0
	golang.org/x/sys v0.45.0
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cel.dev/expr v0.25.1 // indirect
	github.com/BobuSumisu/aho-corasick v1.0.3 // indirect
	github.com/PaesslerAG/gval v1.0.0 // indirect
	github.com/PaesslerAG/jsonpath v0.1.1 // indirect
	github.com/alecthomas/participle v0.7.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgraph-io/ristretto/v2 v2.2.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/flatbuffers v25.2.10+incompatible // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/exp v0.0.0-20240823005443-9b4947da3948 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

replace github.com/razatechofficial/xdr/api => ../server/api
