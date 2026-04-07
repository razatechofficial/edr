package observability

import "github.com/prometheus/client_golang/prometheus"

var (
	ThreatIntelIngested = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_threatintel_ingested_total",
			Help: "Total ingested threat intel indicators by source.",
		},
		[]string{"source"},
	)
)

func init() {
	prometheus.MustRegister(ThreatIntelIngested)
}
