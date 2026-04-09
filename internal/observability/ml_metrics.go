package observability

import "github.com/prometheus/client_golang/prometheus"

var (
	MLInferenceDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "edr_ml_inference_duration_seconds",
			Help:    "ML model inference latency in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms to ~4s
		},
		[]string{"model"},
	)

	MLScoreDistribution = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "edr_ml_score_distribution",
			Help:    "Distribution of ML model prediction scores.",
			Buckets: prometheus.LinearBuckets(0, 0.1, 11), // 0.0 to 1.0
		},
		[]string{"model"},
	)

	MLModelVersion = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "edr_ml_model_version",
			Help: "Currently loaded model version (label contains SHA256).",
		},
		[]string{"model", "sha256"},
	)

	MLDriftScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "edr_ml_drift_score",
			Help: "Feature/prediction drift score per model.",
		},
		[]string{"model", "drift_type"},
	)

	MLFeatureDriftScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "edr_ml_feature_drift_score",
			Help: "Feature drift score per model.",
		},
		[]string{"model"},
	)

	MLPredictionDriftScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "edr_ml_prediction_drift_score",
			Help: "Prediction drift score per model.",
		},
		[]string{"model"},
	)

	MLTruePositiveRate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "edr_ml_true_positive_rate",
			Help: "True positive rate from feedback loop.",
		},
		[]string{"model"},
	)

	MLFalsePositiveRate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "edr_ml_false_positive_rate",
			Help: "False positive rate from feedback loop.",
		},
		[]string{"model"},
	)

	MLInferenceTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_ml_inference_total",
			Help: "Total ML inference count by model and result.",
		},
		[]string{"model", "result"},
	)

	MLInferenceErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "edr_ml_inference_errors_total",
			Help: "Total ML inference errors by model.",
		},
		[]string{"model"},
	)
)

func init() {
	prometheus.MustRegister(
		MLInferenceDuration,
		MLScoreDistribution,
		MLModelVersion,
		MLDriftScore,
		MLFeatureDriftScore,
		MLPredictionDriftScore,
		MLTruePositiveRate,
		MLFalsePositiveRate,
		MLInferenceTotal,
		MLInferenceErrors,
	)
}
