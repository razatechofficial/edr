package features

import (
	"time"
)

const (
	// TransformerMaxSeq is the maximum sequence length for the transformer.
	TransformerMaxSeq = 512
)

// TransformerFeatureExtractor encodes event windows for the behavioral
// transformer model, supporting variable-length sequences up to
// TransformerMaxSeq events with relative time delta encoding.
type TransformerFeatureExtractor struct {
	maxSeq int
}

// NewTransformerFeatureExtractor creates a new extractor with the given
// maximum sequence length.
func NewTransformerFeatureExtractor(maxSeq int) *TransformerFeatureExtractor {
	if maxSeq <= 0 || maxSeq > TransformerMaxSeq {
		maxSeq = TransformerMaxSeq
	}
	return &TransformerFeatureExtractor{maxSeq: maxSeq}
}

// Extract encodes a variable-length event window into a flat float32 slice
// of shape (actual_len * FeaturesPerEvent). The transformer model handles
// variable lengths via dynamic ONNX axes.
func (t *TransformerFeatureExtractor) Extract(events []interface{}) []float32 {
	n := len(events)
	if n > t.maxSeq {
		events = events[n-t.maxSeq:]
		n = t.maxSeq
	}
	if n == 0 {
		return make([]float32, FeaturesPerEvent)
	}

	result := make([]float32, n*FeaturesPerEvent)
	var prevTime time.Time

	for i, evt := range events {
		offset := i * FeaturesPerEvent
		row := result[offset : offset+FeaturesPerEvent]

		eventType, procCat, privLevel, ts := classifyEvent(evt)

		if idx, ok := eventSubtypeIndex[eventType]; ok && idx < numEventSubtypes {
			row[idx] = 1.0
		}

		catIdx := processCategoryIndex[procCat]
		if catIdx < numProcessCats {
			row[numEventSubtypes+catIdx] = 1.0
		}

		privOffset := numEventSubtypes + numProcessCats
		switch privLevel {
		case "system":
			row[privOffset+2] = 1.0
		case "elevated":
			row[privOffset+1] = 1.0
		default:
			row[privOffset] = 1.0
		}

		flagBase := privOffset + numPrivLevels
		switch eventType {
		case "network_connect", "network_listen", "network_send", "network_receive":
			row[flagBase] = 1.0
		}
		switch eventType {
		case "file_write", "file_create":
			row[flagBase+1] = 1.0
		}
		switch eventType {
		case "registry_create", "registry_modify", "registry_delete":
			row[flagBase+2] = 1.0
		}

		if !ts.IsZero() {
			hour := ts.Hour()
			row[flagBase+3] = float32(hour) / 24.0

			dow := int(ts.Weekday())
			if dow < 7 {
				row[flagBase+4+dow] = 1.0
			}

			if !prevTime.IsZero() {
				delta := ts.Sub(prevTime).Seconds()
				if delta > 0 {
					row[flagBase+4+7] = LogScale(delta)
				}
			}
			prevTime = ts
		}
	}

	return result
}

// SequenceLength returns the actual number of events that would be encoded.
func (t *TransformerFeatureExtractor) SequenceLength(events []interface{}) int {
	n := len(events)
	if n > t.maxSeq {
		return t.maxSeq
	}
	return n
}

// classifyEvent extracts metadata from a raw event interface. This mirrors
// the logic in the LSTM extractor but returns structured components.
func classifyEvent(evt interface{}) (eventType, procCategory, privLevel string, ts time.Time) {
	eventType = "process_create"
	procCategory = "other"
	privLevel = "standard"

	type hasType interface{ GetType() string }
	type hasCategory interface{ GetCategory() string }
	type hasPrivilege interface{ GetPrivilegeLevel() string }
	type hasTimestamp interface{ GetTimestamp() time.Time }

	if t, ok := evt.(hasType); ok {
		eventType = t.GetType()
	}
	if c, ok := evt.(hasCategory); ok {
		procCategory = c.GetCategory()
	}
	if p, ok := evt.(hasPrivilege); ok {
		privLevel = p.GetPrivilegeLevel()
	}
	if ts2, ok := evt.(hasTimestamp); ok {
		ts = ts2.GetTimestamp()
	}

	return
}
