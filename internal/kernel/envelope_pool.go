package kernel

import "sync"

// envelopePool reuses map[string]interface{} envelopes across event
// callbacks (P2-9). Each event used to allocate a fresh map (and the
// Go runtime then garbage-collected it), which showed up as
// runtime.makemap_small / runtime.mapassign in profiles at sustained
// 100k events/sec.
//
// Usage:
//
//	env := getEnvelope()
//	defer putEnvelope(env)
//	env["k"] = v
//	json.Marshal(env)
//
// Callers MUST NOT retain the map after putEnvelope. The pool clears
// the map on release so map keys do not leak between events.
var envelopePool = sync.Pool{
	New: func() any {
		// Start with a generous default. Most envelopes carry 12-18
		// keys; starting at 16 keeps the runtime from immediately
		// rehashing.
		return make(map[string]interface{}, 16)
	},
}

// getEnvelope returns a cleared envelope map ready to be filled.
func getEnvelope() map[string]interface{} {
	return envelopePool.Get().(map[string]interface{})
}

// putEnvelope returns an envelope to the pool after clearing all
// entries so the next caller sees a clean map. nil maps are silently
// dropped.
func putEnvelope(m map[string]interface{}) {
	if m == nil {
		return
	}
	for k := range m {
		delete(m, k)
	}
	envelopePool.Put(m)
}
