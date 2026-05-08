package collector

// TCCRowChangeTag returns the posture tag for a TCC DB row transition: new keys
// are "tcc_added"; existing keys with a changed serialized value are "tcc_modified".
func TCCRowChangeTag(rowKeyExistedInPreviousSnapshot bool) string {
	if rowKeyExistedInPreviousSnapshot {
		return "tcc_modified"
	}
	return "tcc_added"
}
