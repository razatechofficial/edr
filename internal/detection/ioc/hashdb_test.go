package ioc

import "testing"

func TestHashDBAddLookup(t *testing.T) {
	t.Parallel()
	db := NewHashDB()
	db.Add(HashEntry{
		Hash:          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Type:          HashSHA256,
		MalwareFamily: "EmptyHash",
		Severity:      "high",
	})
	entry, found := db.Lookup("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if !found {
		t.Fatal("Lookup returned false, want true")
	}
	if entry.MalwareFamily != "EmptyHash" {
		t.Errorf("MalwareFamily = %q, want %q", entry.MalwareFamily, "EmptyHash")
	}
}

func TestHashDBLookupMiss(t *testing.T) {
	t.Parallel()
	db := NewHashDB()
	_, found := db.Lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if found {
		t.Error("Lookup returned true for non-existent hash")
	}
}

func TestHashDBBloomPreFilter(t *testing.T) {
	t.Parallel()
	db := NewHashDB()
	db.Add(HashEntry{
		Hash: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
		Type: HashSHA256,
	})

	_, found := db.Lookup("0000000000000000000000000000000000000000000000000000000000000000")
	if found {
		t.Error("expected miss for hash not in bloom filter")
	}
}

func TestHashDBMultipleTypes(t *testing.T) {
	t.Parallel()
	db := NewHashDB()

	entries := []HashEntry{
		{Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Type: HashSHA256, MalwareFamily: "sha256-fam"},
		{Hash: "da39a3ee5e6b4b0d3255bfef95601890afd80709", Type: HashSHA1, MalwareFamily: "sha1-fam"},
		{Hash: "d41d8cd98f00b204e9800998ecf8427e", Type: HashMD5, MalwareFamily: "md5-fam"},
	}
	for _, e := range entries {
		db.Add(e)
	}

	tests := []struct {
		hash   string
		family string
	}{
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256-fam"},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1-fam"},
		{"d41d8cd98f00b204e9800998ecf8427e", "md5-fam"},
	}
	for _, tc := range tests {
		entry, found := db.Lookup(tc.hash)
		if !found {
			t.Errorf("Lookup(%s) miss", tc.hash[:16])
			continue
		}
		if entry.MalwareFamily != tc.family {
			t.Errorf("MalwareFamily = %q, want %q", entry.MalwareFamily, tc.family)
		}
	}
}

func TestHashDBCount(t *testing.T) {
	t.Parallel()
	db := NewHashDB()
	db.Add(HashEntry{Hash: "aaa", Type: HashSHA256})
	db.Add(HashEntry{Hash: "bbb", Type: HashSHA1})
	db.Add(HashEntry{Hash: "ccc", Type: HashMD5})
	if got := db.Count(); got != 3 {
		t.Errorf("Count() = %d, want 3", got)
	}
}

func TestHashDBClear(t *testing.T) {
	t.Parallel()
	db := NewHashDB()
	db.Add(HashEntry{Hash: "aaa", Type: HashSHA256})
	db.Add(HashEntry{Hash: "bbb", Type: HashSHA1})
	db.Clear()
	if got := db.Count(); got != 0 {
		t.Errorf("Count() after Clear = %d, want 0", got)
	}
	if _, found := db.Lookup("aaa"); found {
		t.Error("Lookup succeeded after Clear")
	}
}
