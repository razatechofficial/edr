//go:build windows

package collector

import (
	"crypto/md5"
	"debug/pe"
	"encoding/hex"
	"os"
	"sort"
	"strings"
)

// impHashFromImportedSymbols builds a Mandiant-style imphash from debug/pe
// ImportedSymbols entries, which use the "SymbolName:library.dll" form.
func impHashFromImportedSymbols(syms []string) string {
	entries := make([]string, 0, len(syms))
	for _, s := range syms {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			continue
		}
		fn, dll := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if fn == "" || dll == "" {
			continue
		}
		entries = append(entries, strings.ToLower(dll)+"."+strings.ToLower(fn))
	}
	sort.Strings(entries)
	sum := md5.Sum([]byte(strings.Join(entries, ",")))
	return hex.EncodeToString(sum[:])
}

// ComputeImpHash returns the MD5 imphash of a PE file's import table.
func ComputeImpHash(path string) (string, error) {
	r, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer r.Close()
	pf, err := pe.NewFile(r)
	if err != nil {
		return "", err
	}
	defer pf.Close()
	syms, err := pf.ImportedSymbols()
	if err != nil {
		return "", err
	}
	if len(syms) == 0 {
		return impHashFromImportedSymbols(nil), nil
	}
	return impHashFromImportedSymbols(syms), nil
}

// ImphashPEFile returns ComputeImpHash(path) or empty on error.
func ImphashPEFile(path string) string {
	h, _ := ComputeImpHash(path)
	return h
}
