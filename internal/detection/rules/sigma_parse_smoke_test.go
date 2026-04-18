package rules

import (
	"os"
	"path/filepath"
	"testing"

	sigma "github.com/bradleyjkemp/sigma-go"
)

func TestSigmaRulesParse(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "rules", "sigma")
	var bad []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch filepath.Ext(path) {
		case ".yml", ".yaml":
		default:
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: read: %v", path, err)
			return nil
		}
		if _, err := sigma.ParseRule(b); err != nil {
			bad = append(bad, path+": "+err.Error())
		}
		return nil
	})
	for _, s := range bad {
		t.Error(s)
	}
}
