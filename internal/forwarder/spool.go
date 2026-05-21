package forwarder

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/razatechofficial/edr/internal/alert"
	"github.com/razatechofficial/edr/internal/schema"
)

// AppendSpool appends one OCSF alert line for later replay.
func AppendSpool(path string, a schema.Alert) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := alert.MarshalOCSF(a, "")
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// DrainSpool reads spool lines, calls send for each; failed lines are rewritten back.
func DrainSpool(path string, send func(schema.Alert) error) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return os.Remove(path)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	var failed []schema.Alert
	for sc.Scan() {
		var ocsfDoc map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ocsfDoc); err != nil {
			continue
		}
		a := schema.Alert{OCSF: ocsfDoc}
		if err := send(a); err != nil {
			failed = append(failed, a)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(failed) == 0 {
		return os.Remove(path)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, a := range failed {
		line, err := alert.MarshalOCSF(a, "")
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}
