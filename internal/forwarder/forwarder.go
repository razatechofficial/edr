package forwarder

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/razatechofficial/edr/internal/schema"
)

type Forwarder interface {
	Send(alert schema.Alert) error
}

func New(mode, endpoint string, logger *slog.Logger) (Forwarder, error) {
	switch mode {
	case "http":
		return &httpForwarder{endpoint: endpoint, cli: &http.Client{}}, nil
	case "syslog":
		return &noopForwarder{logger: logger, mode: "syslog"}, nil
	case "kafka":
		return &noopForwarder{logger: logger, mode: "kafka"}, nil
	default:
		return nil, errors.New("unsupported forwarder mode")
	}
}

type httpForwarder struct {
	endpoint string
	cli      *http.Client
}

func (h *httpForwarder) Send(alert schema.Alert) error {
	body, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return errors.New("forward failed with non-2xx status")
	}
	return nil
}

type noopForwarder struct {
	logger *slog.Logger
	mode   string
}

func (n *noopForwarder) Send(alert schema.Alert) error {
	n.logger.Info("forwarder stub send", "mode", n.mode, "alert_id", alert.AlertID)
	return nil
}
