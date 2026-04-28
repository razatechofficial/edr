package main

import (
	"context"
	"log/slog"

	"go.uber.org/zap"
)

type zapSlogHandler struct {
	logger *zap.Logger
	attrs  []slog.Attr
}

func (h *zapSlogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.logger != nil
}

func (h *zapSlogHandler) Handle(_ context.Context, r slog.Record) error {
	if h.logger == nil {
		return nil
	}
	fields := make([]zap.Field, 0, len(h.attrs)+r.NumAttrs())
	for _, a := range h.attrs {
		fields = append(fields, zap.Any(a.Key, a.Value.Any()))
	}
	r.Attrs(func(a slog.Attr) bool {
		fields = append(fields, zap.Any(a.Key, a.Value.Any()))
		return true
	})
	switch {
	case r.Level >= slog.LevelError:
		h.logger.Error(r.Message, fields...)
	case r.Level >= slog.LevelWarn:
		h.logger.Warn(r.Message, fields...)
	case r.Level <= slog.LevelDebug:
		h.logger.Debug(r.Message, fields...)
	default:
		h.logger.Info(r.Message, fields...)
	}
	return nil
}

func (h *zapSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &cp
}

func (h *zapSlogHandler) WithGroup(_ string) slog.Handler {
	return h
}
