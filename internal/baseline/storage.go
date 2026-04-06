package baseline

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"go.uber.org/zap"
)

var baselineKey = []byte("baselines_v1")

// BaselineStorage provides durable persistence for baselines using BadgerDB.
// It runs a background goroutine that periodically flushes in-memory baselines
// to disk.
type BaselineStorage struct {
	db     *badger.DB
	logger *zap.Logger

	closeOnce sync.Once
	closed    chan struct{}
}

// NewBaselineStorage opens (or creates) the BadgerDB at dir.
func NewBaselineStorage(dir string, logger *zap.Logger) (*BaselineStorage, error) {
	opts := badger.DefaultOptions(dir).
		WithLogger(nil).
		WithValueLogFileSize(32 << 20)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}

	return &BaselineStorage{
		db:     db,
		logger: logger,
		closed: make(chan struct{}),
	}, nil
}

// Save serialises baselines and writes them to the store.
func (s *BaselineStorage) Save(baselines map[string]map[string]*Baseline) error {
	data, err := json.Marshal(baselines)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(baselineKey, data)
	})
}

// Load reads and deserialises previously-persisted baselines.
func (s *BaselineStorage) Load() (map[string]map[string]*Baseline, error) {
	var result map[string]map[string]*Baseline
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(baselineKey)
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &result)
		})
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		result = make(map[string]map[string]*Baseline)
	}
	return result, nil
}

// StartPeriodicSave begins persisting engine baselines every 5 minutes.
func (s *BaselineStorage) StartPeriodicSave(engine *BaselineEngine) {
	go s.persistLoop(engine)
}

// Close terminates background goroutines and closes the database.
func (s *BaselineStorage) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		err = s.db.Close()
	})
	return err
}

func (s *BaselineStorage) persistLoop(engine *BaselineEngine) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.closed:
			if err := s.Save(engine.Baselines()); err != nil {
				s.logger.Error("final baseline save failed", zap.Error(err))
			}
			return
		case <-ticker.C:
			if err := s.Save(engine.Baselines()); err != nil {
				s.logger.Error("periodic baseline save failed", zap.Error(err))
			} else {
				s.logger.Debug("baselines persisted")
			}
		}
	}
}
