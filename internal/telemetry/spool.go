package telemetry

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"
	"go.uber.org/zap"
)

// Spool provides durable offline buffering backed by BadgerDB. Events are
// written with monotonically-increasing sequence keys so that reads always
// return the oldest entries first.
type Spool struct {
	db     *badger.DB
	logger *zap.Logger
	seq    atomic.Uint64

	closeOnce sync.Once
	closed    chan struct{}
}

// NewSpool opens (or creates) a BadgerDB-backed spool at the given directory.
// A background goroutine runs BadgerDB value-log GC periodically.
func NewSpool(dir string, logger *zap.Logger) (*Spool, error) {
	opts := badger.DefaultOptions(dir).
		WithLogger(nil).
		WithValueLogFileSize(64 << 20)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}

	s := &Spool{
		db:     db,
		logger: logger,
		closed: make(chan struct{}),
	}

	if err := s.initSequence(); err != nil {
		_ = db.Close()
		return nil, err
	}

	go s.gcLoop()
	return s, nil
}

// Write appends a payload to the spool with the next sequence number.
func (s *Spool) Write(batch []byte) error {
	key := s.nextKey()
	return s.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(key, batch).WithMeta(0)
		return txn.SetEntry(e)
	})
}

// Read returns the oldest `limit` entries without removing them.
func (s *Spool) Read(limit int) ([][]byte, error) {
	var results [][]byte
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = limit
		it := txn.NewIterator(opts)
		defer it.Close()

		count := 0
		for it.Rewind(); it.Valid() && count < limit; it.Next() {
			item := it.Item()
			val, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			results = append(results, val)
			count++
		}
		return nil
	})
	return results, err
}

// Ack removes the given keys from the spool, indicating successful delivery.
func (s *Spool) Ack(keys [][]byte) error {
	return s.db.Update(func(txn *badger.Txn) error {
		for _, k := range keys {
			if err := txn.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// ReadKeys returns the oldest `limit` key-value pairs so that callers can Ack
// by key after successful processing.
func (s *Spool) ReadKeys(limit int) (keys [][]byte, values [][]byte, err error) {
	err = s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = limit
		it := txn.NewIterator(opts)
		defer it.Close()

		count := 0
		for it.Rewind(); it.Valid() && count < limit; it.Next() {
			item := it.Item()
			k := item.KeyCopy(nil)
			v, verr := item.ValueCopy(nil)
			if verr != nil {
				return verr
			}
			keys = append(keys, k)
			values = append(values, v)
			count++
		}
		return nil
	})
	return
}

// Close shuts down the spool and its background GC goroutine.
func (s *Spool) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		err = s.db.Close()
	})
	return err
}

func (s *Spool) initSequence() error {
	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()

		it.Rewind()
		if it.Valid() {
			key := it.Item().Key()
			if len(key) == 8 {
				s.seq.Store(binary.BigEndian.Uint64(key))
			}
		}
		return nil
	})
}

func (s *Spool) nextKey() []byte {
	n := s.seq.Add(1)
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, n)
	return key
}

func (s *Spool) gcLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			for s.db.RunValueLogGC(0.5) == nil {
			}
		}
	}
}
