package memstore

// This is a demo package.. please dont use except for testing of the
// consumers of the SimpleStpre interface

import (
	"time"
)

type Index struct {
	Key      string
	DataType int
}

type MemDatum struct {
	Data       string
	Expiration int64
}

type MemStore struct {
	mstore map[Index]MemDatum
}

func New() *MemStore {
	var mstore MemStore
	mstore.mstore = make(map[Index]MemDatum)
	return &mstore
}

func (ms *MemStore) UpsertSigned(key string, dataType int, expiration int64, data string) error {
	datum := MemDatum{Data: data, Expiration: expiration}
	index := Index{Key: key, DataType: dataType}
	ms.mstore[index] = datum
	return nil
}
func (ms *MemStore) DeleteSigned(key string, dataType int) error {
	index := Index{Key: key, DataType: dataType}
	delete(ms.mstore, index)
	return nil
}
func (ms *MemStore) GetSigned(key string, dataType int) (bool, string, error) {
	index := Index{Key: key, DataType: dataType}
	datum, ok := ms.mstore[index]
	if !ok {
		return false, "", nil
	}
	if datum.Expiration < time.Now().Unix() {
		delete(ms.mstore, index)
		return false, "", nil
	}
	return true, datum.Data, nil
}
