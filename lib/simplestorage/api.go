package simplestorage

// Simple is an interface type that defines how to store, retrieve and
// delete simple strings. Values are uniquely defined by the key and the type
// The data MUST be signed if stored out of the memory space of the running process.
// The data however is not required to be encrypted.
type SimpleStore interface {
	// Upsert will insert or update the data and expiration of a string
	UpsertSigned(key string, dataType int, expiration int64, data string) error
	// Deletes a value from the storage service
	DeleteSigned(key string, dataType int) error
	// Gets the value from the storage service if the value exists and
	// is not expired will return true, the value and nill.
	// if the value does not exist or is expired will return false, empty string
	// and nil. Any other case is an error.
	GetSigned(key string, dataType int) (bool, string, error)
}
