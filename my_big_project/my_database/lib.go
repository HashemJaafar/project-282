package database

import (
	"tools"

	badger "github.com/dgraph-io/badger/v4"
)

const packageName = "my_database"

type DB = *badger.DB

func Open(db *DB, path string) {
	var err error
	*db, err = badger.Open(badger.DefaultOptions(path))
	tools.PanicIfErr(err)
}

func Delete(db DB, key []byte) error {
	err := db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
	return err
}

// func Add(db DB, key []byte, value []byte) error {
// 	err := db.Update(func(txn *badger.Txn) error {
// 		_, err := txn.Get(key)
// 		if err == nil {
// 			return tools.Errorf(packageName, 2, "key %v is used", key)
// 		}
// 		return txn.Set(key, value)
// 	})
// 	return err
// }

func Update(db DB, key []byte, value []byte) {
	err := db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
	tools.PanicIfErr(err)
}

func Get(db DB, key []byte) ([]byte, error) {
	var valCopy []byte

	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		valCopy, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, tools.Errorf(packageName, 1, "key %v not found", key)
		}
		return nil, err
	}

	return valCopy, nil
}

func View(db DB, function func(key, value []byte)) {
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			item.Value(func(value []byte) error {
				function(item.Key(), value)
				return nil
			})
		}
		return nil
	})
	tools.PanicIfErr(err)
}
