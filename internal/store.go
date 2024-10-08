package internal

import (
	"context"
	"errors"
)

// Store is the top-level interface (e.g. SQLiteStore)
type Store interface {
	WithCtx(ctx context.Context) StoreCtx
}

// StoreCtx is a Store bound to a cancellable Context
type StoreCtx interface {
	StoreTxn
	Transaction(func(tx StoreTxn) error) error
}

type StoreTxn interface {
	SetKey(id int, s1, s2, enc, pub []byte, allowReplace bool) error
	GetKey(id int) (s1, s2, enc, pub []byte, err error)
	GetKeyPub(id int) (pub []byte, err error)
	SetDelegate(id string, s1, s2, enc, pub []byte, keyid uint32) (err error)
	GetDelegatePriv(id string) (s1, s2, enc, pub []byte, err error)
	GetDelegatePub(id string) (pub []byte, keyid uint32, err error)
	GetMaxDelegate() (uint32, error)
}

var ErrNotFound = errors.New("store: not found")
var ErrAlreadyExists = errors.New("store: already exists")
var ErrDBConflict = errors.New("store: conflict: transaction must be retried")

func IsNotFoundError(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func IsAlreadyExistsError(err error) bool {
	return errors.Is(err, ErrAlreadyExists)
}

func IsDBConflictError(err error) bool {
	return errors.Is(err, ErrDBConflict)
}
